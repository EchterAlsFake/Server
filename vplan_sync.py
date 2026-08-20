"""Periodic, local synchronization of the public substitution board."""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
from dotenv import load_dotenv


LOGGER = logging.getLogger(__name__)

DEFAULT_BOARD_URL = (
    "https://edith-stein-schulstiftung.a4.school/schedulemanager/TemplateFiles/"
    "SubstitutionBoardViewCommon/SubstitutionBoardViewCommon.aspx?schoolId={school_id}"
)
VPLAN_ASSIGNMENT_RE = re.compile(r"\bvar\s+vplanTage\s*=\s*", re.MULTILINE)
STAND_RE = re.compile(r'\bvar\s+datum_stand\s*=\s*"([^"\r\n]*)"\s*;')
TEACHER_TOKEN_PATTERN = r"[A-ZÄÖÜ][A-Za-zÄÖÜäöüß-]{1,15}"
TEACHER_CODE_RE = re.compile(
    r"\bLiGyDe\.[^\s,;.<>()]+(?:\s*,\s*LiGyDe\.[^\s,;.<>()]+)*",
    re.IGNORECASE,
)
EXPLICIT_TEACHER_CAPTURE_RE = re.compile(
    rf"\bLiGyDe\.({TEACHER_TOKEN_PATTERN})\b", re.IGNORECASE
)
TASKS_FROM_TEACHER_RE = re.compile(
    rf"(\bAufgaben\s+von\s+)(?!Lehrkraft\b)({TEACHER_TOKEN_PATTERN})\b"
)
TEACHER_PAIR_BEFORE_ROOM_RE = re.compile(
    r"\b([A-ZÄÖÜ][a-zäöüß]{2})\s+(?:und|&|/)\s+"
    r"([A-ZÄÖÜ][a-zäöüß]{2})(?=\s+in\s+(?:[A-ZÄÖÜ]\d{2,4}|TH\d+|Aula)\b)"
)
COURSE_CODE_RE = re.compile(r"^(?:0?[5-9]|1[0-2])[A-Za-z0-9ÄÖÜäöüß_.-]{1,62}$")
TEACHER_CODE_VALUE_RE = re.compile(rf"^{TEACHER_TOKEN_PATTERN}$")
MULTIPLE_TEACHERS_RE = re.compile(
    r"\bLehrkraft(?:\s*(?:,|und|&|/)\s*Lehrkraft)+\b"
)
LEARNING_STATE_KEY = "vplan_learning"
LEARNING_TIMEZONE = ZoneInfo("Europe/Berlin")


class VPlanSyncError(RuntimeError):
    """Raised when a downloaded plan cannot safely replace the local copy."""


def _normalized_teacher_codes(values: Any) -> tuple[str, ...]:
    if isinstance(values, str):
        values = values.split(",")
    if not isinstance(values, (list, tuple, set, frozenset)):
        return ()
    codes = {
        str(value).strip()
        for value in values
        if TEACHER_CODE_VALUE_RE.fullmatch(str(value).strip())
    }
    return tuple(sorted(codes, key=str.casefold))[:256]


def discover_teacher_codes(value: Any) -> set[str]:
    """Learn teacher codes only from strongly identifying source contexts."""
    if isinstance(value, str):
        discovered = {
            match.group(1) for match in EXPLICIT_TEACHER_CAPTURE_RE.finditer(value)
        }
        discovered.update(match.group(2) for match in TASKS_FROM_TEACHER_RE.finditer(value))
        for match in TEACHER_PAIR_BEFORE_ROOM_RE.finditer(value):
            discovered.update(match.groups())
        return discovered
    if isinstance(value, list):
        return set().union(*(discover_teacher_codes(item) for item in value)) if value else set()
    if isinstance(value, dict):
        return set().union(*(discover_teacher_codes(item) for item in value.values())) if value else set()
    return set()


def redact_teacher_codes(value: Any, known_teacher_codes: Any = ()) -> str:
    """Replace explicit and contextual teacher identifiers with a neutral label."""
    redacted = TEACHER_CODE_RE.sub("Lehrkraft", str(value or ""))
    redacted = TASKS_FROM_TEACHER_RE.sub(r"\1Lehrkraft", redacted)
    known_codes = _normalized_teacher_codes(known_teacher_codes)
    if known_codes:
        standalone_codes = re.compile(
            rf"(?<![\w.])(?:{'|'.join(re.escape(code) for code in known_codes)})(?![\w-])",
            re.IGNORECASE,
        )
        redacted = standalone_codes.sub("Lehrkraft", redacted)
    return MULTIPLE_TEACHERS_RE.sub("Lehrkräfte", redacted)


def redact_teacher_data(value: Any, known_teacher_codes: Any = ()) -> Any:
    """Recursively redact teacher identifiers before plan data is persisted."""
    if isinstance(value, str):
        return redact_teacher_codes(value, known_teacher_codes)
    if isinstance(value, list):
        return [redact_teacher_data(item, known_teacher_codes) for item in value]
    if isinstance(value, dict):
        return {
            key: redact_teacher_data(item, known_teacher_codes)
            for key, item in value.items()
        }
    return value


def discover_course_codes(plan: dict[str, Any]) -> set[str]:
    """Collect usable class/course identifiers observed in a parsed plan."""
    discovered: set[str] = set()
    for day in plan.get("tage", []):
        if not isinstance(day, dict):
            continue
        for entry in day.get("EINTRAEGE_KLASSEN", []):
            if not isinstance(entry, dict):
                continue
            code = str(entry.get("KLASSE", "")).strip()
            if COURSE_CODE_RE.fullmatch(code):
                discovered.add(code)
    return discovered


def school_year_for_timestamp(now_epoch: float | None = None) -> str:
    """Return the August-to-July school year used to scope learned values."""
    current = datetime.fromtimestamp(
        time.time() if now_epoch is None else now_epoch,
        tz=LEARNING_TIMEZONE,
    )
    first_year = current.year if current.month >= 8 else current.year - 1
    return f"{first_year}-{first_year + 1}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        LOGGER.warning("Ignoring invalid integer in %s", name)
        return default
    return max(minimum, min(value, maximum))


def _required_env_int(name: str, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        raise ValueError(f"{name} must be set in the .env file")
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a whole number") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class VPlanSyncConfig:
    enabled: bool
    school_id: int
    plan_path: Path
    state_path: Path
    lock_path: Path
    board_url: str
    teacher_code_seeds: tuple[str, ...]
    check_interval_seconds: int
    request_timeout_seconds: int
    max_response_bytes: int

    @classmethod
    def from_environment(cls, base_dir: str | os.PathLike[str]) -> "VPlanSyncConfig":
        root = Path(base_dir).resolve()
        load_dotenv(dotenv_path=root / ".env")
        school_id = _required_env_int("VPLAN_SCHOOL_ID", 1, 1_000_000)
        plan_path = Path(os.environ.get("VPLAN_JSON_PATH", root / "vplan.json")).resolve()
        check_interval = _env_int("VPLAN_CHECK_INTERVAL_SECONDS", 120, 60, 86_400)

        return cls(
            enabled=_env_bool("VPLAN_SYNC_ENABLED", True),
            school_id=school_id,
            plan_path=plan_path,
            state_path=Path(
                os.environ.get("VPLAN_SYNC_STATE_PATH", f"{plan_path}.sync-state.json")
            ).resolve(),
            lock_path=Path(
                os.environ.get("VPLAN_SYNC_LOCK_PATH", f"{plan_path}.sync.lock")
            ).resolve(),
            board_url=os.environ.get(
                "VPLAN_SOURCE_URL", DEFAULT_BOARD_URL.format(school_id=school_id)
            ),
            teacher_code_seeds=_normalized_teacher_codes(
                os.environ.get("VPLAN_TEACHER_CODE_SEEDS", "")
            ),
            check_interval_seconds=check_interval,
            request_timeout_seconds=_env_int("VPLAN_REQUEST_TIMEOUT_SECONDS", 20, 5, 120),
            max_response_bytes=_env_int(
                "VPLAN_MAX_RESPONSE_BYTES", 5 * 1024 * 1024, 64 * 1024, 20 * 1024 * 1024
            ),
        )


def plan_content_hash(plan: dict[str, Any]) -> str:
    """Hash source-controlled fields while ignoring local synchronization metadata."""
    source_content = {
        "stand": str(plan.get("meta", {}).get("stand", "")),
        "tage": plan.get("tage", []),
    }
    canonical_json = json.dumps(
        source_content,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def parse_vplan_html(
    html_text: str,
    school_id: int,
    *,
    known_teacher_codes: Any = (),
    discovered_teacher_codes: set[str] | None = None,
) -> dict[str, Any]:
    """Extract and validate the embedded JSON without trying to parse JavaScript."""
    assignment = VPLAN_ASSIGNMENT_RE.search(html_text)
    if assignment is None:
        raise VPlanSyncError("'var vplanTage' was not found in the downloaded page")

    try:
        days, _ = json.JSONDecoder().raw_decode(html_text, assignment.end())
    except json.JSONDecodeError as exc:
        raise VPlanSyncError("The embedded vplanTage value is not valid JSON") from exc

    if not isinstance(days, list):
        raise VPlanSyncError("vplanTage is not a JSON list")
    if len(days) > 31:
        raise VPlanSyncError("The downloaded plan contains an unexpected number of days")

    for index, day in enumerate(days):
        if not isinstance(day, dict):
            raise VPlanSyncError(f"Plan day {index} is not a JSON object")
        entries = day.get("EINTRAEGE_KLASSEN", [])
        if not isinstance(entries, list):
            raise VPlanSyncError(f"Entries for plan day {index} are not a JSON list")

    newly_discovered = discover_teacher_codes(days)
    if discovered_teacher_codes is not None:
        discovered_teacher_codes.update(newly_discovered)
    redaction_codes = _normalized_teacher_codes(
        [*_normalized_teacher_codes(known_teacher_codes), *newly_discovered]
    )

    # Redact before hashing or writing so teacher identifiers never enter the local cache.
    days = redact_teacher_data(days, redaction_codes)

    stand_match = STAND_RE.search(html_text)
    if stand_match is None or not stand_match.group(1).strip():
        raise VPlanSyncError("'var datum_stand' was not found in the downloaded page")

    plan = {
        "meta": {
            "stand": stand_match.group(1).strip(),
            "schoolId": school_id,
            "synced_at": _utc_now(),
        },
        "tage": days,
    }
    plan["meta"]["content_sha256"] = plan_content_hash(plan)
    return plan


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file_handle:
            payload = json.load(file_handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _learning_for_state(
    state: dict[str, Any],
    now_epoch: float,
    teacher_code_seeds: Any = (),
) -> dict[str, Any]:
    school_year = school_year_for_timestamp(now_epoch)
    stored = state.get(LEARNING_STATE_KEY, {})
    if not isinstance(stored, dict) or stored.get("school_year") != school_year:
        stored = {}

    teacher_codes = _normalized_teacher_codes(
        [
            *_normalized_teacher_codes(teacher_code_seeds),
            *_normalized_teacher_codes(stored.get("teacher_codes", [])),
        ]
    )
    stored_course_codes = stored.get("course_codes", [])
    if not isinstance(stored_course_codes, (list, tuple, set, frozenset)):
        stored_course_codes = []
    course_codes = sorted(
        {
            str(code).strip()
            for code in stored_course_codes
            if COURSE_CODE_RE.fullmatch(str(code).strip())
        },
        key=lambda code: (code.casefold(), code),
    )[:1000]
    return {
        "school_year": school_year,
        "teacher_codes": list(teacher_codes),
        "course_codes": course_codes,
    }


def load_vplan_learning(
    state_path: Path,
    teacher_code_seeds: Any = (),
    *,
    now_epoch: float | None = None,
) -> dict[str, Any]:
    """Read only the current school year's validated private learning state."""
    return _learning_for_state(
        _read_json_object(state_path),
        time.time() if now_epoch is None else now_epoch,
        teacher_code_seeds,
    )


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(payload, temporary_file, ensure_ascii=False, indent=2)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


class VPlanSynchronizer:
    """Coordinates polite refreshes across threads and Gunicorn workers."""

    def __init__(self, config: VPlanSyncConfig):
        self.config = config
        self._thread_lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        """Start one scheduler thread for this process. Safe to call repeatedly."""
        if not self.config.enabled:
            return False
        with self._start_lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="vplan-synchronizer",
                daemon=True,
            )
            self._thread.start()
            return True

    def stop(self) -> None:
        self._stop_event.set()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.sync_if_due()
            except Exception:
                LOGGER.exception("Unexpected error in the substitution-plan scheduler")
            self._stop_event.wait(self.config.check_interval_seconds)

    def sync_if_due(self, *, force: bool = False) -> dict[str, Any]:
        """Run a due check while preventing duplicate work across server workers."""
        if not self.config.enabled and not force:
            return {"status": "disabled"}

        self.config.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self._thread_lock, self.config.lock_path.open("a+", encoding="utf-8") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {"status": "busy"}

            state = _read_json_object(self.config.state_path)
            now_epoch = time.time()
            last_checked_epoch = float(state.get("last_checked_epoch", 0) or 0)
            if not force and now_epoch - last_checked_epoch < self.config.check_interval_seconds:
                return {"status": "not_due"}

            result = self._sync_locked(state, now_epoch)
            state["last_checked_epoch"] = now_epoch
            state["last_checked_at"] = _utc_now()
            state["last_result"] = result["status"]
            if result.get("warning"):
                state["last_warning"] = result["warning"]
            else:
                state.pop("last_warning", None)
            if result.get("error"):
                state["last_error"] = result["error"]
            elif result["status"] in {"updated", "unchanged", "checked"}:
                state.pop("last_error", None)
            _atomic_write_json(self.config.state_path, state)
            return result

    def _sync_locked(self, state: dict[str, Any], now_epoch: float) -> dict[str, Any]:
        current_plan = _read_json_object(self.config.plan_path)
        learning = _learning_for_state(
            state,
            now_epoch,
            self.config.teacher_code_seeds,
        )
        state[LEARNING_STATE_KEY] = learning

        try:
            downloaded_plan, discovered_teachers = self._download_plan(
                learning["teacher_codes"]
            )
        except (httpx.HTTPError, ValueError, VPlanSyncError, OSError) as exc:
            LOGGER.warning("Could not refresh substitution plan: %s", exc)
            return {
                "status": "error",
                "error": str(exc),
            }

        learning["teacher_codes"] = list(
            _normalized_teacher_codes(
                [*learning["teacher_codes"], *discovered_teachers]
            )
        )
        learning["course_codes"] = sorted(
            {
                *learning["course_codes"],
                *discover_course_codes(downloaded_plan),
            },
            key=lambda code: (code.casefold(), code),
        )[:1000]
        state[LEARNING_STATE_KEY] = learning

        downloaded_hash = plan_content_hash(downloaded_plan)
        downloaded_plan.setdefault("meta", {})["content_sha256"] = downloaded_hash
        downloaded_stand = str(downloaded_plan.get("meta", {}).get("stand", ""))
        current_hash = plan_content_hash(current_plan) if current_plan else None

        state["last_fetch_epoch"] = now_epoch
        state["last_fetch_at"] = _utc_now()
        state["last_source_stand"] = downloaded_stand
        state["last_content_sha256"] = downloaded_hash
        for obsolete_key in (
            "last_full_refresh_epoch",
            "last_full_refresh_at",
            "last_source_modified_at",
        ):
            state.pop(obsolete_key, None)

        if current_hash == downloaded_hash:
            return {
                "status": "unchanged",
                "source_stand": downloaded_stand,
                "content_sha256": downloaded_hash,
            }

        _atomic_write_json(self.config.plan_path, downloaded_plan)
        state["last_success_at"] = _utc_now()
        LOGGER.info("Updated substitution plan to content hash %s", downloaded_hash)
        return {
            "status": "updated",
            "source_stand": downloaded_stand,
            "content_sha256": downloaded_hash,
            "days": len(downloaded_plan["tage"]),
        }

    def _request(self, client: httpx.Client, url: str) -> httpx.Response:
        response = client.get(url)
        response.raise_for_status()
        if len(response.content) > self.config.max_response_bytes:
            raise VPlanSyncError("Remote response exceeded the configured size limit")
        return response

    def _download_plan(
        self, known_teacher_codes: Any
    ) -> tuple[dict[str, Any], set[str]]:
        with httpx.Client(
            timeout=self.config.request_timeout_seconds,
            follow_redirects=True,
            headers={
                "Accept": "text/html,application/xhtml+xml",
                "User-Agent": "PrivateStudentVPlan/1.0 (+personal school project)",
            },
        ) as client:
            response = self._request(client, self.config.board_url)
        discovered_teacher_codes: set[str] = set()
        plan = parse_vplan_html(
            response.text,
            self.config.school_id,
            known_teacher_codes=known_teacher_codes,
            discovered_teacher_codes=discovered_teacher_codes,
        )
        return plan, discovered_teacher_codes
