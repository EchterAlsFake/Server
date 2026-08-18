"""Periodic, local synchronization of the public substitution board."""

from __future__ import annotations

import fcntl
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

import httpx
from dotenv import load_dotenv


LOGGER = logging.getLogger(__name__)

DEFAULT_BOARD_URL = (
    "https://edith-stein-schulstiftung.a4.school/schedulemanager/TemplateFiles/"
    "SubstitutionBoardViewCommon/SubstitutionBoardViewCommon.aspx?schoolId={school_id}"
)
DEFAULT_MODIFICATION_URL = (
    "https://edith-stein-schulstiftung.a4.school/api/Api/Substitution/"
    "GetLastModificationDate"
)
VPLAN_ASSIGNMENT_RE = re.compile(r"\bvar\s+vplanTage\s*=\s*", re.MULTILINE)
STAND_RE = re.compile(r'\bvar\s+datum_stand\s*=\s*"([^"\r\n]*)"\s*;')
TEACHER_CODE_RE = re.compile(
    r"\bLiGyDe\.[\wÄÖÜäöüß-]+(?:\s*,\s*LiGyDe\.[\wÄÖÜäöüß-]+)*",
    re.IGNORECASE,
)


class VPlanSyncError(RuntimeError):
    """Raised when a downloaded plan cannot safely replace the local copy."""


def redact_teacher_codes(value: Any) -> str:
    """Remove one or more teacher identifiers from text shown to visitors."""
    return TEACHER_CODE_RE.sub("Lehrkraft", str(value or ""))


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
    modification_url: str
    check_interval_seconds: int
    full_refresh_interval_seconds: int
    request_timeout_seconds: int
    max_response_bytes: int

    @classmethod
    def from_environment(cls, base_dir: str | os.PathLike[str]) -> "VPlanSyncConfig":
        root = Path(base_dir).resolve()
        load_dotenv(dotenv_path=root / ".env")
        school_id = _required_env_int("VPLAN_SCHOOL_ID", 1, 1_000_000)
        plan_path = Path(os.environ.get("VPLAN_JSON_PATH", root / "vplan.json")).resolve()
        check_interval = _env_int("VPLAN_CHECK_INTERVAL_SECONDS", 120, 60, 86_400)
        full_refresh_interval = _env_int(
            "VPLAN_FULL_REFRESH_INTERVAL_SECONDS", 3_600, check_interval, 604_800
        )

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
            modification_url=os.environ.get(
                "VPLAN_MODIFICATION_URL", DEFAULT_MODIFICATION_URL
            ),
            check_interval_seconds=check_interval,
            full_refresh_interval_seconds=full_refresh_interval,
            request_timeout_seconds=_env_int("VPLAN_REQUEST_TIMEOUT_SECONDS", 20, 5, 120),
            max_response_bytes=_env_int(
                "VPLAN_MAX_RESPONSE_BYTES", 5 * 1024 * 1024, 64 * 1024, 20 * 1024 * 1024
            ),
        )


def parse_vplan_html(html_text: str, school_id: int) -> dict[str, Any]:
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

    stand_match = STAND_RE.search(html_text)
    if stand_match is None or not stand_match.group(1).strip():
        raise VPlanSyncError("'var datum_stand' was not found in the downloaded page")

    return {
        "meta": {
            "stand": stand_match.group(1).strip(),
            "schoolId": school_id,
            "synced_at": _utc_now(),
        },
        "tage": days,
    }


def _valid_modification_date(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    try:
        parsed = datetime.strptime(candidate, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    # The API currently returns year 1 when it has no usable school context.
    if parsed.year < 2000:
        return None
    return candidate


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file_handle:
            payload = json.load(file_handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


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

            result = self._sync_locked(state, now_epoch, force=force)
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

    def _sync_locked(
        self, state: dict[str, Any], now_epoch: float, *, force: bool
    ) -> dict[str, Any]:
        current_plan = _read_json_object(self.config.plan_path)
        current_stand = str(current_plan.get("meta", {}).get("stand", ""))

        remote_modified: str | None = None
        modification_warning: str | None = None
        try:
            remote_modified = self._get_remote_modification()
            if remote_modified is None:
                modification_warning = "Modification API returned no usable timestamp"
        except (httpx.HTTPError, ValueError, VPlanSyncError) as exc:
            modification_warning = f"Modification check failed: {exc}"

        last_full_refresh = float(state.get("last_full_refresh_epoch", 0) or 0)
        full_refresh_due = (
            force
            or not current_plan
            or now_epoch - last_full_refresh >= self.config.full_refresh_interval_seconds
        )
        source_changed = bool(remote_modified and remote_modified != current_stand)

        if not source_changed and remote_modified is not None and current_plan and not force:
            return {"status": "checked", "remote_modified": remote_modified}
        if not source_changed and not full_refresh_due:
            result: dict[str, Any] = {"status": "checked"}
            if modification_warning:
                result["warning"] = modification_warning
            return result

        try:
            downloaded_plan = self._download_plan()
        except (httpx.HTTPError, ValueError, VPlanSyncError, OSError) as exc:
            LOGGER.warning("Could not refresh substitution plan: %s", exc)
            return {
                "status": "error",
                "error": str(exc),
                **({"warning": modification_warning} if modification_warning else {}),
            }

        state["last_full_refresh_epoch"] = now_epoch
        state["last_full_refresh_at"] = _utc_now()
        downloaded_stand = str(downloaded_plan.get("meta", {}).get("stand", ""))
        state["last_source_modified_at"] = downloaded_stand

        if current_plan and downloaded_stand == current_stand:
            return {
                "status": "unchanged",
                "remote_modified": downloaded_stand,
                **({"warning": modification_warning} if modification_warning else {}),
            }

        _atomic_write_json(self.config.plan_path, downloaded_plan)
        state["last_success_at"] = _utc_now()
        LOGGER.info("Updated substitution plan to source timestamp %s", downloaded_stand)
        return {
            "status": "updated",
            "remote_modified": downloaded_stand,
            "days": len(downloaded_plan["tage"]),
            **({"warning": modification_warning} if modification_warning else {}),
        }

    def _request(self, client: httpx.Client, url: str) -> httpx.Response:
        response = client.get(url)
        response.raise_for_status()
        if len(response.content) > self.config.max_response_bytes:
            raise VPlanSyncError("Remote response exceeded the configured size limit")
        return response

    def _get_remote_modification(self) -> str | None:
        with httpx.Client(
            timeout=self.config.request_timeout_seconds,
            follow_redirects=True,
            headers={
                "Accept": "application/json",
                "User-Agent": "PrivateStudentVPlan/1.0 (+personal school project)",
            },
        ) as client:
            response = self._request(client, self.config.modification_url)
            payload = response.json()
        if not isinstance(payload, dict):
            raise VPlanSyncError("Modification API did not return a JSON object")
        return _valid_modification_date(payload.get("DATUM"))

    def _download_plan(self) -> dict[str, Any]:
        with httpx.Client(
            timeout=self.config.request_timeout_seconds,
            follow_redirects=True,
            headers={
                "Accept": "text/html,application/xhtml+xml",
                "User-Agent": "PrivateStudentVPlan/1.0 (+personal school project)",
            },
        ) as client:
            response = self._request(client, self.config.board_url)
        return parse_vplan_html(response.text, self.config.school_id)
