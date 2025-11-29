# 100% AI generated

#!/usr/bin/env python3
"""
Repo test runner: clone repos, create venvs, install deps, run pytest,
and report status to a CI server.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict

# --------- OPTIONAL HTTP CLIENTS (for robustness) ---------
try:
    import httpx  # type: ignore[import]
except Exception:  # httpx may not be installed
    httpx = None  # type: ignore[assignment]

try:
    import requests  # type: ignore[import]
except Exception:  # requests may not be installed
    requests = None  # type: ignore[assignment]

from urllib import request as urllib_request, error as urllib_error

# ---------------- CONFIG ----------------

REPOS = [
    "https://github.com/EchterAlsFake/xvideos_api",
    "https://github.com/EchterAlsFake/PHUB",
    "https://github.com/EchterAlsFake/xnxx_api",
    "https://github.com/EchterAlsFake/hqporner_api",
    "https://github.com/EchterAlsFake/EPorner_API",
    "https://github.com/EchterAlsFake/xhamster_api",
    "https://github.com/EchterAlsFake/spankbang_api",
    "https://github.com/EchterAlsFake/missAV_api",
    "https://github.com/EchterAlsFake/porntrex_api",
    "https://github.com/EchterAlsFake/youporn_api",
    "https://github.com/EchterAlsFake/beeg_api",
]

# Use env vars if set to mimic the Bash script behavior
CI_SERVER_URL = os.environ.get("CI_SERVER_URL", "https://echteralsfake.duckdns.org").rstrip("/")
CI_TOKEN = os.environ.get("CI_TOKEN", "")
CI_SUITE_NAME = os.environ.get("CI_SUITE_NAME", "repo_suite")

# This is the "outer" Python used to create venvs
PYTHON_BIN = os.environ.get("PYTHON_BIN", sys.executable or "python3")

# Default TEST_ROOT: $HOME/n8n_repo_tests
DEFAULT_TEST_ROOT = os.path.join(os.path.expanduser("~"), "n8n_repo_tests")
TEST_ROOT = os.environ.get("TEST_ROOT", DEFAULT_TEST_ROOT)


# ---------------- UTILS ----------------


def which(cmd: str) -> str | None:
    """Return full path to executable or None."""
    return shutil.which(cmd)


def ci_post(test_name: str, status: str) -> None:
    """
    Post CI status to CI_SERVER_URL.

    status: "running" | "pass" | "fail" | "unknown"
    """
    if not test_name or not status:
        print("[repo_tests][ci] WARNING: Missing test_name or status for ci_post.")
        return

    url = f"{CI_SERVER_URL}/ci/{test_name}"
    payload = {"status": status}
    headers = {"Content-Type": "application/json"}
    if CI_TOKEN:
        headers["X-CI-TOKEN"] = CI_TOKEN

    # Prefer httpx, then requests, then stdlib urllib, so script works even
    # without extra dependencies.
    last_error = None

    if httpx is not None:
        try:
            resp = httpx.post(url, json=payload, headers=headers, timeout=10.0)  # type: ignore[arg-type]
            if 200 <= resp.status_code < 300:
                print(f"[repo_tests][ci] Updated CI status for '{test_name}' -> {status} (httpx).")
                return
            last_error = f"httpx HTTP {resp.status_code}"
        except Exception as exc:  # pragma: no cover
            last_error = f"httpx error: {exc!r}"

    if requests is not None:
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10.0)  # type: ignore[arg-type]
            if 200 <= resp.status_code < 300:
                print(f"[repo_tests][ci] Updated CI status for '{test_name}' -> {status} (requests).")
                return
            last_error = f"requests HTTP {resp.status_code}"
        except Exception as exc:  # pragma: no cover
            last_error = f"requests error: {exc!r}"

    # Fallback to urllib
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(url, data=data, headers=headers, method="POST")
        with urllib_request.urlopen(req, timeout=10.0) as resp:
            if 200 <= resp.status < 300:
                print(f"[repo_tests][ci] Updated CI status for '{test_name}' -> {status} (urllib).")
                return
            last_error = f"urllib HTTP {resp.status}"
    except urllib_error.URLError as exc:  # pragma: no cover
        last_error = f"urllib error: {exc!r}"

    print(
        f"[repo_tests][ci] WARNING: Failed to update CI status for '{test_name}' ({status}). "
        f"Last error: {last_error}"
    )


def map_status_to_ci(status: str) -> str:
    """Map internal status to CI status string."""
    if status == "PASSED":
        return "pass"
    if status == "NOT RUN":
        return "unknown"
    return "fail"


def safe_mkdtemp(test_root: str) -> str:
    """Create a safe temporary directory inside TEST_ROOT."""
    test_root_path = Path(test_root).expanduser().resolve()
    try:
        test_root_path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"[repo_tests] ERROR: Failed to create TEST_ROOT '{test_root_path}': {exc}")
        sys.exit(1)

    tmp_root = tempfile.mkdtemp(prefix="n8n_repo_tests_", dir=str(test_root_path))
    tmp_root_path = Path(tmp_root).resolve()

    if test_root_path not in tmp_root_path.parents and tmp_root_path != test_root_path:
        print(f"[repo_tests] ERROR: Unsafe TMP_ROOT created: {tmp_root_path}")
        shutil.rmtree(tmp_root_path, ignore_errors=True)
        sys.exit(1)

    print(f"[repo_tests] Working directory: {tmp_root_path}")
    return str(tmp_root_path)


def run_subprocess(
    cmd: list[str],
    cwd: str | None = None,
    description: str = "",
    allow_failure: bool = False,
) -> int:
    """Run a subprocess, streaming output, return exit code."""
    desc_prefix = f"[repo_tests] {description}: " if description else "[repo_tests] "
    print(f"{desc_prefix}Executing: {' '.join(cmd)}")

    try:
        proc = subprocess.run(cmd, cwd=cwd, check=False)
        return proc.returncode
    except FileNotFoundError:
        print(f"{desc_prefix}ERROR: Command not found: {cmd[0]}")
        if allow_failure:
            return 127
        raise
    except Exception as exc:  # pragma: no cover
        print(f"{desc_prefix}ERROR: Exception while running command: {exc!r}")
        if allow_failure:
            return 1
        raise


def process_repo(url: str, tmp_root: str) -> str:
    """
    Clone repo, create venv, install deps, run pytest.

    Returns a status string:
      PASSED | FAILED | CLONE_FAILED | VENV_FAILED |
      REQUIREMENTS_FAILED | EXTRA_DEPS_FAILED | ERROR
    """
    repo_name = os.path.splitext(os.path.basename(url))[0]

    print()
    print("===============================================")
    print(f"[repo_tests] Processing repository: {repo_name}")
    print("===============================================")

    repo_dir = os.path.join(tmp_root, repo_name)
    status = "NOT RUN"

    # 1. Clone
    print(f"[repo_tests][{repo_name}] Cloning {url} ...")
    rc = run_subprocess(["git", "clone", url, repo_dir], description=f"[{repo_name}] git clone")
    if rc != 0:
        print(f"[repo_tests][{repo_name}] ERROR: git clone failed with exit code {rc}.")
        return "CLONE_FAILED"

    # 2. Create virtual env (.venv)
    print(f"[repo_tests][{repo_name}] Creating virtual environment (.venv)...")
    venv_dir = os.path.join(repo_dir, ".venv")
    rc = run_subprocess(
        [PYTHON_BIN, "-m", "venv", venv_dir],
        cwd=repo_dir,
        description=f"[{repo_name}] venv",
    )
    if rc != 0:
        print(f"[repo_tests][{repo_name}] ERROR: Failed to create virtualenv (exit code {rc}).")
        return "VENV_FAILED"

    # Detect venv python path (POSIX & Windows)
    venv_python_candidates = [
        os.path.join(venv_dir, "bin", "python"),          # POSIX
        os.path.join(venv_dir, "Scripts", "python.exe"),  # Windows
        os.path.join(venv_dir, "Scripts", "python"),      # Windows alt
    ]
    venv_python = next((p for p in venv_python_candidates if os.path.exists(p)), None)

    if not venv_python:
        print(f"[repo_tests][{repo_name}] ERROR: Could not locate python inside venv.")
        return "VENV_FAILED"

    def pip_cmd(*args: str) -> list[str]:
        return [venv_python, "-m", "pip", *args]

    # 3. Upgrade pip
    print(f"[repo_tests][{repo_name}] Upgrading pip...")
    rc = run_subprocess(
        pip_cmd("install", "--upgrade", "pip"),
        cwd=repo_dir,
        description=f"[{repo_name}] pip upgrade",
        allow_failure=True,
    )
    if rc != 0:
        print(f"[repo_tests][{repo_name}] WARNING: Failed to upgrade pip (exit code {rc}), continuing.")

    # 4. requirements.txt
    req_path = os.path.join(repo_dir, "requirements.txt")
    if os.path.isfile(req_path):
        print(f"[repo_tests][{repo_name}] Installing requirements.txt...")
        rc = run_subprocess(
            pip_cmd("install", "-r", "requirements.txt"),
            cwd=repo_dir,
            description=f"[{repo_name}] pip install -r requirements.txt",
        )
        if rc != 0:
            print(f"[repo_tests][{repo_name}] ERROR: Failed to install requirements.txt (exit code {rc}).")
            return "REQUIREMENTS_FAILED"
    else:
        print(f"[repo_tests][{repo_name}] WARNING: requirements.txt not found, skipping.")

    # 5. Extra packages: h2 socks5 pytest
    print(f"[repo_tests][{repo_name}] Installing extra packages: h2 socks5 pytest...")
    rc = run_subprocess(
        pip_cmd("install", "h2", "socks5", "pytest"),
        cwd=repo_dir,
        description=f"[{repo_name}] install extra deps",
    )
    if rc != 0:
        print(f"[repo_tests][{repo_name}] ERROR: Failed to install extra packages (exit code {rc}).")
        return "EXTRA_DEPS_FAILED"

    # 6. Run tests with pytest
    print(f"[repo_tests][{repo_name}] Running tests: pytest ...")
    rc = run_subprocess(
        [venv_python, "-m", "pytest"],
        cwd=repo_dir,
        description=f"[{repo_name}] pytest",
        allow_failure=True,
    )

    if rc == 0:
        print(f"[repo_tests][{repo_name}] ✅ Tests PASSED.")
        status = "PASSED"
    else:
        print(f"[repo_tests][{repo_name}] ❌ Tests FAILED (exit code {rc}).")
        status = "FAILED"

    return status


def main() -> int:
    # ---------------- PRE-CHECKS ----------------

    if which("git") is None:
        print("[repo_tests] ERROR: git not found in PATH.")
        return 1

    if which(PYTHON_BIN) is None:
        print(f"[repo_tests] ERROR: {PYTHON_BIN} not found in PATH.")
        return 1

    # TEST_ROOT & TMP_ROOT setup
    tmp_root = safe_mkdtemp(TEST_ROOT)

    # Ensure cleanup on exit
    def cleanup() -> None:
        tmp_path = Path(tmp_root)
        print(f"[repo_tests] Cleaning up temporary directory: {tmp_path}")
        try:
            # Safety: only remove if inside TEST_ROOT and matches our prefix
            if tmp_path.exists():
                parent = tmp_path.parent
                if (
                    Path(TEST_ROOT).resolve() == parent.resolve()
                    and tmp_path.name.startswith("n8n_repo_tests_")
                ):
                    shutil.rmtree(tmp_path, ignore_errors=True)
                else:
                    print(f"[repo_tests] WARNING: Not removing TMP_ROOT because it looks unsafe: '{tmp_path}'")
        except Exception as exc:  # pragma: no cover
            print(f"[repo_tests] WARNING: Exception during cleanup: {exc!r}")

    import atexit

    atexit.register(cleanup)

    # ---------------- RESULT TRACKING ----------------
    results: Dict[str, str] = {}
    any_failure = False

    # Set suite status to running
    ci_post(CI_SUITE_NAME, "running")

    # ---------------- MAIN LOOP ----------------
    for url in REPOS:
        repo_name = os.path.splitext(os.path.basename(url))[0]
        try:
            status = process_repo(url, tmp_root)
        except Exception as exc:  # pragma: no cover
            print(f"[repo_tests][{repo_name}] ERROR: Unexpected exception: {exc!r}")
            status = "ERROR"

        results[repo_name] = status
        if status not in ("PASSED", "NOT RUN"):
            any_failure = True

        # Report each repo immediately after it has been processed
        ci_status = map_status_to_ci(status)
        ci_post(repo_name, ci_status)

    # ---------------- SUMMARY ----------------
    print()
    print("===============================================")
    print("[repo_tests] TEST SUMMARY")
    print("===============================================")

    for url in REPOS:
        repo_name = os.path.splitext(os.path.basename(url))[0]
        status = results.get(repo_name, "NOT RUN")
        print(f"[repo_tests] {repo_name:20s} : {status}")

    if not any_failure:
        print("[repo_tests] All repositories PASSED ✅")
        ci_post(CI_SUITE_NAME, "pass")
        return 0
    else:
        print("[repo_tests] One or more repositories FAILED ❌")
        ci_post(CI_SUITE_NAME, "fail")
        return 1


if __name__ == "__main__":
    exit_code = 1
    try:
        exit_code = main()
    except Exception as e:  # pragma: no cover
        # Last-resort error path; try to notify CI that the suite failed.
        print(f"[repo_tests] FATAL: Unhandled exception: {e!r}")
        try:
            ci_post(CI_SUITE_NAME, "fail")
        except Exception:
            pass
    sys.exit(exit_code)
