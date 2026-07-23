#!/usr/bin/env python3
"""
Simplified Repo Test Runner
Clones repositories, injects the local eaf_base_api into pyproject.toml,
runs tests, and hard fails if anything goes wrong.
"""

import os
import sys
import shutil
import tempfile
import argparse
import subprocess
import json
import urllib.request
import urllib.error

REPOS = [
    "https://github.com/EchterAlsFake/unofficial-api-for-xvideos",
    "https://github.com/EchterAlsFake/unofficial-api-for-pornhub",
    "https://github.com/EchterAlsFake/unofficial-api-for-xnxx",
    "https://github.com/EchterAlsFake/unofficial-api-for-hqporner",
    "https://github.com/EchterAlsFake/unofficial-api-for-eporner",
    "https://github.com/EchterAlsFake/unofficial-api-for-xhamster",
    "https://github.com/EchterAlsFake/unofficial-api-for-spankbang",
    "https://github.com/EchterAlsFake/unofficial-api-for-missav",
    "https://github.com/EchterAlsFake/unofficial-api-for-porntrex",
    "https://github.com/EchterAlsFake/unofficial-api-for-youporn",
    "https://github.com/EchterAlsFake/unofficial-api-for-beeg",
    "https://github.com/EchterAlsFake/unofficial-api-for-thumbzilla",
    "https://github.com/EchterAlsFake/unofficial-api-for-redtube",
    "https://github.com/EchterAlsFake/unofficial-api-for-tube8",
    "https://github.com/EchterAlsFake/unofficial-api-for-xfreehd",
]

BASE_API_REPO = "https://github.com/EchterAlsFake/eaf_base_api"
CI_URL = "https://echteralsfake.me"
SUITE_NAME = "repo_suite"


def ci_post(test_name: str, status: str, token: str):
    """Post CI status to the hardcoded CI_URL."""
    url = f"{CI_URL}/ci/{test_name}"
    payload = json.dumps({"status": status}).encode("utf-8")

    req = urllib.request.Request(url, data=payload, method="POST")
    # Extremely explicit headers to ensure Flask's request.is_json parses it properly
    req.add_header("Content-Type", "application/json; charset=utf-8")
    req.add_header("Content-Length", str(len(payload)))
    req.add_header("Accept", "application/json")
    req.add_header("X-CI-TOKEN", token)
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[CI] Updated '{test_name}' -> {status}")
    except urllib.error.HTTPError as e:
        # Read the body of the error response to see what Flask complained about
        error_body = e.read().decode("utf-8", errors="ignore")
        print(
            f"[CI] WARNING: Failed to update status for '{test_name}' -> HTTP {e.code}: {e.reason} | Response: {error_body.strip()}")
    except Exception as e:
        print(f"[CI] WARNING: Failed to update status for '{test_name}' -> {e}")


def run_cmd(cmd: list, cwd: str, token: str, repo_name: str = None):
    """Run a subprocess. Hard fail the entire script on any error."""
    print(f"\n>> Executing: {' '.join(cmd)}")

    # Strip parent virtual environment variables so `uv` doesn't get confused
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)

    result = subprocess.run(cmd, cwd=cwd, env=env)

    if result.returncode != 0:
        print(f"\n[FATAL ERROR] Command failed with exit code {result.returncode}")
        if repo_name:
            ci_post(repo_name, "fail", token)
        ci_post(SUITE_NAME, "fail", token)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Test EAF API repositories.")
    parser.add_argument("ci_token", help="The authentication token for the CI server")
    args = parser.parse_args()
    token = args.ci_token

    # 1. Pre-checks for required tools
    for tool in ["git", "uv"]:
        if not shutil.which(tool):
            print(f"[FATAL ERROR] '{tool}' is not installed or not in PATH.")
            ci_post(SUITE_NAME, "fail", token)
            sys.exit(1)

    ci_post(SUITE_NAME, "running", token)

    # 2. Setup a temporary directory (automatically cleans up on exit/crash)
    with tempfile.TemporaryDirectory(prefix="eaf_tests_") as tmpdir:
        print(f"[INFO] Created workspace: {tmpdir}")

        # 3. Clone the base API once
        base_api_dir = os.path.join(tmpdir, "eaf_base_api")
        print("\n=== Cloning eaf_base_api ===")
        run_cmd(["git", "clone", BASE_API_REPO, base_api_dir], cwd=tmpdir, token=token)

        # 4. Iterate and test all target repositories
        for url in REPOS:
            repo_name = os.path.splitext(os.path.basename(url))[0]
            repo_dir = os.path.join(tmpdir, repo_name)

            print(f"\n{'=' * 50}\n[TESTING] {repo_name}\n{'=' * 50}")
            ci_post(repo_name, "running", token)

            # Clone target repo
            run_cmd(["git", "clone", url, repo_dir], cwd=tmpdir, token=token, repo_name=repo_name)

            # Ensure it is a valid uv project
            if not os.path.exists(os.path.join(repo_dir, "pyproject.toml")):
                print(f"[FATAL ERROR] Missing pyproject.toml in {repo_name}")
                ci_post(repo_name, "fail", token)
                ci_post(SUITE_NAME, "fail", token)
                sys.exit(1)

            # Inject the local base API and testing deps into pyproject.toml natively (added av here)
            run_cmd(["uv", "add", "../eaf_base_api"], cwd=repo_dir, token=token, repo_name=repo_name)
            run_cmd(["uv", "add", "--dev", "h2", "socks5", "pytest", "pytest-asyncio", "curl_cffi", "av"],
                    cwd=repo_dir, token=token, repo_name=repo_name)

            # Sync to ensure environment is fully prepared
            run_cmd(["uv", "sync"], cwd=repo_dir, token=token, repo_name=repo_name)

            # Execute tests
            run_cmd(["uv", "run", "pytest"], cwd=repo_dir, token=token, repo_name=repo_name)

            # Mark repo as passed
            print(f"[SUCCESS] {repo_name} passed all tests.")
            ci_post(repo_name, "pass", token)

    # 5. Suite Complete
    print("\n[SUCCESS] All repositories passed! ✅")
    ci_post(SUITE_NAME, "pass", token)


if __name__ == "__main__":
    main()