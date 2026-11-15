#!/usr/bin/python3
"""Configure the private Mollie experiment on the rootless production server."""

import argparse
import fcntl
import getpass
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request

QUADLET = Path("/var/lib/pornfetch/.config/containers/systemd/pornfetch-web.container")
SOURCE = Path("/srv/infra/msi/podman/application/quadlet/pornfetch-web.container")
CREDENTIALS = QUADLET.parent / "credentials"
STATE = Path("/var/lib/pornfetch-ops/mollie-config")
NAMES = {
    "MOLLIE_TEST_API_KEY": "server_mollie_test_api_key.cred",
    "MOLLIE_TEST_PASSWORD_HASH": "server_mollie_test_password_hash.cred",
}


def run(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=600, cwd="/")
    if result.returncode:
        raise RuntimeError(
            "Command failed: "
            + Path(args[0]).name
            + "; output suppressed to protect credentials"
        )
    return result.stdout


def user_command(*args):
    account = pwd.getpwnam("pornfetch")
    return [
        "runuser",
        "-u",
        account.pw_name,
        "--",
        "env",
        "HOME=" + account.pw_dir,
        "XDG_RUNTIME_DIR=/run/user/" + str(account.pw_uid),
        *args,
    ]


def replace_settings(text, enabled, profile=None):
    # Modify only this experiment's explicit environment/credential declarations.
    lines = [
        line
        for line in text.splitlines()
        if not re.match(
            r"Environment=MOLLIE_(TEST_ENABLED|PROFILE_ID)=|LoadCredentialEncrypted=MOLLIE_TEST_(API_KEY|PASSWORD_HASH):",
            line,
        )
    ]
    section = None
    output = []
    for line in lines:
        output.append(line)
        if line.startswith("["):
            section = line
            if section == "[Container]":
                output.append(
                    "Environment=MOLLIE_TEST_ENABLED="
                    + ("true" if enabled else "false")
                )
                if profile:
                    output.append("Environment=MOLLIE_PROFILE_ID=" + profile)
            elif section == "[Service]" and profile:
                output.extend(
                    "LoadCredentialEncrypted="
                    + name
                    + ":%h/.config/containers/systemd/credentials/"
                    + filename
                    for name, filename in NAMES.items()
                )
    return "\n".join(output) + "\n"


def atomic_write(path, content, uid=None, gid=None):
    existing = path.stat() if path.exists() else None
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.chmod(temporary, existing.st_mode & 0o777 if existing else 0o600)
            os.chown(
                temporary,
                existing.st_uid if existing else uid,
                existing.st_gid if existing else gid,
            )
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def restart_and_check():
    run(user_command("systemctl", "--user", "daemon-reload"))
    run(user_command("systemctl", "--user", "restart", "pornfetch-web.service"))
    for _ in range(30):
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:18080/ping", timeout=3
            ) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(1)
    raise RuntimeError("Web health check failed")


def configure_live(profile):
    """Final activation: preserve sandbox credentials and encrypt a separate live key."""
    key = getpass.getpass("Mollie LIVE API key (live_…): ").strip()
    if not key.startswith("live_") or len(key) < 10:
        raise RuntimeError("A live API key is required")
    account = pwd.getpwnam("pornfetch")
    name = "MOLLIE_LIVE_API_KEY"
    destination = CREDENTIALS / "server_mollie_live_api_key.cred"
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE / "configure.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        run(["/usr/local/sbin/pfctl", "backup"])
        originals = {
            p: p.read_bytes() if p.exists() else None
            for p in (QUADLET, SOURCE, destination)
        }
        backup = Path(tempfile.mkdtemp(prefix="live-settings-", dir=STATE))
        for i, (path, content) in enumerate(originals.items()):
            if content is not None:
                (backup / str(i)).write_bytes(content)
        try:
            encrypted = run(
                [
                    "systemd-creds",
                    "encrypt",
                    "--quiet",
                    "--user",
                    "--uid=" + str(account.pw_uid),
                    "--with-key=host+tpm2",
                    "--name=" + name,
                    "-",
                    "-",
                ],
                key.encode(),
            )
            atomic_write(destination, encrypted, account.pw_uid, account.pw_gid)
            for path in (QUADLET, SOURCE):
                text = path.read_text()
                text = re.sub(
                    r"^Environment=MOLLIE_(LIVE_ENABLED|PROFILE_ID)=.*\n?",
                    "",
                    text,
                    flags=re.M,
                )
                text = re.sub(
                    r"^LoadCredentialEncrypted=MOLLIE_LIVE_API_KEY:.*\n?",
                    "",
                    text,
                    flags=re.M,
                )
                text = text.replace(
                    "[Container]\n",
                    "[Container]\nEnvironment=MOLLIE_LIVE_ENABLED=true\nEnvironment=MOLLIE_PROFILE_ID="
                    + profile
                    + "\n",
                    1,
                )
                text = text.replace(
                    "[Service]\n",
                    "[Service]\nLoadCredentialEncrypted=MOLLIE_LIVE_API_KEY:%h/.config/containers/systemd/credentials/server_mollie_live_api_key.cred\n",
                    1,
                )
                atomic_write(path, text.encode())
            restart_and_check()
        except Exception:
            for path, content in originals.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, content, account.pw_uid, account.pw_gid)
            restart_and_check()
            raise
    print(
        "Live Mollie checkout enabled. Sandbox credentials retained for existing test orders."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["configure", "configure-live", "disable", "status"]
    )
    parser.add_argument("--profile", default="pfl_QGqZL2B4xY")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run with sudo on the production server.")
    if args.action == "status":
        code = (
            "import json; from main import app; from pf_server.mollie_service import enabled,live_enabled; "
            "ctx=app.app_context(); ctx.push(); print(json.dumps(dict(enabled=enabled(), live_enabled=live_enabled(), "
            'profile=app.config.get("MOLLIE_PROFILE_ID"), test_key_configured='
            'app.config.get("MOLLIE_TEST_API_KEY", "").startswith("test_"))))'
        )
        print(
            run(
                user_command(
                    "podman",
                    "exec",
                    "--user",
                    "0",
                    "pornfetch-web",
                    "/entrypoint-wrapper.sh",
                    "/drop-privileges",
                    "1000",
                    "1000",
                    "python3",
                    "-c",
                    code,
                )
            )
            .decode()
            .strip()
        )
        return
    if not re.fullmatch(r"pfl_[A-Za-z0-9]+", args.profile):
        parser.error("Invalid profile identifier")
    if args.action == "configure-live":
        configure_live(args.profile)
        return
    values = {}
    if args.action == "configure":
        api_key = getpass.getpass("Mollie profile TEST API key (test_…): ").strip()
        if not api_key.startswith("test_") or len(api_key) < 10:
            parser.error("Only a Mollie test API key is accepted.")
        password = getpass.getpass(
            "New shared tester password (at least 16 characters): "
        )
        if len(password) < 16 or password != getpass.getpass(
            "Confirm tester password: "
        ):
            parser.error("Passwords differ or contain fewer than 16 characters.")
        code = "import sys; from werkzeug.security import generate_password_hash; print(generate_password_hash(sys.stdin.read()))"
        hashed = (
            run(
                user_command(
                    "podman",
                    "exec",
                    "-i",
                    "--user",
                    "1000",
                    "pornfetch-web",
                    "python3",
                    "-c",
                    code,
                ),
                password.encode(),
            )
            .decode()
            .strip()
        )
        values = {"MOLLIE_TEST_API_KEY": api_key, "MOLLIE_TEST_PASSWORD_HASH": hashed}
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE / "configure.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # Online, consistent SQLite backup; services remain available during backup.
        run(["/usr/local/sbin/pfctl", "backup"])
        backup = Path(tempfile.mkdtemp(prefix="settings-", dir=STATE))
        paths = [QUADLET, SOURCE, *(CREDENTIALS / name for name in NAMES.values())]
        originals = {}
        for index, path in enumerate(paths):
            originals[path] = path.read_bytes() if path.exists() else None
            if path.exists():
                shutil.copy2(path, backup / str(index))
        account = pwd.getpwnam("pornfetch")
        try:
            for name, value in values.items():
                ciphertext = run(
                    [
                        "systemd-creds",
                        "encrypt",
                        "--quiet",
                        "--user",
                        "--uid=" + str(account.pw_uid),
                        "--with-key=host+tpm2",
                        "--name=" + name,
                        "-",
                        "-",
                    ],
                    value.encode(),
                )
                atomic_write(
                    CREDENTIALS / NAMES[name],
                    ciphertext,
                    account.pw_uid,
                    account.pw_gid,
                )
            for path in (QUADLET, SOURCE):
                # Disabling keeps credential bindings for unfinished orders and delivery.
                text = path.read_text()
                profile = (
                    args.profile
                    if values
                    else (
                        re.search(
                            r"^Environment=MOLLIE_PROFILE_ID=(.+)$", text, re.M
                        ).group(1)
                        if re.search(
                            r"^Environment=MOLLIE_PROFILE_ID=(.+)$", text, re.M
                        )
                        else None
                    )
                )
                updated = replace_settings(text, bool(values), profile)
                if args.action == "disable":
                    updated = re.sub(
                        r"^Environment=MOLLIE_LIVE_ENABLED=.*$",
                        "Environment=MOLLIE_LIVE_ENABLED=false",
                        updated,
                        flags=re.M,
                    )
                atomic_write(path, updated.encode())
            restart_and_check()
        except Exception:
            for path, content in originals.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, content, account.pw_uid, account.pw_gid)
            restart_and_check()
            raise
        print(
            "Mollie tester access "
            + ("enabled" if values else "disabled")
            + ". Existing payment settings preserved."
        )
        print("Encrypted settings rollback copy: " + str(backup))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError, EOFError, KeyboardInterrupt:
        raise SystemExit(
            "Configuration did not complete. Inspect service health; secret output was suppressed."
        ) from None
