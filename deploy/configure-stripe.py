#!/usr/bin/env python3
"""Prepare encrypted Stripe credentials for the rootless production deployment.

Run the reviewed, root-owned copy with sudo. Input is a JSON object on stdin;
secret values never enter command arguments, public configuration, or output.
This prepares the next deployment; it does not restart the running web service.
"""

import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile

QUADLET = Path("/var/lib/pornfetch/.config/containers/systemd/pornfetch-web.container")
CREDENTIALS = QUADLET.parent / "credentials"
STATE = Path("/var/lib/pornfetch-ops/stripe-config")
SECRET_NAMES = (
    "STRIPE_TEST_API_KEY",
    "STRIPE_TEST_WEBHOOK_SECRET",
    "STRIPE_TEST_PASSWORD_HASH",
    "STRIPE_LIVE_API_KEY",
    "STRIPE_LIVE_WEBHOOK_SECRET",
)


def validate(values):
    required = {
        "STRIPE_TEST_ACCOUNT_ID": r"acct_[A-Za-z0-9]+",
        "STRIPE_LIVE_ACCOUNT_ID": r"acct_[A-Za-z0-9]+",
        "STRIPE_TEST_API_KEY": r"(?:sk|rk)_test_[A-Za-z0-9_]+",
        "STRIPE_LIVE_API_KEY": r"(?:sk|rk)_live_[A-Za-z0-9_]+",
        "STRIPE_TEST_WEBHOOK_SECRET": r"whsec_[A-Za-z0-9_]+",
        "STRIPE_LIVE_WEBHOOK_SECRET": r"whsec_[A-Za-z0-9_]+",
    }
    if not isinstance(values, dict):
        raise ValueError("Settings must be a JSON object")
    for name, pattern in required.items():
        value = values.get(name)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("Missing or invalid setting: " + name)
    if values.get("STRIPE_TEST_PASSWORD_HASH") and not values[
        "STRIPE_TEST_PASSWORD_HASH"
    ].startswith(("scrypt:", "pbkdf2:")):
        raise ValueError("Invalid STRIPE_TEST_PASSWORD_HASH")


def render_settings(text, values, *, enable_sandbox=False):
    validate(values)
    if enable_sandbox and not values.get("STRIPE_TEST_PASSWORD_HASH"):
        raise ValueError(
            "STRIPE_TEST_PASSWORD_HASH is required for private sandbox access"
        )
    lines = [
        line
        for line in text.splitlines()
        if not re.match(
            r"Environment=STRIPE_[A-Z_]+=|LoadCredentialEncrypted=STRIPE_[A-Z_]+:|Environment=MOLLIE_(LIVE|TEST)_ENABLED=",
            line,
        )
    ]
    output = []
    for line in lines:
        output.append(line)
        if line == "[Container]":
            output.extend(
                [
                    "Environment=STRIPE_LIVE_ENABLED=true",
                    "Environment=STRIPE_TEST_ENABLED="
                    + ("true" if enable_sandbox else "false"),
                    "Environment=STRIPE_TEST_ACCOUNT_ID="
                    + values["STRIPE_TEST_ACCOUNT_ID"],
                    "Environment=STRIPE_LIVE_ACCOUNT_ID="
                    + values["STRIPE_LIVE_ACCOUNT_ID"],
                    "Environment=MOLLIE_LIVE_ENABLED=false",
                    "Environment=MOLLIE_TEST_ENABLED=false",
                ]
            )
        elif line == "[Service]":
            output.extend(
                "LoadCredentialEncrypted="
                + name
                + ":%h/.config/containers/systemd/credentials/"
                + filename(name)
                for name in SECRET_NAMES
                if values.get(name)
            )
    if lines.count("[Container]") != 1 or lines.count("[Service]") != 1:
        raise ValueError("Unexpected Quadlet structure")
    return "\n".join(output) + "\n"


def filename(name):
    return "server_" + name.lower() + ".cred"


def run(arguments, data=None):
    result = subprocess.run(
        arguments, input=data, capture_output=True, timeout=600, cwd="/"
    )
    if result.returncode:
        raise RuntimeError(
            "Command failed: "
            + Path(arguments[0]).name
            + "; output suppressed to protect credentials"
        )
    return result.stdout


def atomic_write(path, content, uid, gid):
    previous = path.stat() if path.exists() else None
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.chmod(temporary, previous.st_mode & 0o777 if previous else 0o600)
            os.chown(
                temporary,
                previous.st_uid if previous else uid,
                previous.st_gid if previous else gid,
            )
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--enable-sandbox",
        action="store_true",
        help="Enable the password-protected sandbox alongside live checkout",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("Run the reviewed root-owned script with sudo")
    values = json.load(sys.stdin)
    validate(values)
    account = pwd.getpwnam("pornfetch")
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE / "configure.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        prepared = render_settings(
            QUADLET.read_text(), values, enable_sandbox=args.enable_sandbox
        ).encode()
        run(["/usr/local/sbin/pfctl", "backup"])
        paths = [
            QUADLET,
            *(
                CREDENTIALS / filename(name)
                for name in SECRET_NAMES
                if values.get(name)
            ),
        ]
        originals = {
            path: path.read_bytes() if path.exists() else None for path in paths
        }
        backup = Path(tempfile.mkdtemp(prefix="settings-", dir=STATE))
        for index, (path, content) in enumerate(originals.items()):
            if content is not None:
                destination = backup / str(index)
                destination.write_bytes(content)
                destination.chmod(0o600)
        try:
            for name in SECRET_NAMES:
                if not values.get(name):
                    continue
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
                    values[name].encode(),
                )
                atomic_write(
                    CREDENTIALS / filename(name),
                    encrypted,
                    account.pw_uid,
                    account.pw_gid,
                )
            atomic_write(QUADLET, prepared, account.pw_uid, account.pw_gid)
        except Exception:
            for path, content in originals.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, content, account.pw_uid, account.pw_gid)
            raise
    print(
        "Stripe credentials encrypted; live configuration prepared for the next pfctl deployment. Running services unchanged."
    )


if __name__ == "__main__":
    try:
        main()
    except ValueError, RuntimeError, OSError, KeyError:
        print(
            "Stripe configuration failed; sensitive details suppressed.",
            file=sys.stderr,
        )
        raise SystemExit(1)
