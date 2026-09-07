#!/srv/server/.venv/bin/python
"""Authenticated encrypted backup and safe extraction. Run as root."""
import argparse
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path("/srv/keygen")
MAGIC = b"EAFKEYGEN1"


def backup():
    folder = ROOT / "backups"
    folder.mkdir(mode=0o700, exist_ok=True)
    keyfile = ROOT / "backup.key"
    if not keyfile.exists():
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(32))
    with tempfile.TemporaryDirectory(prefix=".backup-", dir=ROOT) as temporary:
        stage = Path(temporary)
        for name in (".env", "postgres.env", "compose.yaml", "Gemfile", "privacy.rb", "bootstrap.rb"):
            shutil.copyfile(ROOT / name, stage / name)
        (stage / "credentials").mkdir(mode=0o700)
        shutil.copyfile(ROOT / "credentials/product.json", stage / "credentials/product.json")
        # Capture purchase state before Keygen, so persisted issued credentials are in the later dump.
        (stage / "purchase").mkdir(mode=0o700)
        shutil.copyfile("/srv/server/.env", stage / "purchase/server.env")
        with sqlite3.connect("file:/srv/server/data/server.db?mode=ro", uri=True) as source:
            with sqlite3.connect(stage / "purchase/server.db") as destination:
                source.backup(destination)
        with (stage / "keygen.dump").open("wb") as output:
            subprocess.run(["docker", "compose", "--project-directory", str(ROOT), "exec", "-T",
                            "postgres", "pg_dump", "-U", "keygen", "-d", "keygen", "-Fc"],
                           stdout=output, check=True)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            for path in stage.iterdir():
                tar.add(path, arcname=path.name)
        nonce = secrets.token_bytes(12)
        encrypted = MAGIC + nonce + AESGCM(keyfile.read_bytes()).encrypt(nonce, archive.getvalue(), MAGIC)
        filename = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".aesgcm"
        pending = folder / (filename + ".partial")
        with pending.open("xb") as output:
            os.chmod(pending, 0o600)
            output.write(encrypted)
            output.flush()
            os.fsync(output.fileno())
        pending.replace(folder / filename)
    for path in folder.glob("*.aesgcm"):
        if path.stat().st_mtime < time.time() - 7 * 86400:
            path.unlink()
    print("Encrypted Keygen and purchase-state backup completed:", filename)


def extract(archive, destination, keyfile):
    target = Path(destination)
    if target.exists():
        raise SystemExit("Restore destination must not exist")
    data = Path(archive).read_bytes()
    if not data.startswith(MAGIC):
        raise SystemExit("Unknown backup format")
    start = len(MAGIC)
    plain = AESGCM(Path(keyfile).read_bytes()).decrypt(data[start:start+12], data[start+12:], MAGIC)
    target.mkdir(mode=0o700, parents=True)
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        tar.extractall(target, filter="data")
    print("Authenticated backup extracted into protected recovery directory.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["backup", "extract"])
    parser.add_argument("--archive")
    parser.add_argument("--destination")
    parser.add_argument("--key", default=str(ROOT / "backup.key"))
    args = parser.parse_args()
    if args.action == "backup":
        backup()
    elif args.archive and args.destination:
        extract(args.archive, args.destination, args.key)
    else:
        parser.error("extract requires --archive and --destination")
