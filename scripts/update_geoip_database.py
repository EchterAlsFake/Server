"""Download a DB-IP City Lite snapshot for local, offline checkout lookups."""

import argparse
import gzip
import hashlib
import os
import re
import tempfile
from datetime import datetime, timezone
from urllib.request import Request, urlopen

MAX_DATABASE_BYTES = 300 * 1024 * 1024
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release",
        default=datetime.now(timezone.utc).strftime("%Y-%m"),
        help="DB-IP release in YYYY-MM format (default: current UTC month)",
    )
    parser.add_argument(
        "--accept-license",
        action="store_true",
        help="Confirm acceptance of DB-IP's CC BY 4.0 licensing terms",
    )
    return parser.parse_args()


def main() -> None:
    options = arguments()
    if not options.accept_license:
        raise SystemExit("Pass --accept-license after reviewing geoip/README.md")
    if re.fullmatch(r"20\d{2}-(?:0[1-9]|1[0-2])", options.release) is None:
        raise SystemExit("--release must use YYYY-MM")

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_directory = os.path.abspath(
        os.environ.get("PF_SERVER_DATA_DIR", project_root)
    )
    destination_directory = os.path.join(data_directory, "geoip")
    destination = os.path.join(destination_directory, "dbip-city-lite.mmdb")
    os.makedirs(destination_directory, exist_ok=True)
    source_url = (
        "https://download.db-ip.com/free/"
        f"dbip-city-lite-{options.release}.mmdb.gz"
    )

    temporary_path = None
    digest = hashlib.sha256()
    written = 0
    try:
        request = Request(source_url, headers={"User-Agent": "Porn-Fetch-Server/1"})
        with (
            urlopen(request, timeout=60) as response,
            gzip.GzipFile(fileobj=response) as compressed,
            tempfile.NamedTemporaryFile(
                dir=destination_directory,
                prefix=".dbip-city-lite-",
                suffix=".tmp",
                delete=False,
            ) as temporary_file,
        ):
            temporary_path = temporary_file.name
            while chunk := compressed.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_DATABASE_BYTES:
                    raise ValueError("GeoIP database exceeds the configured size limit")
                digest.update(chunk)
                temporary_file.write(chunk)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        with open(temporary_path, "rb") as database_file:
            database_file.seek(max(written - 128 * 1024, 0))
            if METADATA_MARKER not in database_file.read():
                raise ValueError("Downloaded file is not a valid MMDB database")
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)

    print(f"Installed {destination}")
    print(f"Release: {options.release}")
    print(f"Size: {written} bytes")
    print(f"SHA-256: {digest.hexdigest()}")


if __name__ == "__main__":
    main()
