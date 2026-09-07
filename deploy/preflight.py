"""Validate production setup without printing secrets or contacting providers."""
import os
from pathlib import Path
import sys

from dotenv import load_dotenv

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
load_dotenv(root / ".env")

required = (
    "SECRET_KEY", "CHECKLIST_AUTH", "KEYGEN_PRODUCT_TOKEN", "KEYGEN_POLICY_ID",
    "NOWPAYMENTS_API_KEY", "NOWPAYMENTS_IPN_SECRET", "PATREON_SECRET",
    "LICENSE_SMTP_HOST",
)
missing = [name for name in required if not os.environ.get(name, "").strip()]
if missing:
    raise SystemExit("Fill required settings: " + ", ".join(missing))
from pf_server.config import load_environment_config
config = load_environment_config(str(root))
if not config["LICENSE_EMAIL_FROM"]:
    raise SystemExit("Fill LICENSE_EMAIL_FROM or LICENSE_SMTP_USERNAME")
import maxminddb
with maxminddb.open_database(config["GEOIP_DATABASE_PATH"]) as reader:
    reader.metadata()
print("Production configuration and local GeoIP database validated.")
