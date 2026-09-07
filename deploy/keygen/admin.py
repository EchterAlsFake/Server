#!/srv/server/.venv/bin/python
"""Local support operations; never prints signed keys or tokens."""
import argparse
import json
from pathlib import Path
import uuid
import httpx

parser = argparse.ArgumentParser()
parser.add_argument("action", choices=["machines", "deactivate", "suspend", "reinstate"])
parser.add_argument("id", type=lambda value: str(uuid.UUID(value)))
args = parser.parse_args()
credentials = json.loads(Path("/srv/keygen/credentials/product.json").read_text())
with httpx.Client(base_url="http://127.0.0.1:8004/v1/", timeout=15, trust_env=False,
                  headers={"Host": "licenses.echteralsfake.me", "X-Forwarded-Proto": "https",
                           "Authorization": "Bearer " + credentials["product_token"],
                           "Content-Type": "application/vnd.api+json"}) as api:
    if args.action == "machines":
        response = api.get("machines", params={"license": args.id})
        response.raise_for_status()
        for item in response.json()["data"]:
            print(item["id"], item["attributes"]["fingerprint"])
    elif args.action == "deactivate":
        response = api.delete("machines/" + args.id)
        print("HTTP", response.status_code)
        response.raise_for_status()
    else:
        action = "suspend" if args.action == "suspend" else "reinstate"
        response = api.post("licenses/" + args.id + "/actions/" + action)
        print("HTTP", response.status_code)
        response.raise_for_status()
