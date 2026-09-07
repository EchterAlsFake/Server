"""Integration tests for a disposable restored CE instance. Never sends payment/email."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import tempfile
import uuid
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from license_client import LicenseClient

parser = argparse.ArgumentParser()
parser.add_argument("--root", default="/srv/keygen-restore-test")
parser.add_argument("--port", type=int, default=8005)
args = parser.parse_args()
credentials = json.loads((Path(args.root)/"credentials/product.json").read_text())
base = f"http://127.0.0.1:{args.port}/v1/"
headers = {"Host": "licenses.echteralsfake.me", "X-Forwarded-Proto": "https",
           "Authorization": "Bearer "+credentials["product_token"], "Content-Type": "application/vnd.api+json"}
admin = httpx.Client(base_url=base, headers=headers, trust_env=False, timeout=30)
license_id = str(uuid.uuid4())
clients = []

def send(request):
    headers = dict(request.headers)
    headers.update({"host": "licenses.echteralsfake.me", "x-forwarded-proto": "https"})
    return httpx.request(request.method, f"http://127.0.0.1:{args.port}"+request.url.raw_path.decode(),
                         headers=headers, content=request.content, trust_env=False, timeout=20)

def new_client(folder):
    return LicenseClient(folder, **{k:credentials[k] for k in ("public_key","account_id","product_id","policy_id")},
                         transport=httpx.MockTransport(send))

try:
    created = admin.post("licenses", json={"data":{"id":license_id,"type":"licenses",
                         "relationships":{"policy":{"data":{"type":"policies","id":credentials["policy_id"]}}}}})
    assert created.status_code == 201, ("create", created.status_code)
    key = created.json()["data"]["attributes"]["key"]
    blob = json.dumps({"schema":2,"license_key":key})
    repeated = admin.post("licenses", json={"data":{"id":license_id,"type":"licenses",
                         "relationships":{"policy":{"data":{"type":"policies","id":credentials["policy_id"]}}}}})
    assert repeated.status_code in (409,422), ("duplicate",repeated.status_code)
    assert admin.get("licenses/"+license_id).json()["data"]["attributes"]["key"] == key
    with tempfile.TemporaryDirectory(prefix="keygen-integration-") as temporary:
        clients = [new_client(Path(temporary)/str(index)) for index in range(12)]
        with ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(lambda client:client.import_license(blob),clients))
        states = [r.state for r in results]
        print("Concurrent client states:", {state:states.count(state) for state in set(states)})
        machines = admin.get("machines",params={"license":license_id,"limit":100}).json()["data"]
        assert len(machines)==10, ("machine count",len(machines))
        assert states.count("valid")==10 and states.count("installation_limit")==2, states
        assert all(all(m["attributes"].get(field) is None for field in
                       ("ip","hostname","platform","name","cores","memory","disk")) for m in machines)
        active = clients[states.index("valid")]
        limited = clients[states.index("installation_limit")]
        with active._state() as state:
            record = state["licenses"][license_id]
            certificate = record["permit"]
            machine_id = active.verify_permit(certificate,license_id=license_id,
                installation_id=state["installation_id"],now=active.clock())["machine_id"]
        checkout = admin.post("machines/"+machine_id+"/actions/check-out",
                              json={"meta":{"ttl":604801,"include":["license"]}},
                              headers={"Authorization":"License "+key})
        assert checkout.status_code==400, ("oversize TTL",checkout.status_code)
        assert active.deactivate().state=="deactivated"
        assert limited.check(force=True).state=="valid"
        suspended = admin.post("licenses/"+license_id+"/actions/suspend")
        assert suspended.status_code==200
        result=limited.check(force=True)
        print("Suspended license:",result.state)
        assert not result.allowed
        # Simulate an outage after an explicit rejection: cached grace cannot unlock it.
        limited.http.close()
        limited.http=httpx.Client(base_url="https://licenses.echteralsfake.me/v1/",
            transport=httpx.MockTransport(lambda request: httpx.Response(503)))
        assert not limited.check(force=True).allowed
        active.verify_key(key)  # Restored signing key must match the pre-backup public key.
        print("PASS: restored signing identity, 10-slot concurrency, privacy fields, TTL cap, deactivation, revocation.")
finally:
    for client in clients:
        client.close()
    response=admin.delete("licenses/"+license_id)
    print("Synthetic license cleanup:",response.status_code)
    admin.close()
