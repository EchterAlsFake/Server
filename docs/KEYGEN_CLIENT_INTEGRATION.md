# Application agent handoff: Keygen licensing

Implement this in the actual Porn Fetch application. The server repository contains a
tested reusable client; the desktop application's integration is a separate deliverable.
Do not release an application that expects the previous schema-1 license format.

## Files and dependencies

Copy the `license_client/` package from this repository into the application.
Dependencies: Python 3.10 or newer, `cryptography`, and `httpx`. Keep
`license_client/production.json` with the application: it contains only the public
Ed25519 verification key and account/product/policy IDs. It is public configuration,
not a secret. Never fetch a replacement verification key from an imported license or
the network. Private keys and product/admin tokens must never enter the application.

The endpoint is `https://licenses.echteralsfake.me`. TLS verification stays enabled.
Requests use the imported signed key as a license-scoped credential.

## Product behavior

Both NOWPayments purchases and qualifying paid Patreon memberships grant perpetual
access to `full_unlock`. Membership cancellation does not revoke a license.
Ten active installation profiles may be registered per license. These are persistent
random UUIDv4 identities, not physical-computer identities. Never read MAC addresses,
hardware serial numbers, hostname, OS machine IDs, or `uuid.getnode()`/`uuid.uuid1()`.

Choose the application's normal per-user persistent data directory using its existing
platform abstraction. Create a dedicated licensing subdirectory. Preserve it across
updates and ordinary reinstall operations; never put it in a cache or temporary folder.
On Windows apply the application's normal current-user-only directory ACL; POSIX
permissions are handled by the module. A copied profile is the same installation.
Do not silently recreate an unreadable database.

## Initialization and calls

```python
import json
from pathlib import Path
from license_client import LicenseClient, LicenseError

config = json.loads(Path("license_client/production.json").read_text())
client = LicenseClient(app_data_dir / "licensing", **config)

# Run network work in a background task, never on the UI event thread.
status = client.check()  # startup, and every 60 seconds while the app is open
status = client.import_license(selected_file.read_bytes())  # explicit user import
status = client.check(force=True)  # explicit Retry/Refresh button
status = client.deactivate()  # explicit Deactivate installation button
client.close()  # shutdown
```

Adapt resource loading to the application's packaging system (including frozen builds).
Use one long-lived client instance per process. SQLite transactions serialize state
changes across processes; operations can wait up to 30 seconds for its lock.
Catch `LicenseError` and present a recoverable licensing message. Never log the imported
file, credential, network headers/bodies, or local state database contents.

The module stores a schema-2 envelope's signed Keygen key. Unsigned envelope fields do
not confer permissions. Signed claims must match the compiled-in product, account and
policy. The client verifies the separate signed machine permit and seven-day expiry.

## UI and feature gating

Use `LicenseStatus.allowed` to gate premium features; keep existing free functionality,
license import, support and data access available. Never delete customer data or abort
an already-running export/download because renewal failed.

| State | Display and action |
| --- | --- |
| valid | Licensed; show installation management and optional expiry of offline permit. |
| provisional | Server unavailable; temporary access ends at `expires_at`; offer Retry. |
| offline_grace | Previously activated; offline access ends at `expires_at`; offer Retry. |
| expired_grace | Premium access paused; reconnect and retry. |
| installation_limit | All ten slots are in use; deactivate another installation or contact support. |
| revoked / rejected / not_found | Server rejected the license; offer retry and support. |
| invalid_signature | Invalid or mismatched license/permit; offer import and support. |
| clock_invalid | Correct the device clock and reconnect. |
| unlicensed | Offer import and the existing purchase link. |
| deactivation_pending / deactivation_failed | Slot release is not confirmed; retain state and offer retry. |
| deactivated | This installation is released and premium access is disabled. |

After every call, update the UI on the main thread. Periodic `check()` enforces expiry
even if the app stays open for weeks; actual online renewal happens at most daily under
normal operation. Transient failures use bounded exponential retry backoff, at most one
hour. Explicit retry bypasses the delay. Avoid adding independent timers that renew
on every screen change or download.

## Grace and trust boundaries

First offline import grants seven days measured from the locally persisted first import.
Reopening, reimporting, or switching between previously imported licenses does not restart
their deadlines. Successful activation permanently transitions that local license to signed
seven-day machine permits. A failed renewal cannot extend a permit.

An explicit rejection blocks access even if a cached permit remains. An offline client
cannot discover revocation until it reconnects or its permit expires. Deactivation frees
a server slot immediately after confirmation; copied permits can still be used offline
until expiry. Deleting all local state, cloning it, changing the application, and deliberate
clock manipulation cannot be prevented reliably without a different trust model. These
limitations are intentional; do not add hardware fingerprinting to address them.

## Application acceptance tests

Run the module's tests and add integration tests for the application's actual feature gates:

- Import from file picker and drag/drop; reject oversized or malformed files safely.
- Activate on each supported OS and packaged binary; persist UUID across updates/restarts.
- Network work never freezes UI; close/shutdown works during retries.
- First offline import, seven-day boundary, restart/reimport, clock rollback and recovery.
- A running app stops starting new premium work after grace expires.
- Ten UUIDs succeed; the eleventh is refused; deactivation permits a replacement.
- Explicit server rejection remains blocked during an outage.
- Invalid signature/product/UUID and excessive permit TTL never unlock features.
- No customer keys, hardware identifiers, or browsing/download history enter logs or requests.
- A frozen build loads the bundled public configuration, with no admin credentials.
