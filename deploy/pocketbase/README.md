# PocketBase error-log integration

Verified on 2026-09-17 after the security and reliability audit. This guide documents the deployed server and the contract for project clients.

Pinned Linux amd64 artifact: https://github.com/pocketbase/pocketbase/releases/download/v0.40.4/pocketbase_0.40.4_linux_amd64.zip

SHA-256: 9042ec818570e79c3628dadcd0a756c1496d9e1173918ec409d133c02f82e5fa

## Public contract

Send an unauthenticated POST to https://api.echteralsfake.me/error_log with Content-Type: application/json and exactly one string property:

~~~json
{"message":"download_failed: media transfer failed"}
~~~

No PocketBase SDK, login, bearer token, API key, cookies, user/device ID, or additional fields are needed. Do not use the PocketBase collections API. Do not add query parameters or a trailing slash. The endpoint accepts deliberate diagnostic messages; it does not accept Sentry envelopes, automatic exception dumps, stack traces as separate fields, or arbitrary metadata.

The original trimmed message must contain 1–2000 UTF-16 code units (JavaScript string length). The ENTIRE serialized UTF-8 JSON request must be at most 4096 bytes; 2000 characters alone does not guarantee this. Redaction runs before storage, then its output is bounded to 2000 code units and checked for emptiness. Redaction may expand text and may truncate the sanitized result. Successful storage returns 204 with no response body or record ID.

| HTTP status | Client handling |
| --- | --- |
| 204 | Stored; do not parse a JSON response. |
| 400 | Invalid JSON/fields/message, query parameters, or an empty sanitized result. Fix the request; do not retry unchanged input. |
| 405 | Wrong method at the public proxy, including browser OPTIONS. |
| 413 | Serialized body exceeds 4096 bytes, including chunked requests. |
| 415 | Content-Type is not application/json. |
| 429 | Admission/per-IP limit hit. Drop or defer reports; avoid immediate retry loops. |
| 503 | Storage is full/unavailable. Reporting must not break the original operation. Current Retry-After is 3600 seconds. |
| 5xx/timeout/network error | Best effort failure; preserve normal application behavior. |

The per-IP allowance is 10 requests in a 60-second fixed window, shared by clients behind the same public/NAT address. A separate atomic global token bucket allows a burst of 120 attempts, refilling at 2 tokens/second. Invalid requests also consume admission capacity. Global throttling returns Retry-After: 1; the native per-IP limiter does not guarantee that header, so allow at least 60 seconds before a deferred retry. Prefer dropping repetitive diagnostics and locally deduplicating/rate-limiting them.

## Client implementation

Choose fixed event codes and safe messages at the call site. Do not interpolate exception text, filenames, usernames, paths, URLs, licence keys, HTTP headers, cookies, request/response bodies, or personal data. A regex scrubber cannot prove arbitrary input is anonymous. Redaction on the server happens after transport, so it cannot replace this client-side selection.

Standard-library Python example:

~~~python
import json
from urllib.error import URLError
from urllib.request import Request, urlopen

ERROR_MESSAGES = {
    "download_failed": "download_failed: media transfer failed",
    "provider_unavailable": "provider_unavailable: upstream service unavailable",
    "license_check_failed": "license_check_failed: validation request failed",
}

def report_error(code: str) -> bool:
    message = ERROR_MESSAGES.get(code)
    if message is None:
        return False
    body = json.dumps({"message": message}, ensure_ascii=False).encode("utf-8")
    if len(body) > 4096:
        return False
    request = Request(
        "https://api.echteralsfake.me/error_log",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=2) as response:
            return response.status == 204
    except (OSError, URLError):
        return False
~~~

Call this through the project's bounded background-work mechanism, with local deduplication and a small queue. Do not create an unbounded thread/task per exception or block the UI thread. Leave normal TLS certificate verification enabled. Reporting failures must not recursively report themselves. The example uses intentionally fixed messages; add new reviewed messages to the mapping as needed.

For same-origin browser pages, fetch can use credentials: "omit" and a short AbortSignal timeout. Cross-origin JSON requests from the apex/docs/another web application require a same-origin backend relay: Caddy rejects OPTIONS, so this service does not support cross-origin browser preflight. Do not work around that with no-cors or by exposing PocketBase administration.

## Architecture and server implementation

Traffic follows the existing trusted WireGuard/PROXY-protocol ingress into Caddy. Only exact /error_log on host api.echteralsfake.me is sent to loopback 127.0.0.1:8090. Other paths on that host continue to the Flask service; /api/ and /_/ are not public PocketBase routes.

- PocketBase binary: /srv/pocketbase/pocketbase, version 0.40.4.
- Service: eaf-pocketbase.service, dedicated user/group eaf-pocketbase.
- Hook: /srv/pocketbase/pb_hooks/error_log.pb.js.
- Shared redaction helper: /srv/pocketbase/pb_hooks/redact.js.
- Migrations: /srv/pocketbase/pb_migrations/1758120000_create_error_logs.js and 1789650000_bound_error_intake.js.
- Private runtime data: /var/lib/eaf-pocketbase. Never put it in Git or the note vault.
- Caddy snippet: /etc/caddy/conf.d/managed-sites.caddy.
- Working source, regression tests, and service template: `deploy/pocketbase/` in this repository.
- Working proxy source/tests: `deploy/managed-sites.caddy` and `deploy/test_proxy.py`.

The application collection is error_logs, containing only PocketBase-generated id, created, updated, and the sanitized message. Framework/auth collections also exist. All five collection CRUD rules on error_logs are null/locked to ordinary clients. The custom route explicitly creates the record on the server. Public users signup is disabled; existing users are preserved. Superuser access requires both authentication and a loopback address. No client should carry a superuser token.

The handler validates type/schema/length and reads a one-byte overflow sentinel beyond the 4096-byte contract so a valid JSON prefix cannot hide an oversized chunked body. The middleware internal body cap is 4097 bytes solely to permit overflow detection. A cached collection lookup avoids a metadata query for each report. Storage failures return a generic 503 without database internals or submitted text.

## Privacy, logging, and security

The server removes controls/selected invisible formatting characters before matching secrets. It scrubs quoted JSON/Python-style credentials, prefixed keys such as access_token and license_key, Bearer/Basic values, cookies, private-key blocks, email/IP patterns, and entire URL values including userinfo, paths, queries, and fragments. Arbitrary unlabeled secrets or personal data cannot reliably be detected; use fixed client messages.

Caddy removes Authorization and Cookie as well as Origin, Referer, client-supplied forwarding aliases, and the original User-Agent. It supplies EAF-Error-Relay and reconstructs trusted forwarding headers. The hook also removes auth/cookies before native authentication, so credentials cannot switch this public intake into an exempt authenticated/superuser rate-limit class. Caddy and the hook apply no-store; this is cache control, not a promise of no network metadata anywhere.

PocketBase activity-log persistence is disabled with maxDays=0, minLevel=8, logIP=false, logAuthId=false and dev=false. Client IPs are used in the native limiter's transient in-memory map, not saved as error record fields. Native limiter cleanup is hourly and only evicts clients after at least 30 minutes of inactivity; a process restart clears memory. Service startup/operational messages remain in the system journal. Storage failures emit a fixed message at most once per minute, without request data. This audit did not verify logging on the external relay/provider.

HTTP bounds: headers 5 seconds, total request read 10 seconds, writes 15 seconds, idle keepalive 60 seconds, headers 16 KiB. Caddy's PocketBase upstream has connect/write/read/response-header deadlines. The service has MemoryHigh=192 MiB, MemoryMax=256 MiB, CPUQuota=100% (one CPU worth), TasksMax=64, and LimitNOFILE=4096, plus its existing filesystem/user sandbox and namespace restriction.

An atomic SQLite insertion trigger caps error_logs at 100,000 records. At capacity, submissions receive 503; existing records are NOT evicted. There is no automatic expiration. Administrators must review/remove records according to their retention needs. Do not infer that disabling PocketBase activity logs deletes error_logs or stops application error storage.

## Operations and rollout

For administration use an authenticated SSH tunnel to the loopback-only PocketBase UI:

~~~sh
ssh -L 8090:127.0.0.1:8090 user@server.example
~~~

Then open http://127.0.0.1:8090/_/ and authenticate with operator-managed superuser credentials. No credentials belong in source, CLI examples with actual values, or this note.

Test changes first:

~~~sh
POCKETBASE_BIN=/srv/pocketbase/pocketbase python deploy/pocketbase/test_error_log.py
python deploy/test_proxy.py
~~~

The tests start isolated loopback services and temporary databases. They never seed or clear the production collection.

Before rollout take a private consistent backup while PocketBase is stopped. Install both hook files and the migrations, then explicitly run PocketBase migrate up as eaf-pocketbase using /var/lib/eaf-pocketbase and the production hooks/migrations paths. Production keeps automigrate=false and hooksWatch=false; restart after changing hooks. Validate Caddy with its existing service environment before reloading. Preserve the global ECH/DNS/PROXY protocol settings and all unrelated routes. Normal eaf-deploy server does not install these system changes automatically.

The rollout created a root-only local rollback snapshot containing the previous
hook, migrations, service unit, Caddy snippet, and a consistent database copy.
Its generated path is intentionally not documented in this public repository.
No scheduled PocketBase backups were added. Manual rollback snapshots still
contain private data and require deliberate retention. Rolling back the new
migration drops the storage cap but intentionally does not reopen signup or
relax rate-limit settings.

## Verification and audit result

The audit reproduced credential-redaction leaks, an oversized chunked-body bypass, and failures when redaction expanded a message. All were fixed and deployed. The default users signup permission was locked, per-IP limits made audience-independent, and request-wide auth stripping, aggregate admission, storage bounds, timeouts and process limits added.

Eleven isolated PocketBase integration tests pass, including UTF-8 byte boundaries, quoted secrets, controls, a 100,000-record capacity fixture, 200 concurrent admission attempts, collection/signup access checks, and empty activity logs. Separate Caddy tests pass for header stripping, host/method scoping, and existing service routing. Full production Caddy validation passed.

Live non-storing public checks returned GET 405, invalid JSON-object POST 400, and text/plain POST 415. The service remained on loopback, the migration/settings were present, and both error_logs and PocketBase activity logs contained zero records after verification. Health alone is insufficient: PocketBase can start even when JS hook registration fails, so also check the custom route.

~~~sh
curl -fsS http://127.0.0.1:8090/api/health
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Content-Type: application/json' --data '{"invalid":true}' \
  https://api.echteralsfake.me/error_log
~~~

Expected statuses: 200 health, 400 invalid input without storing a record. A successful 204 smoke test WOULD create a diagnostic; use only deliberately approved synthetic content. Never treat an arbitrary 404 on / as a health check.

Reference: https://github.com/pocketbase/pocketbase/releases/tag/v0.40.4 and the deployed-version middleware/binding source. The checked worker-panic advisory GHSA-84vh-m24q-wjjx was fixed upstream in v0.39.7; the installed v0.40.4 already includes that fix.
