# PocketBase error-log integration

The current source accepts detailed, consented error reports. Deploy the updated hook, proxy configuration and `1793750400_full_error_reports.js` migration together before releasing the updated client. The previous deployed contract accepted only 2,000-character messages in 4 KiB requests and removed URLs; changing the client alone is insufficient. Local verification does not establish production deployment.

Pinned Linux amd64 artifact: https://github.com/pocketbase/pocketbase/releases/download/v0.40.4/pocketbase_0.40.4_linux_amd64.zip

SHA-256: 9042ec818570e79c3628dadcd0a756c1496d9e1173918ec409d133c02f82e5fa

## Public contract

Send an unauthenticated POST to https://api.echteralsfake.me/error_log with Content-Type: application/json and exactly one string property:

~~~json
{"message":"download_failed: media transfer failed"}
~~~

No PocketBase SDK, login, bearer token, API key, cookies, user/device ID, or additional fields are needed. Do not use the PocketBase collections API. Do not add query parameters or a trailing slash. Full Python tracebacks and reproduction context, including video URLs, belong inside the single message string. Sentry envelopes and separate metadata fields are not accepted.

The ENTIRE serialized UTF-8 JSON request must be at most 1,048,576 bytes (1 MiB). The message must contain diagnostic text, rather than only whitespace or control characters. Accepted messages are stored verbatim, including URLs, query strings, source lines, exception messages and final newlines. Neither the receiver nor client silently redacts or shortens a traceback. Oversized reports are rejected or skipped as a whole. Successful storage returns 204 with no response body or record ID.

| HTTP status | Client handling |
| --- | --- |
| 204 | Stored; do not parse a JSON response. |
| 400 | Invalid JSON/fields/message or query parameters. Fix the request; do not retry unchanged input. |
| 405 | Wrong method at the public proxy, including browser OPTIONS. |
| 413 | Serialized body exceeds 1 MiB, including chunked requests. |
| 415 | Content-Type is not application/json. |
| 429 | Admission/per-IP limit hit. Drop or defer reports; avoid immediate retry loops. |
| 503 | Storage is full/unavailable. Reporting must not break the original operation. Current Retry-After is 3600 seconds. |
| 5xx/timeout/network error | Best effort failure; preserve normal application behavior. |

The per-IP allowance is 10 requests in a 60-second fixed window, shared by clients behind the same public/NAT address. A separate atomic global token bucket allows a burst of 120 attempts, refilling at 2 tokens/second. Invalid requests also consume admission capacity. Global throttling returns Retry-After: 1; the native per-IP limiter does not guarantee that header, so allow at least 60 seconds before a deferred retry. Prefer dropping repetitive diagnostics and locally deduplicating/rate-limiting them.

## Client implementation

Porn Fetch builds reports in `src/shared/error_reporting.py`. Reports contain the full exception chain and explicit diagnostic context, including the failing video URL when available. They do not collect local-variable dumps or attach cookies, credentials or authorization headers, but tracebacks and URLs can themselves contain personal or sensitive data. The client explains this before opt-in. Users who enabled the older structural reports must consent again; existing opt-outs stay disabled. Never send detailed reports on the strength of the older disclosure.

Standard-library Python example:

~~~python
import json
import traceback
from urllib.error import URLError
from urllib.request import Request, urlopen

def report_error(error: Exception, video_url: str, *, enabled: bool) -> bool:
    if not enabled:
        return False
    message = f"video_url={video_url}\n" + "".join(traceback.format_exception(error))
    body = json.dumps({"message": message}, ensure_ascii=False).encode("utf-8")
    if len(body) > 1048576:
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

The synchronous example illustrates the wire contract; Porn Fetch uses its existing asynchronous sender. Do not block the UI thread. Leave normal TLS certificate verification enabled. Reporting failures must not recursively report themselves or break the original operation.

For same-origin browser pages, fetch can use credentials: "omit" and a short AbortSignal timeout. Cross-origin JSON requests from the apex/docs/another web application require a same-origin backend relay: Caddy rejects OPTIONS, so this service does not support cross-origin browser preflight. Do not work around that with no-cors or by exposing PocketBase administration.

## Architecture and server implementation

Traffic follows the existing trusted WireGuard/PROXY-protocol ingress into Caddy. Only exact /error_log on host api.echteralsfake.me is sent to loopback 127.0.0.1:8090. Other paths on that host continue to the Flask service; /api/ and /_/ are not public PocketBase routes.

- PocketBase binary: /srv/pocketbase/pocketbase, version 0.40.4.
- Service: eaf-pocketbase.service, dedicated user/group eaf-pocketbase.
- Hook: /srv/pocketbase/pb_hooks/error_log.pb.js.
- Historical redaction helper: /srv/pocketbase/pb_hooks/redact.js; no longer applied to incoming error reports.
- Migrations: /srv/pocketbase/pb_migrations/1758120000_create_error_logs.js, 1789650000_bound_error_intake.js and 1793750400_full_error_reports.js.
- Private runtime data: /var/lib/eaf-pocketbase. Never put it in Git or the note vault.
- Caddy snippet: /etc/caddy/conf.d/managed-sites.caddy.
- Working source, regression tests, and service template: `deploy/pocketbase/` in this repository.
- Working proxy source/tests: `deploy/managed-sites.caddy` and `deploy/test_proxy.py`.

The application collection is error_logs, containing only PocketBase-generated id, created, updated, and the full message. The new migration raises the existing message field maximum to 1,048,576 without deleting reports or changing access rules. Framework/auth collections also exist. All five collection CRUD rules on error_logs are null/locked to ordinary clients. The custom route explicitly creates the record on the server. Public users signup is disabled; existing users are preserved. Superuser access requires both authentication and a loopback address. No client should carry a superuser token.

The handler validates type/schema/length and reads a one-byte overflow sentinel beyond the 1 MiB contract so a valid JSON prefix cannot hide an oversized chunked body. The middleware internal body cap is 1,048,577 bytes solely to permit overflow detection. The Caddy intake limit is also 1,048,576 bytes. A cached collection lookup avoids a metadata query for each report. Storage failures return a generic 503 without database internals or submitted text.

## Privacy, logging, and security

Reports are private debugging data stored securely on the operator's server, never shared with third parties and used only to reproduce, diagnose and fix application errors. Intake no longer redacts report contents: video URLs, paths, query strings and exception details are needed for reproduction. They can contain sensitive or personal information. This includes any secrets present in source lines, exception messages or URLs, despite the client not attaching authentication data. Do not treat these records as anonymous or copy them into public issues. The English and German privacy disclosures describe this behavior.

Caddy removes Authorization and Cookie as well as Origin, Referer, client-supplied forwarding aliases, and the original User-Agent. It supplies EAF-Error-Relay and reconstructs trusted forwarding headers. The hook also removes auth/cookies before native authentication, so credentials cannot switch this public intake into an exempt authenticated/superuser rate-limit class. Caddy and the hook apply no-store; this is cache control, not a promise of no network metadata anywhere.

PocketBase activity-log persistence is disabled with maxDays=0, minLevel=8, logIP=false, logAuthId=false and dev=false. Client IPs are used in the native limiter's transient in-memory map, not saved as error record fields. Native limiter cleanup is hourly and only evicts clients after at least 30 minutes of inactivity; a process restart clears memory. Service startup/operational messages remain in the system journal. Storage failures emit a fixed message at most once per minute, without request data. This audit did not verify logging on the external relay/provider.

HTTP bounds: headers 5 seconds, total request read 10 seconds, writes 15 seconds, idle keepalive 60 seconds, headers 16 KiB. Caddy's PocketBase upstream has connect/write/read/response-header deadlines. The service has MemoryHigh=192 MiB, MemoryMax=256 MiB, CPUQuota=100% (one CPU worth), TasksMax=64, and LimitNOFILE=4096, plus its existing filesystem/user sandbox and namespace restriction.

An atomic SQLite insertion trigger caps error_logs at 100,000 records. At capacity, submissions receive 503; existing records are NOT evicted. There is no automatic expiration. Administrators must review/remove records according to their retention needs. Do not infer that disabling PocketBase activity logs deletes error_logs or stops application error storage.

## Manual diagnostic deletion

Operator policy confirmed on 2026-10-31: remove diagnostic reports manually, preferably with each new published application version. There is no fixed retention period or automatic deletion job. This describes the intended practice, not a guarantee that every release has already triggered deletion. The unresolved retention assessment is recorded in `docs/LEGAL_REVIEW_2026-10-31.md`.

Reports are database records in the `error_logs` collection, not individual text files. Use the existing protected PocketBase administration interface to delete the intended records. Do not delete the whole database or runtime directory as a substitute: it also holds the collection schema and administrative/authentication data. Review any exports, backups and restored copies separately so that deletion from the active collection is not mistaken for deletion from every copy. No production deletion was performed as part of this documentation update.

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

Before rollout take a private consistent backup while PocketBase is stopped. Install the hook and migrations, then explicitly run PocketBase migrate up as eaf-pocketbase using /var/lib/eaf-pocketbase and the production hooks/migrations paths. Production keeps automigrate=false and hooksWatch=false; restart after changing hooks. Install the matching 1 MiB Caddy intake limit, validate Caddy with its existing service environment and reload. Publish the matching privacy disclosure and deploy the receiver before distributing the updated app. Preserve the global ECH/DNS/PROXY protocol settings and all unrelated routes. Normal eaf-deploy server does not install these system changes automatically.

The rollout created a root-only local rollback snapshot containing the previous
hook, migrations, service unit, Caddy snippet, and a consistent database copy.
Its generated path is intentionally not documented in this public repository.
No scheduled PocketBase backups were added. Manual rollback snapshots still
contain private data and require deliberate retention. Rolling back the new
migration drops the storage cap but intentionally does not reopen signup or
relax rate-limit settings.

## Historical audit and current verification

The statements below describe the 2026-09-17 deployed audit. The detailed-report source change was tested locally with isolated databases, including verbatim traceback/URL storage beyond 4 KiB and the new byte boundary. It has not been deployed by this change. The earlier redaction behavior and 4 KiB limit are intentionally superseded by the current source contract above.

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
