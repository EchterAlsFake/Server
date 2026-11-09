# Patreon Shop operations

The configured purchase URL is `https://www.patreon.com/EchterAlsFake/posts/porn-fetch-174679355?utm_medium=clipboard_copy&utm_source=copyLink&utm_campaign=postshare_creator&utm_content=join_link`.
Live configuration accepts specific Patreon purchase posts as well as specific Shop products; a generic Shop homepage is rejected.

Set `NOWPAYMENTS_SANDBOX=false` and `NOWPAYMENTS_LOCAL_SIMULATION_ENABLED=false` with production API/IPN credentials.

Required rollout flags in the deployed web/worker environment:

```dotenv
NOWPAYMENTS_SANDBOX=false
NOWPAYMENTS_LOCAL_SIMULATION_ENABLED=false
PATREON_SHOP_ENABLED=true
```

Set `PATREON_SHOP_PRODUCT_URL` to the exact purchase URL above, replacing any existing
Shop-homepage override. Keep the verified product variant ID and the existing encrypted
delivery, Redis, Keygen and SMTP settings. Production API/IPN credentials and the provider's
webhook configuration are configured separately by the owner. Updating source or the
example environment files alone does not change the deployed environment.

The `/activate` page supports email delivery and browser retrieval. Browser retrieval
requires both the purchase email and the receipt’s public Patreon order ID. The
worker verifies an eligible sale before returning its signed license to that browser.
New submissions wake a background worker immediately. Scraping runs outside the
HTTP request; the browser can show progress while verification continues. The
scheduled worker remains a fallback for interrupted jobs and delayed retries.
Patreon membership webhooks, tier checks and subscription delivery have been removed. Only Shop sales are verified.

There is no separate security-period agreement or mailbox challenge before purchase.
Set the Patreon Shop listing to EUR 29.99 for lifetime Premium, including every future
Porn Fetch update and feature released, before enabling purchases. Patreon still
handles its own fees and taxes. Update `PATREON_SHOP_PRODUCT_VARIANT_ID` if needed.

## Configure and enable

1. Install project dependencies and run `flask --app main db upgrade` against the
   intended deployment database after backing it up.
2. Configure existing Keygen and SMTP settings and a valid
   `LICENSE_DELIVERY_ENCRYPTION_KEY`. Set `RATELIMIT_STORAGE_URI` to shared Redis.
3. Generate a random `PATREON_SHOP_LOOKUP_KEY` of at least 32 characters. Keep this
   stable and back it up with the encryption key: changing it breaks recovery and
   deduplication. Set `PATREON_SHOP_PRODUCT_VARIANT_ID` to the verified product
   variant ID (the local proof of concept used `5808702`).
4. Export only Patreon cookies in Netscape cookies.txt format to a protected file
   outside Git and the public/static directories, for example
   `/srv/server/data/secrets/patreon-cookies.txt`. Set `PATREON_SHOP_COOKIE_FILE`
   in both the web and scheduled worker environments. The file must be owned by the worker account and
   have mode 0600; its directory should have mode 0700. Symlinks are rejected.
   Do not copy the Brave profile or grant access to its cookie database. Immediate
   processing runs in a background thread in the web process, so that process
   needs the same cookie-file access and Keygen/SMTP configuration as the scheduled
   worker. The supplied services use the same Unix user as the existing server.
5. Run `flask --app main verify-patreon-shop` with the worker environment. This is
   read-only and prints only aggregate counts. Confirm eligibility for a controlled
   purchase before enabling issuance. Cookie expiration does not guarantee session
   validity; login, security challenges or server-side invalidation can end it early.
6. Set `PATREON_SHOP_ENABLED=true` for the web and worker processes. Install and
   enable `deploy/eaf-patreon-shop.service` and `.timer`, adapting paths/accounts
   for other deployments. The timer retries unfinished work every minute; new
   requests start processing immediately. Restart web workers after
   configuration changes. Keep cookies, keys and export contents out of logs/chat.

The unofficial `/api/sales` endpoint is not documented in the public API reference.
Patreon's security policy asks developers to check with Patreon before scraping
for a useful feature: https://www.patreon.com/policy/security . Session blocks or
account restrictions remain a production dependency.

## Matching and failure behavior

A complete sales snapshot is fetched once per batch, at most 100 pages / 5,000
orders and roughly two minutes plus one in-flight request. Only fulfilled,
matching, unrefunded items qualify. A short page alone never proves completion;
missing/changing totals, repeated IDs or malformed relationships produce an
unavailable result. No upstream-provided URL is followed. This endpoint lacks a
snapshot consistency guarantee; offset pagination cannot prove consistency if
orders change without changing the reported total.

Matching preserves email local parts, normalizes IDNA domains, and does not strip
plus tags or dots. Purchases are keyed by internal Patreon order ID. A request
selects the newest eligible order without a license; otherwise it resends the
latest eligible issued license. Multiple historical unissued purchases are handled
one per claim, subject to the fifteen-minute cooldown. A later purchase creates a
new lifetime Premium license, not an extension of the previous key.

Timeouts, redirects, authentication failures, blocks, 429s, invalid JSON/schema,
and incomplete scans open a durable circuit breaker. 429 retry delays are honored;
other failures back off five to fifteen minutes. Existing known licenses are reused.
Unknown purchases remain pending until verification recovers. No new license is
granted solely because verification is unavailable. Browser requests also remain
pending and never disclose a license from an unverified email/order pair. Invalid input,
CSRF errors and throttling do not grant licenses.

On recovery, an unbound fallback is associated with the newest qualifying unissued
purchase dated no later than that grant. This does not send unsolicited email or
create another key. Purchases made later remain eligible for a new license. A grant
that never matches a purchase is retained; it is not automatically revoked.

Keygen/SMTP/database failures retain work for retry rather than triggering Patreon
fallback. Selected license identity is persisted before fulfillment. SMTP handover
and database commit are not atomic, so an email can be duplicated; the key and
Message-ID remain the same. Requests accepted by the page are queued, not promises
that SMTP has delivered a message. Customer support handles persistent bounces.

## Monitoring, rotation and recovery

Read the worker journal for aggregate processed/fallback/pending counts, oldest
pending age, verification health and fixed-category failures. Alert on pending age
above ten minutes or repeated verification/fulfillment failures.
`patreon_shop_health.last_success_at` and `retry_at` record verification health.
The lookup workers must run on one machine with a shared DATA_DIR and SQLite DB.
One background thread per web process coalesces wakeups. A file lock serializes
those threads with timer and manual invocations; immediate workers wait for an
active batch to finish and then drain new intake without waiting for the timer.
They skip completed/cooldown requests and preserve provider and delivery backoff.
Pending database jobs survive a web-process restart and are picked up by the timer.
Redis provides shared throttles (five requests per minute and twenty per hour per
signed browser session, plus sixty submissions per minute for the endpoint).
Status polling is limited to 180 checks per minute per browser session, allowing
both active panels to update once per second; delayed retries poll less often.
The application strips visitor IPs; these limits do not claim to be per-IP.

Replace cookie exports atomically using a fresh 0600 file owned by the worker.
Never inspect/export secrets through application logs. The next circuit-breaker
probe reloads the export. An operator can reset `patreon_shop_health.retry_at` to
zero for an earlier probe after fixing credentials. Do not delete license/purchase
mappings to retry mail; a pending job already retains its selected identity.

To disable new claims while draining work, block `/activate` at the proxy and leave
the enabled worker running. Setting the feature flag false disables both intake and
the worker. Keep schema and outstanding work until the queue is drained; do not
roll back the migration while issuance is active.

Sales responses are memory-only. Completed queue reason/completion details clear
after thirty days while the worker runs. Encrypted recipient, keyed email digest,
last request time, purchase and license mappings remain for recovery. Review valid
erasure requests manually, including contractual evidence, backups and the effect
on future deduplication. Do not promise recovery after deleting those mappings.

## MSI rootless deployment

The MSI host uses `sudo pfctl update web`, not the legacy `/srv/server` layout.
Pin `curl-cffi==0.17.0` in the infrastructure repository's
`ops/web.requirements.txt` and its installed constraints before building. The
candidate image runs the server tests before the coordinated backup, migration
and image cutover. Persistent application files live in the `pornfetch-data`
volume mounted at `/data`.

The matching user units are supplied in `deploy/rootless/`. Install them into
the `pornfetch` account's user-systemd directory and mirror them in the
infrastructure repository's `ops/user-systemd/`. Register `patreon-shop` as the
`pornfetch-patreon-shop.timer` component in `pfctl` so maintenance commands also
control it. The worker executes inside the running web container with the same
credential wrapper as the existing delivery jobs.

Add the feature flag, product-variant ID and cookie-file path to the web and
migration Quadlets. Store the stable lookup key as a TPM-sealed user credential
named `PATREON_SHOP_LOOKUP_KEY` and load it in both units, following their existing
credential pattern. Keep the cookie export at `/data/secrets/patreon-cookies.txt`,
owned by container UID 1000 with mode 0600 in a 0700 directory. It is covered by
the existing encrypted application backups. The web and worker share a Unix
identity in this layout; the export is not isolated from the web process.

Before enabling the flag, run `verify-patreon-shop` inside the container through
the credential wrapper with the cookie path and variant ID supplied. After a
successful complete scan, enable the flag, reload the user manager, restart web,
and enable the minute timer. Check the public activation page, CSRF rejection,
Keygen policy and worker status without creating a customer claim or sending a
test email. Preserve the existing lookup key on future deployments.

## Browser recovery

The migration `e8b42f930d16` adds `patreon_shop_lookups`. The form posts credentials
with CSRF protection; they never appear in a URL. The table holds HMAC email and
public-order-ID values, a random request ID, time, status and license association.
Only the random request ID is put into the signed, secure session cookie.

The background worker fetches a complete snapshot and compares both values
against `buyer_email` and `public_order_id`, also checking product, fulfilled status
and refund state. Internal order IDs cannot substitute for receipt IDs. The same
purchase/license mapping is used for email delivery and browser requests.
Issuance failures retry using that mapping. Browser requests never use outage
fallbacks without a verified matching purchase. Historical fallback mappings are
retained and may be reconciled with an earlier verified sale.

The result is readable at `/activate`, polled at `/activate/status`, and downloadable
through the CSRF-protected `POST /activate/download`. All responses, including errors,
use `no-store` and `no-referrer`. Requests expire after fifteen minutes; the worker
deletes expired rows. Without JavaScript, refresh the result page manually.

## Commercial handoff

With `NOWPAYMENTS_SANDBOX=false`, the picker omits test acknowledgments and the
Patreon handoff presents the configured Shop product with purchase instructions.
It still requires the website declarations and a current offer digest. Set the
actual product URL and variant ID before enabling live Patreon purchases. A Shop
homepage is rejected as the live product URL.

The private sales endpoint remains an external policy and availability dependency.
Patreon’s security policy requires checking with Patreon before this kind of
automated access; technical success does not establish authorization.
