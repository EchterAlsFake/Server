# Patreon Shop operations

The email-only `/activate` queue uses the existing annual Keygen policy and SMTP
transport. It never accepts an order ID or returns license data to the browser.
Shop orders and membership webhooks have independent identities and entitlements.

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
   in the worker environment. The file must be owned by the worker account and
   have mode 0600; its directory should have mode 0700. Symlinks are rejected.
   Do not copy the Brave profile or grant access to its cookie database. The web
   service does not need the cookie path; use a worker-only environment override
   when deploying separate credentials. The supplied service uses the same Unix
   user as the existing server; separate Unix accounts are needed if access to
   the export must also be isolated from a compromised web process.
5. Run `flask --app main verify-patreon-shop` with the worker environment. This is
   read-only and prints only aggregate counts. Confirm eligibility for a controlled
   purchase before enabling issuance. Cookie expiration does not guarantee session
   validity; login, security challenges or server-side invalidation can end it early.
6. Set `PATREON_SHOP_ENABLED=true` for the web and worker processes. Install and
   enable `deploy/eaf-patreon-shop.service` and `.timer`, adapting paths/accounts
   for other deployments. The worker runs every minute. Restart web workers after
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
new annual license, not an extension of the previous key.

Timeouts, redirects, authentication failures, blocks, 429s, invalid JSON/schema,
and incomplete scans open a durable circuit breaker. 429 retry delays are honored;
other failures back off five to fifteen minutes. Existing known licenses are reused.
An unknown mailbox receives one fallback grant. A mailbox already known only for
ineligible orders does not get a new fallback during an outage. Invalid input,
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
above ten minutes, repeated fulfillment failures or a sudden rise in fallback grants.
`patreon_shop_health.last_success_at` and `retry_at` record verification health.
The lookup worker must run on one machine with a shared DATA_DIR and SQLite DB;
a nonblocking file lock serializes timer and manual invocations. This is not a
multi-host worker design. Redis provides shared web throttles (five requests per
minute and twenty per hour per IP); only trust a proxy that sanitizes client IPs.

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
