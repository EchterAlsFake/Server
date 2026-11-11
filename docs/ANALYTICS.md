# Aggregate website measurement

The optional collector counts events rather than people. It never creates a visitor
identifier or stores individual event rows. The existing business database is not
queried by the collector or reporter. No purchase-completion events are collected.

## Collection and reports

Set `AGGREGATE_ANALYTICS_ENABLED=true` only after the rollout checks below. The
default is false. No database is created until collection or a CLI command runs.
A local script on allowlisted pages sends `{page, action}` to `/_metrics/event`.
Page names are fixed IDs derived from the server's guide/platform catalogs, never
request parameters. Actions are page displays, download/premium/help links,
platform choices, installation-guide links, package download clicks, and clicks
on the checkout continue button. The latter records an attempt, not a validated
form submission. Generic checkout displays deliberately omit provider/order IDs.
Success, recovery, license, account, legal, arbitrary release-detail and unknown
pages are excluded. Only APP_DOMAIN participates; onion and docs hosts are excluded.

Requests omit cookies and referrers; the script uses no storage or fingerprinting.
DNT/GPC suppress collection. There is no connected funnel, returning-visitor
count, installation detection, or attribution of purchases to guides. Repeat clicks,
reloads, bots and forged events can inflate counts. Blocked scripts and interrupted
navigation can reduce counts. The shared 6,000/minute limiter protects availability,
not measurement integrity, and stores no visitor-specific rate-limit keys.

`DATA_DIR/aggregate-analytics.sqlite3` contains only
`daily_counts(day, page, action, count)`. File permissions are 0600. Collection
atomically increments a daily counter using SQLite, with a one-second lock timeout;
storage failures return 503 with a fixed log message and never block navigation.
The store contains no per-event timestamp or join key. Daily totals are still
sensitive operational data: do not publish the database or grant analytics readers
access to purchase data. Suppression reduces exposure; it is not differential
privacy or a mathematical guarantee against inference from outside information.

Run as the service user from the deployed application directory:

```sh
.venv/bin/flask --app main analytics-report --weeks 4
.venv/bin/flask --app main analytics-purge
```

Reports return JSON for completed Monday–Sunday UTC weeks, omitting cells below
20 events and providing no totals over suppressed cells. Current-week counters
are unavailable through the report. There is deliberately no public reporting API.
Compare `open_download`/`pageview` within a guide as an event ratio, never a user
conversion or abandonment rate. Independent stage totals do not establish that
the same visitors progressed. Platform choices record the destination only on the
current page; they do not follow users onto the next page.

Retain counters for thirteen calendar months. Collection and reporting purge old
rows; install `deploy/eaf-analytics-purge.service` and `.timer` under
`/etc/systemd/system/`, then run `systemctl daemon-reload` and
`systemctl enable --now eaf-analytics-purge.timer` so inactivity does not prevent
cleanup. Monitor timer failures. Backups must also expire; deleting working rows
does not remove old backups or filesystem snapshots.

## Deployment checks

1. Keep collection disabled while validating the deployment. This repository change
   does not modify the running server, dashboard, Caddy root configuration, logs,
   or historical databases.
2. Deploy the application and the updated `deploy/pornfetch-site.caddy` together.
   It retires the old product-host `/__eaf/visit*` routes (410), skips collector access
   logging, bounds request bodies and strips identifying forwarded headers. Validate
   the full Caddy configuration with the existing global ECH/DNS/PROXY settings.
   The application requires an exact Origin header and rejects query parameters,
   ambient Cookie/Authorization headers and fields outside its allowlist.
3. Verify all other proxy/platform/access/error logs and tracing omit collector
   bodies, raw headers, source IPs, request IDs and individual analytics event logs.
   Gunicorn must retain its access-log-disabled configuration. The local development
   handler also skips the collector. Caddy cannot control upstream infrastructure
   logging. Transport metadata necessarily exists while requests are processed.
4. Review the legacy visitor counter and download importer using
   `deploy/dashboard-privacy/README.md`. Its prepared migration is separate from
   this change. Other hosts retain their existing visitor endpoints. Decide retention
   and remove obsolete identifying working records, logs and backups after a verified
   migration; do not treat a disabled script as deletion of historical data.
5. Verify the precise deployment's TDDDG/GDPR basis. Cookie-free does not by itself
   establish that consent is unnecessary. Review the conditional EN/DE privacy
   disclosures and install the retention timer before enabling the collector.
6. Enable the environment flag, restart the application and inspect synthetic browser
   requests: only page/action, no cookies/referrer/query strings. Verify sparse report
   suppression and the onion exclusion. Never use real customer data for these checks.
7. Establish four weeks of baseline. Start with the XVideos, Eporner and XHamster
   guides. Compare Search Console page/query CTR and ranking separately from guide
   action rates; align reporting windows explicitly (GSC dates use Pacific time,
   local counters UTC). Google clicks and local page displays are different measures.
   Change one guide or call to action at a time. Record editorial changes without
   identifying visitors. The MCP connection already supports read-only GSC reports;
   there is no new Google browser script or user-level data join.

Disable the flag to stop collection immediately; reports and purge still work.
Retire the new database according to the chosen retention policy if removing the
feature. Do not re-enable the former visitor script as a rollback.

## Private dashboard integration

The dashboard adds a **Website analytics** tab and `/dashboard/analytics` shortcut.
Its existing session authentication protects `/dashboard/api/analytics?weeks=4`.
The selectable periods are 4, 8, 12, 26 and 52 completed weeks. Search filters the
published cells; action/display ratios are computed only when both cells are
reportable for the same page and week. Missing activity is never presented as zero.
The collection status, snapshot date and stale-report warning distinguish a disabled
collector, an unavailable source and an empty initial reporting period.

The dashboard does not mount the collector database. `analytics-export` atomically
writes `DATA_DIR/aggregate-analytics-report.json`, containing only suppressed weekly
counts for up to 57 completed weeks, collection status and a UTC update date. This
snapshot has mode 0640; the collector database remains 0600. The broker helper
`deploy/dashboard-analytics/aggregate_analytics_report.py` reads only this fixed
snapshot, bounds its size, validates the threshold and excludes current weeks. It
never opens a purchase database. No export endpoint or snapshot is publicly served.

For the production rootless container deployment:

- Copy the report helper into `/srv/infra/ops/` and the installed broker directory
  `/var/lib/pornfetch/.local/lib/eaf-dashboard/`; apply `dashboard-broker.patch` to
  `dashboard_broker.py` and install the resulting broker as `broker_server.py`.
  Check the patch against the current source before applying. Restart the broker
  after the report is generated and the dashboard update is ready.
- Install `deploy/dashboard-analytics/pornfetch-analytics.{service,timer}` into the
  `pornfetch` user's systemd directory. The exporter runs as container UID/GID
  1000. The production data volume already grants the host `pornfetch` user an
  inherited named-user ACL. The snapshot's 0640 mask permits read access through
  that ACL; the raw database's 0600 mask prevents it. Verify these effective
  permissions when deploying to a different volume; do not broaden raw DB access. Enable the
  timer and run the exporter service once. It replaces the standalone purge timer
  on this deployment, since export includes retention cleanup.
- Enable `AGGREGATE_ANALYTICS_ENABLED=true` in the web Quadlet and restart the web
  service. Install the collector route in the actual generated Caddy configuration,
  preserving its global transport configuration and the other services. Adapt the
  example's upstream to this deployment's `127.0.0.1:18080`; dashboard is `18010`.
  Retire the product host's old visit endpoint and validate Caddy before reloading.
- Deploy the dashboard commit using the existing `pfctl deploy dashboard REF`
  pipeline, which tests the candidate image, creates a coordinated backup and
  performs health verification. Deploy the web commit through the same pipeline.
- Verify dashboard unauthenticated requests return 401, raw counters remain 0600,
  the broker can read only the suppressed export, and no synthetic test events
  remain in production counters. Newly enabled collection has no historical events;
  completed-week results may initially be empty.

Source changes to other dashboard/infra features already present on the server
must be preserved. The patch and helper are versioned here so this integration can
be reproduced without committing unrelated infrastructure edits.
