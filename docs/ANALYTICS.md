# Private aggregate website analytics

The collector measures events, not visitors. It stores no visitor identifier,
individual event row, raw IP, cookie, referrer, URL parameter, email, order ID,
fingerprint or journey. It does not join the purchase database. Guide layout,
Premium price and licensing entitlements are unchanged by this work.

## Events and their purpose

- `pageview`: displays on fixed allowlisted public product pages.
- `pageview_mobile`, `pageview_tablet`, `pageview_desktop`: approximate viewport
  groups (<768, <1024 and >=1024 CSS pixels); these are not identified devices.
- Existing download, platform, help and Premium actions are retained.
- `visible_download_*`, `visible_premium_*`: a link was at least 50% visible.
  Each kind/placement counts once per page load, even if several links qualify.
- `click_download_*`, `click_premium_*`: clicks by fixed placement: header,
  guide_top, guide_steps, comparison, content, footer. Multiple clicks can count.
  The comparison placement is ready for future `data-metric-section="comparison"`
  markup; this release does not redesign the guides or add that comparison.
- `download_click`: only explicitly marked package links, excluding checksums.
- `checkout_continue`: clicking the payment button, including invalid forms.
- `checkout_valid_METHOD_ENVIRONMENT`: recorded by the backend after checkout
  validation succeeds. These mean accepted initial checkout starts, not provider
  payment creation or completed payment. Crypto may still require its second
  confirmation. Production/sandbox and payment methods are separate. Browsers
  cannot submit these names to the event endpoint. Repeated valid submissions
  can count again, because no identity or deduplication key is retained.
- `feedback_price`, `feedback_information`, `feedback_payment`,
  `feedback_try_first`, `feedback_free_sufficient`: voluntary fixed choices on
  Premium. The UI accepts one answer per page load. Reloads and forged requests
  can repeat answers; this is not a representative or unique-person survey.

Daily country totals cover `pageview` events only, across the product site.
They are stored separately from page/action totals, never combined with device,
page, placement or survey answers. The existing trusted checkout-address resolver
uses the local MMDB in memory and strips address headers before Flask handles
requests. Unknown countries are omitted. Country is an estimate and can reflect
VPNs or gateways. There is no external geolocation call.

## Storage, access and reporting

`DATA_DIR/aggregate-analytics.sqlite3`, mode 0600, has two tables:

- `daily_counts(day, page, action, count)`
- `country_counts(day, country, count)`

No per-event timestamp is stored. Schema extension preserves existing daily
counters. Counters older than thirteen calendar months are purged on collection
and scheduled export. Old backups/snapshots require their own expiry policy.

`analytics-report --days 28` reports daily cells, including today, with a fixed
threshold of twenty events per cell. Missing rows are suppressed or absent, not
zero. It provides no total that reconstructs suppressed cells. `analytics-export`
atomically writes a mode-0640 `aggregate-analytics-report.json`, with daily rows,
separate countries, UTC generation time, collection status and incomplete-today
label. The export covers ninety days; older retained counters remain in storage.
The dashboard broker reads this snapshot, not the raw database. There is no
public analytics reporting endpoint. Existing dashboard authentication protects
its report API; the API uses no-store for the new daily requests.

The dashboard supports 7/28/90-day windows, polls every sixty seconds while the
analytics view is visible, preserves the page/action search and period selection,
and marks snapshots older than three minutes as stale. The source exporter must
also run every minute. An old weekly export remains readable during rollout and
is explicitly labeled as such, rather than presented as current daily data.

Frequent authenticated snapshots permit differencing: after a cell becomes
reportable, comparing successive values can reveal a single additional event.
Small-count suppression is not differential privacy and does not guarantee
anonymity against outside knowledge. These are private operational aggregates,
not safe public data. Do not publish snapshots or raw counters.

Completed purchases and proceeds remain in the existing separate dashboard
Revenue view. That view's fee estimates must not be relabeled as actual receipts.
The existing local Patreon cache lacks actual paid amounts, fee breakdowns and
reliable refund accounting; obtain aggregate actual proceeds/refunds from Patreon
when assessing the experiment. No purchase-completion event is accepted from a
browser, and no browsing-to-purchase attribution is inferred.

## Request boundary and limitations

The client sends only fixed `{page, action}` values to `/_metrics/event`, with
credentials omitted and no referrer. DNT/GPC disable both client collection and
backend measurement; the optional feedback UI stays hidden. The endpoint checks
the exact product origin and host, rejects parameters, credentials, extra fields,
unknown labels and oversized bodies (256 bytes), and uses a global 6,000/minute
limiter without visitor-specific keys. Onion/docs/unlisted pages are excluded.
No session is needed for collector requests. Storage failures use a fixed log
message and do not block browsing or checkout.

Origin checks and rate limits do not authenticate a human. Bots can forge allowed
counters or pollute the survey. Script blockers, privacy signals, interrupted
navigation and independent requests can undercount activity. Counts cannot
establish unique users, installs, connected funnels or causal conversion rates.
The collector does not make the entire site anonymous: purchase records, necessary
session cookies and other infrastructure have separate purposes and policies.

## Local changes and production rollout

Website changes are prepared in this checkout only. The dashboard integration is
updated separately over SSH; no web-container deployment is part of this task.
Deploy through the normal reviewed website pipeline, then:

1. Deploy the collector Caddy route with the application. The local example is
   `deploy/pornfetch-site.caddy`; adapt the port to the actual deployment (18080
   on MSI). Retire the old product-host `/__eaf/visit*` collector with 410. The
   new route uses `log_skip`, caps the body and strips Cookie, Authorization,
   Referer and untrusted forwarding fields. It **replaces** X-Forwarded-For
   with Caddy's authenticated `{client_ip}` for local country resolution.
   The previously deployed metrics route stripped this header entirely: update
   that route if country totals are wanted. The narrow MSI source patch is
   `deploy/dashboard-analytics/caddy-country-header.patch`; verify it against the
   current configuration, render/validate using the existing infrastructure
   procedure, then reload only as part of your website rollout. Preserve
   PROXY-v2/TLS/ECH configuration.
   Verify CHECKOUT_IP_HEADER selects that trusted address header and that only
   the trusted proxy can reach the application.
2. Audit the actual proxy, Gunicorn, error and tracing configuration to ensure
   collector addresses, bodies and headers are not logged. The development
   request handler skips the endpoint; Gunicorn must keep access logs disabled.
   Source changes cannot prove all external infrastructure is configured safely.
3. Enable `AGGREGATE_ANALYTICS_ENABLED=true` after reviewing the disclosure and
   deployment's applicable legal basis. It defaults to false in new installations.
   Existing production enablement should be preserved. The EN/DE privacy text
   describes the collector; it does not declare all other services anonymous.
4. For MSI rootless deployment install
   `deploy/dashboard-analytics/pornfetch-analytics.{service,timer}` into the
   pornfetch user's systemd directory; daemon-reload, enable/start the timer,
   then start the exporter service. The timer runs every minute. The existing
   snapshot ACL must let the host broker read mode 0640 while keeping the raw
   database at 0600. The service runs export as container UID/GID 1000.
   Non-container deployments can schedule `.venv/bin/flask --app main
   analytics-export` every minute as the application user instead.
5. `deploy/dashboard-analytics/aggregate_analytics_report.py` must be installed
   alongside the host broker. Its `read_report(path, weeks=4, *, days=None)`
   interface supports legacy weekly snapshots and the validated daily format.
   The broker operation accepts `days` as well as legacy `weeks`.
6. Check the authenticated dashboard shows a fresh UTC snapshot, daily grain,
   today's incomplete label and eventual reportable rows. Check unauthenticated
   report requests fail. Do not inject synthetic events into production counters.

The new survey is keyboard-operable with ordinary buttons, visible focus styles,
a status message and focus preservation on completion. No tracking storage is
used to remember survey answers. Guide conversion/layout work remains separate.

## Validation

From this repository:

```sh
.venv/bin/python -m unittest discover -s tests -p test_aggregate_analytics.py -v
.venv/bin/python -m unittest discover -s tests -p test_analytics_dashboard_report.py -v
.venv/bin/python -m unittest discover -s tests -p test_analytics_browser.py -v
.venv/bin/python -m unittest discover -s tests -p test_country_compliance.py -v
.venv/bin/python -m unittest discover -s tests -p test_checkout_simplification.py -v
```

Browser tests intercept synthetic local data and never call production. Boundary
checks cover rejection of identifiers/forged backend events, DNT/GPC, country
separation, current-day suppression, exporter permissions, legacy snapshots,
staleness, cookie/referrer omission, visibility and survey behavior.

## Verification on 14 November 2026

The dashboard reader, minute timer and daily-ready UI were installed on MSI.
The broker successfully reads the existing weekly source and labels it legacy;
the production website code was not deployed. The timer was active and had a
successful minute export; raw counters remained 0600 and the snapshot 0640.
The report API returned 401 without authentication and dashboard health returned
200. Deployment candidate tests: 47 passed, one browser test skipped because the
candidate environment lacks Playwright. The dashboard browser scenario was also
run separately with local Chromium against intercepted synthetic data and passed,
including period/search preservation, minute polling, empty data and source errors.
Local Server validation covered 27 focused checks including its Chromium test.
