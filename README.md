# Porn Fetch Server

> [!CAUTION]
> This repository is almost 100% AI-generated. Guys, if I were to do all this myself too,
> I would probably run out of time in my life before publishing my first app. Going to school, writing the final exams,
> while running a commercial site and doing fun side projects isn't possible without AI.

This repository contains the Flask service behind Porn Fetch and several related project pages. It serves release metadata and documentation, handles license purchases and signed license files, receives NOWPayments and Patreon webhooks, exposes a small CI status API, and maintains a public development checklist.

For a human-readable explanation of the refactor, its design decisions, and the new request flows, see [REFACTORING_GUIDE.md](REFACTORING_GUIDE.md). The provider-document audit, hardened retry rules, and privacy-safe logging design are documented in [docs/WEBHOOK_AND_LOGGING_HARDENING.md](docs/WEBHOOK_AND_LOGGING_HARDENING.md); canonical provider snapshots are in [docs/provider_api/](docs/provider_api/). The tax-country evidence design, sanctions-policy limitations, and official legal sources are collected in [docs/CHECKOUT_COUNTRY_COMPLIANCE.md](docs/CHECKOUT_COUNTRY_COMPLIANCE.md).

Production addresses:

- Product website: <https://pornfetch.to>
- Personal website: <https://echteralsfake.me>
- Documentation: <https://docs.echteralsfake.me>
- Payment webhooks: <https://api.echteralsfake.me>
- Onion service: <http://i3vtbgg6dufszjzbccyzd3wk4v2on3k6ljzjpg2ppzapgqmjmsxlvkid.onion/>

For payment creation only, middleware temporarily uses the client address supplied by the trusted, local TLS-terminating reverse proxy for a local country check. It then removes that address, `REMOTE_ADDR`, and common forwarding headers before Flask and its extensions see the request. Other requests are stripped without a lookup. Keep VPS, reverse-proxy, and process-manager access logs disabled if the deployment must retain this no-IP-log property.

## Quick start

The project requires Python 3.14 or newer and uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
uv venv --python 3.14
uv pip install --python .venv/bin/python --upgrade -r pyproject.toml
cp deploy/server.env.example .env
.venv/bin/python -m flask --app main db upgrade
.venv/bin/python main.py
```

The development server listens on `127.0.0.1:8000`. At minimum, set `SECRET_KEY`, `CHECKLIST_AUTH`, and the Keygen settings in `.env` before exercising authenticated or license-related flows.

Run the automated checks with:

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q main.py pf_server docs/build.py api_tests.py
```

Rebuild the generated API documentation with:

```bash
.venv/bin/python docs/build.py
```

The documentation builder replaces `docs/dist/`; edit `docs/content/`, `docs/template.html`, or `docs/index_template.html`, not generated pages directly.

## Repository layout

```text
main.py                     Application factory and deployment entry point
pf_server/extensions.py     Unbound Flask extension instances
pf_server/config.py         Validated environment configuration loader
pf_server/countries.py      Static checkout country names and ISO codes
pf_server/country_service.py Local country lookup and checkout policy middleware
pf_server/models.py         SQLAlchemy models shared with Alembic
pf_server/page_routes.py    Public-page Blueprint and access gate
pf_server/docs_routes.py    Generated-documentation Blueprint
pf_server/ci_routes.py      CI status API and badge Blueprint
pf_server/checklist_routes.py Checklist display and editing Blueprint
pf_server/update_routes.py  Release metadata and Sparkle update Blueprint
pf_server/operations_routes.py Health, statistics, and administration Blueprint
pf_server/payment_routes.py Purchase, license, invoice, and webhook Blueprint
pf_server/licensing.py      License signing, email validation, and SMTP service
pf_server/patreon_service.py Patreon eligibility and idempotent delivery service
pf_server/nowpayments_service.py Payment-provider and completion service
pf_server/invoice_service.py Atomic invoice storage and PDF rendering service
pf_server/time_utils.py     Shared RFC 3339 timestamp formatting
pf_server/webhook_models.py Strict, framework-independent webhook payload models
pf_server/logging_config.py Privacy-safe logging, redaction, and correlation
pf_server/tax_service.py    Privacy-minimizing country transaction summary
migrations/                 Versioned Alembic database migrations
templates/                  Jinja pages
static/                     Website styles and static files
i18n/                       License-delivery email catalogs
docs/content/               API documentation source fragments
docs/dist/                  Generated documentation served by Flask
docs/build.py               Static documentation builder
tests/_support.py           Shared isolated application and database fixture
tests/test_application.py   Public pages, CI, updates, and operations tests
tests/test_config.py        Environment parsing and fail-fast validation tests
tests/test_patreon.py       Patreon eligibility and delivery tests
tests/test_payments.py      NOWPayments, invoice, and license tests
tests/test_country_compliance.py Country evidence, restriction, and summary tests
geoip/README.md             Local DB-IP installation and licensing notes
scripts/update_geoip_database.py Explicit local-database updater
api_tests.py                Manual/local checks for external scraper APIs
```

`create_app()` assembles isolated Flask instances from unbound extensions and grouped Blueprints. The module-level `main:app` remains available for the existing Gunicorn deployment. HTTP handlers live in feature Blueprints, while payment-provider calls, invoice persistence, license signing, and Patreon delivery are separated into service modules.

## Database migrations

Database schemas are managed by Flask-Migrate/Alembic. Startup no longer calls `db.create_all()`, so apply migrations before starting a new deployment:

```bash
.venv/bin/python -m flask --app main db upgrade
.venv/bin/python -m flask --app main db current
```

The initial migration describes only the current schema and is intended for a fresh database. If you created a test database with an earlier schema, move it aside and run `db upgrade` against a new database instead of trying to adopt it.

For a model change:

```bash
.venv/bin/python -m flask --app main db migrate -m "Describe the schema change"
.venv/bin/python -m flask --app main db upgrade
.venv/bin/python -m flask --app main db check
```

Always review an autogenerated revision before applying it. Commit the model change and migration together. The baseline downgrade removes the complete application schema and is destructive.

## Configuration

Configuration is read and validated centrally by `pf_server/config.py`; `python-dotenv` loads a local `.env` automatically. Invalid origins, SMTP ports, and incomplete production payment credentials fail fast during startup. See `.env.example` for a copyable template.

| Variable | Purpose | Default |
| --- | --- | --- |
| `SECRET_KEY` | Signs Flask sessions and CSRF tokens | Persisted locally in `.flask_secret` |
| `PF_SERVER_DATA_DIR` | Database, secret, and invoice directory | Repository root |
| `PF_SERVER_DB` | SQLite database path override | `$PF_SERVER_DATA_DIR/server.db` |
| `CHECKLIST_AUTH` | Password for the checklist editor | Unset; checklist editing is unavailable |
| `CI_TOKEN` | Authorizes `POST /ci/<test_name>` | Unset; CI writes fail closed |
| `KILL_TOKEN` | Authorizes the local poweroff endpoint | Unset; endpoint is unavailable |
| `RATELIMIT_STORAGE_URI` | Flask-Limiter storage backend | `memory://` (per process) |
| `LOG_LEVEL` | Application warning/error verbosity | `INFO` |
| `CHECKOUT_IP_HEADER` | Trusted checkout client-address header; only `X-Forwarded-For` or empty is accepted | `X-Forwarded-For` |
| `GEOIP_DATABASE_PATH` | Local DB-IP City Lite MMDB path | `$PF_SERVER_DATA_DIR/geoip/dbip-city-lite.mmdb` |
| `GEOIP_DATABASE_LABEL` | Optional retained release/source label | Derived from MMDB build date |
| `GITHUB_TOKEN` | Raises the GitHub release API rate limit | Unset |
| `LICENSE_PRIVATE_KEY_B64` | Base64-encoded raw 32-byte Ed25519 private key | Unset |
| `SEO_INDEXING_ENABLED` | Index public product pages and guides; disable on staging independently of payments | `true` |
| `APP_DOMAIN` | Canonical product origin used for links and payment redirects | `https://pornfetch.to` |
| `API_DOMAIN` | Public origin dedicated to payment webhooks | `https://api.echteralsfake.me` |
| `NOWPAYMENTS_SANDBOX` | Uses the sandbox API and enables local payment simulation | `true` |
| `NOWPAYMENTS_API_KEY` | Creates NOWPayments invoices/payments | Unset |
| `NOWPAYMENTS_IPN_SECRET` | Verifies NOWPayments callbacks | Unset |
| `PATREON_SECRET` | Verifies Patreon callback signatures | Unset |
| `PATREON_LICENSE_TIER_IDS` | Optional comma-separated eligible tier IDs | All paid entitled tiers |
| `LICENSE_SMTP_*` | SMTP host, port, credentials, sender, TLS, and SSL settings | See `.env.example` |
| `LICENSE_MAIL_PROVIDER_NAME` | Public name of the outgoing mail provider | Unset |

For local license testing, configure a Keygen product token and policy ID:

```text
KEYGEN_INTERNAL_URL=http://127.0.0.1:8004
KEYGEN_PRODUCT_TOKEN=...
KEYGEN_POLICY_ID=...
```

The product token is a server-side credential and must not be shipped with the application. The public verification configuration is safe to ship with the application.

## HTTP surface

Public pages include `/porn_fetch`, `/donation`, `/stats`, `/impress`, `/terms`, `/refund_policy`, `/privacy_policy`, `/datenschutz`, and `/legal-statement`. `/` serves the v3.9 marketing homepage, with the official logo, product tour, screenshots, platform requirements and website capability table. Product information, downloads, About and setup/help pages are public. Purchase and donation entry pages retain the age-confirmation dialog and secure browser-session cookie. Confirmation reveals the page in place; the CSRF-protected HTML form also works without JavaScript. `/porn_fetch` and checkout entry pages use the same confirmation state; legal documents remain readable before confirmation. `/leave` clears confirmation and displays a neutral exit page. `/download` uses a local release catalog and platform cards, with direct files served by Caddy and local guides, release history, About and help. It does not contact GitHub. See [website distribution and SEO operations](docs/WEBSITE_DOWNLOADS.md). This does not require `CHECKLIST_AUTH`; the old `/access` URL redirects to `/`. Checklist editing has its own login. On the commercial host, `/robots.txt` and `/sitemap.xml` expose the product, download guides, About/help and published release notes when `SEO_INDEXING_ENABLED=true` (the default), independently of payment sandbox mode. Canonical URLs use `APP_DOMAIN` (default `https://pornfetch.to`). Set `SEO_INDEXING_ENABLED=false` on staging to send `noindex` and disable the sitemap. Public guides at `/guides` cover all 15 supported app websites; purchase and private flows remain unindexed. See [SEO research and launch operations](docs/SEO.md) for source checks, rollout, and Search Console setup.

The commercial host returns a plain 403 page when the request's `Referer` has the exact HTTPS origin `vplan.echteralsfake.me`. It sets a host-only, secure, HTTP-only browser marker signed by a random key held only in the current app process. The marker stays effective while the process runs and the browser retains the cookie; a restart invalidates it. The `/docs/` and `/dashboard/` routes and non-commercial hosts are excluded. The VPlan Caddy host overrides its upstream `no-referrer` policy with `strict-origin` so normal HTTPS navigation supplies the source origin without revealing the plan path. This mechanism depends on a browser sending the `Referer` header and retaining its cookie; it cannot identify someone who suppresses either signal. The deployed Gunicorn service uses one worker; multiple workers would need shared signing state.

The main API groups are:

- Releases: `GET /update` and `GET /appcast.xml`
- Licenses and payments: `GET /buy_license`, `POST /create-crypto-payment`, `GET /check-payment-status`, `GET /download_license`, `GET /download_invoice`, and `POST /check_license`. Patreon license delivery uses the webhook endpoint. Sandbox crypto checkout requires `test_acknowledged: true` in addition to terms acceptance.
- Webhooks: `POST /nowpayments-ipn` and `POST /patreon-webhook`
- CI: `POST /ci/<test_name>`, `GET /ci/<test_name>`, `GET /ci/<test_name>.json`, and `GET /ci/<test_name>/badge.svg`
- Checklist: `/checklist`, `/checklist/login`, `/checklist/api/*`, and `/checklist/progress.svg`
- Documentation: `/docs/` on the main origin or `/` on a `docs.*` host
- Operations: `GET /ping` and `POST /killswitch`

## Public MCP documentation

The generated Markdown corpus in `docs/mcp-docs/` is published without authentication at
`https://mcp.echteralsfake.me/mcp` using stateless MCP Streamable HTTP. The separate,
read-only service exposes every Markdown document as an `eaf-docs:///...` resource and provides
three bounded tools: `list_documentation`, `read_documentation`, and `search_documentation`.
It cannot modify packages, application data, or external systems. Its implementation and tests
live in `mcp_service/`; deployment commands are documented in `deploy/OPERATIONS.md`.

`POST /simulate-payment-success` exists only while `NOWPAYMENTS_SANDBOX=true`; production returns 404.

Both payment-creation endpoints require a JSON `country` containing an ISO
alpha-2 code from the checkout list. The customer selection must agree with
the local IP-country evidence before a provider transaction is created.

Both payment webhook routes require the hostname configured by `API_DOMAIN`. Configure the tunnel/DNS route for that host to reach this Flask service, then use:

- NOWPayments IPN: `https://api.echteralsfake.me/nowpayments-ipn`
- Patreon webhook: `https://api.echteralsfake.me/patreon-webhook`

Subscribe Patreon to `members:create`, `members:update`, `members:pledge:create`, and `members:pledge:update`. The update events allow delivery when an initially pending charge later becomes paid or an eligible pledge changes. Delivery is idempotent per Patreon member and retries reuse the same license.

## Production deployment

The installed systemd deployment, current-dependency updates without uv lockfiles,
private configuration, backups and rollback are described in [deploy/OPERATIONS.md](deploy/OPERATIONS.md).

A minimal Gunicorn launch is:

```bash
.venv/bin/python -m gunicorn --bind 127.0.0.1:8000 main:app
```

After installing a release, run the migration and runtime initialization once before restarting Gunicorn:

```bash
.venv/bin/python -m flask --app main db upgrade
.venv/bin/python -m flask --app main init-runtime
```

The intended topology is **Privex VPS (Sweden) → WireGuard tunnel → Acer Swift 3 or Google Pixel 7 Pro (Germany) → TLS-terminating reverse proxy → this loopback listener**. The VPS forwards the still-encrypted connection through WireGuard; TLS is terminated only on the German endpoint after the tunnel. The transport must preserve the original visitor address, using routed forwarding or an authenticated PROXY-protocol hop inside WireGuard. The local reverse proxy must discard any inbound `X-Forwarded-For` value and set exactly one value from that trusted source address. `ProxyFix` trusts one forwarded scheme/host/prefix hop but intentionally trusts no forwarded client address; checkout middleware reads and then removes the separate address header. Keep Gunicorn reachable only from the trusted local proxy, and do not enable VPS, WireGuard, reverse-proxy, or Gunicorn logging that records visitor IPs if operating under the stated zero-log policy.

Before enabling live payments (sandbox mode may intentionally remain enabled during testing):

1. Review `geoip/README.md`, install the local database over an appropriate connection, and restart all workers. Checkout fails closed with `503` while it is absent.
2. Set `NOWPAYMENTS_SANDBOX=false` and configure both NOWPayments secrets.
3. Route `API_DOMAIN` to this service and verify webhook hostname isolation.
4. Configure the Patreon secret and SMTP delivery settings.
5. Keep the reviewed German and English email catalogs accurate; production preflight rejects catalogs whose `reviewed` flag is not true.
6. Set `LICENSE_MAIL_PROVIDER_NAME` so both privacy-policy templates identify the outgoing mail provider, and verify its data handling.
7. Obtain professional review of the tax-evidence and geographic policy documented in `docs/CHECKOUT_COUNTRY_COMPLIANCE.md`.
8. Back up `server.db`, the invoice directory, the signing key, and the Flask secret.

Flask-Limiter currently uses its in-memory backend, so limits are enforced per process. Configure a shared supported backend before scaling to multiple workers if globally consistent rate limits are required.

## Operational notes

- Alembic owns the managed SQLite schema. Importing the application does not query or mutate the database.
- `flask --app main init-runtime` explicitly resets aggregate request/traffic counters and their start timestamp; run it once per deployment, not once per Gunicorn worker.
- The payment schema retains the session/provider identifiers, expected amount/currency values needed to validate callbacks, selected country, evidence method, database label, processing state/lease, and timestamps. IP addresses and subdivisions are not retained. Required crypto/card email addresses are stored encrypted locally and passed to Proton Mail for delivery, not to NOWPayments or Keygen.
- `flask --app main tax-country-summary --year YYYY` prints country/currency totals for completed transactions without transaction identifiers. Combine it with all other sales channels and professional tax advice.
- NOWPayments fulfills only `finished` callbacks that match the stored provider reference, original fiat price/currency, and—where known—the expected crypto asset and paid amount. Unknown or busy orders return retryable `503` responses; permanent mismatches are acknowledged without fulfillment.
- Application warnings and exceptions use a privacy-safe formatter. Never log webhook bodies or user identifiers, and keep Gunicorn/proxy/platform access logs disabled under the no-user-data policy.
- GitHub release metadata is cached for five minutes. A failed refresh uses stale cached data when available and otherwise returns an unavailable response instead of crashing `/update`.
- Invoice JSON and the SQLite database contain purchase data. Restrict filesystem permissions and include them in the privacy/data-retention review.
- The kill switch invokes the host `poweroff` command asynchronously and should only be exposed behind strong network controls in addition to `KILL_TOKEN`.

## Tests

The feature-focused regression suites share an isolated fixture and cover configuration validation, webhook signature ordering and schemas, Patreon eligibility, stale leases and idempotent delivery, payment callback isolation, local country matching and header removal, geographic policy failures, tax aggregation, atomic invoice generation, license reuse, documentation path containment, RFC 3339 timestamps, release-API failure and malformed-metadata behavior, operational authentication and counters, privacy pages, and translation-catalog consistency. The suite does not download the real GeoIP database.

When changing payment or authentication code, add a regression test before deployment. External scraper smoke tests in `api_tests.py` require network access and are intentionally separate from the deterministic unit suite.

## License

See [LICENSE](LICENSE).

## Keygen licensing

Licenses now use self-hosted Keygen CE, schema-2 signed keys, ten UUID installation slots,
and seven-day offline permits. See [application integration](docs/KEYGEN_CLIENT_INTEGRATION.md)
and [operations](deploy/keygen/OPERATIONS.md). The reusable package is `license_client/`.
New licenses cover Premium features in releases published within one year of first activation, with continued Premium access in eligible builds and no automatic license renewal. App updates and desktop history/statistics are free. Free use supports up to 720p, one active download and the first five videos of each public profile, model, channel or playlist; account collections are exempt from that preview. Premium enables qualities above 720p, parallel downloads and full public collections. New Banxa purchases use this same offer; historical beta orders retain their original terms. Patreon memberships still recur until the customer cancels them.

The purchase service no longer holds an Ed25519 private key. Configure `KEYGEN_PRODUCT_TOKEN`
and `KEYGEN_POLICY_ID` before enabling fulfillment. The old `/check_license` route returns 410.

Commercial MSI licensing uses a perpetual fallback with one calendar year of Premium
release coverage from first activation. Renewal checkout accepts `renewal_license_key` in the existing
`POST /create-crypto-payment` JSON body; the server proves key possession and binds
the resulting license UUID before payment. Verified renewal callbacks preserve the
key, with atomic deduplication in Keygen and a durable provider-charge binding locally.
NOWPayments remains sandboxed. Patreon requires explicit `PATREON_PAYMENTS_ENABLED=true`
and a configured qualifying tier (minimum 1999 cents); it is disabled on MSI. Its
`renew_verified_patreon_charge` adapter is internal, for a provider-verified annual
renewal charge, and is deliberately not invoked by repeat membership updates.
Desktop builds must supply their immutable `build_release_date` to `LicenseClient`.

## Website presentation and verification

Shared presentation lives in `templates/base.html`, `static/site.css` and `static/site.js`; existing transactional styles and payment logic are retained. Impressum, privacy and terms display full English sections followed by German sections, with language anchors. `/datenschutz` redirects to `/privacy_policy#de`. Bilingual document bodies live in `templates/partials/`. The privacy policy describes the necessary session cookie.

The original 40-second HEVC promo and its Remotion source remain in `porn-fetch-promo/`. The website serves a compatible H.264 MP4 and poster from `static/media/`; video playback waits for age confirmation, pauses offscreen and respects reduced motion. Assets are local. To regenerate the website video after updating the original:

```bash
ffmpeg -i porn-fetch-promo/out/MyComp.mp4 -c:v libx264 -preset medium -crf 21 -pix_fmt yuv420p -movflags +faststart -an static/media/porn-fetch-promo.mp4
ffmpeg -ss 3 -i porn-fetch-promo/out/MyComp.mp4 -frames:v 1 -q:v 3 static/media/promo-poster.jpg
```

Run the isolated HTTPS browser checks without live provider requests or payments:

```bash
uv run --with playwright python scripts/test_marketing_browser.py
```

The script uses a temporary test database, exercises desktop/mobile layouts, session confirmation, the no-JavaScript fallback, legal anchors, reduced motion and actual video playback, then shuts down its local server. Screenshots are written to `/tmp/porn-fetch-*.png`. It requires Playwright Chromium (`uv run --with playwright python -m playwright install chromium`); pass `--browser firefox` or `--browser webkit` to check other installed browsers. The capability inventory in `pf_server/product_catalog.py` mirrors the app's `docs/WEBSITES.md`; update both when support changes.

The payment selector uses three compact, unselected choices with a recommended crypto
option. Only the selected method’s detail panel is shown with JavaScript; no-JavaScript
visitors get explicit checkout links. All three methods can be selected for preview.
Patreon and card actions require an explicit no-payment acknowledgment before
continuing. Real card link creation still follows the existing configuration gates.
Patreon remains setup-pending until its license tier is ready; repeated
Patreon purchases and customer renewal workflows are separate work.

The app source link and GitHub icon are local presentation assets; attribution and
the icon license are served at `/static/notices/github-octicons.txt`. The app remains
source-available under its custom license; the server/payment implementation is GPL.
Android v3.9 GUI support is listed independently of published build availability.

Before enabling annual purchases, verify the configured Keygen policy against the
client’s public configuration using `flask --app main verify-license-policy --client-config /path/to/production.json`.
See `deploy/keygen/OPERATIONS.md` for annual policy provisioning and historical-policy
preservation. This command only reads the policy; no running service was changed.

## Payment identity and preview testing

The payment selector displays locally served owner-supplied Patreon, NOWPayments,
Google Pay, Apple Pay and cryptocurrency artwork. Provenance, attribution and usage
sources are recorded at `/static/notices/payment-brands.txt`. Visa/Mastercard remain
text references until merchant acceptance/brand permissions are established; attribution
alone is not sufficient for their acceptance marks. The 350+ cryptocurrency statement
refers to NOWPayments' overall advertised catalog, not every individual checkout.

`/payment-preview/patreon` opens the project profile after confirmation.
`/payment-preview/card` continues to the inspectable card form, and
`/payment-preview/banxa?session_id=...` opens only the stored link of an existing,
ready, unpaid Onramp order after confirmation. These routes do not create payments.
The existing NOWPayments deposit → Onramp Pay wallet → Banxa route is retained;
there is no direct Banxa integration. No API keys or live settings are enabled by
this change. The card form can be inspected without credentials, but generating a
valid external link requires the documented merchant configuration.

Preview warnings explicitly say not to send money, subscribe, enter payment details
or submit real identity documents. They do not falsely label live provider pages as
sandboxes. A local launch page performs external navigation after acknowledged POSTs
so the site's same-origin `form-action` CSP remains intact. Without JavaScript, the
same server-rendered warning and an explicit provider link remain available.


NOWPayments final receipts are acknowledged after durable database persistence.
Run `flask --app main:app process-nowpayments-receipts` every 15 seconds and apply
migrations before starting the updated web service. Keygen and SMTP run outside
the webhook request; email outboxes retain their independent retry schedules.
See [checkout operations](docs/ONRAMP_CHECKOUT.md#durable-receipt-worker-and-deployment).

For a real provider sandbox test, use `NOWPAYMENTS_SANDBOX=true` and
`NOWPAYMENTS_LOCAL_SIMULATION_ENABLED=false`. Local fallback is opt-in and startup
rejects it in production. The operator command
`flask --app main:app request-sandbox-payment --order-id NP-...` asks the provider
to emulate a success for an existing sandbox invoice; only the signed webhook can
authorize fulfillment. NOWPayments' current sandbox documentation warns that it
has not been actively maintained since 2025 and does not guarantee production
compatibility. The infrastructure runbook documents credential setup and cutover.

License emails contain English-first HTML and plain-text alternatives. Crypto/card
orders attach their existing PDF invoice alongside the signed license file.
Sandbox messages and invoice PDFs are labelled as tests. Patreon delivery keeps
using its provider receipt rather than inventing a local purchase invoice.

### Required email and retained order contact

New direct NOWPayments and Banxa/Onramp checkouts require a valid delivery email.
The server validates it before creating the checkout. `Transaction.customer_email_encrypted`
keeps the encrypted address as a later purchase/support reference, separate from
short-lived delivery queues. Successful delivery and the existing seven-day outbox
cleanup do not erase this order reference. The address is never included in signed
license files, Keygen requests, public status responses or NOWPayments requests.
Patreon continues using its existing webhook email flow.

Run the database migration before starting the updated application:
`uv run flask --app main db upgrade` (latest revision `c482e16d09a2`, including `ae902bd71c40` and `bf371c20a913`). Existing orders
remain nullable and are not backfilled from addresses collected under the previous
retention notice. Keep `LICENSE_DELIVERY_ENCRYPTION_KEY` (or the existing fallback
`ONRAMP_ENCRYPTION_KEY`) available for as long as retained references need to be read;
changing keys requires explicit re-encryption. Both payment paths use this key
selection for order references, independently of Banxa's outbox encryption.

Review retained order addresses manually and clear references once they are no
longer needed for contractual processing/support or applicable legal obligations.
This includes abandoned checkouts and backup copies; there is no automatic purge
of the new field. Do not infer retention requirements from invoice retention alone.
The separate contract-confirmation and electronic-withdrawal workflows are described
below and in `docs/LEGAL_REVIEW_2026-10-31.md`.

### Checkout evidence and durable confirmations

New crypto and Banxa orders require a current, server-stored checkout agreement.
The agreement records the exact bilingual terms, product information, withdrawal
instructions and immediate-supply declarations, version and acceptance time, without
an IP address. The order stores its own copy; changing templates later cannot rewrite it.
The delivery message attaches the original confirmation PDF, license and invoice.
The same PDF is also available through the private recovery page while access is valid.
Historical orders have no fabricated agreement or confirmation added.

Patreon sends a license benefit confirmation only: no inferred withdrawal waiver,
no invented membership price or invoice. Patreon supplies the membership confirmation.
The member's email is now encrypted in its outbox until successful SMTP handover;
the original benefit PDF remains stored. A successful SMTP handover is not proof of
receipt. Retries reuse the document and Message-ID; SMTP cannot guarantee exactly-once delivery.

Deployment requires migration `bf371c20a913`, a stable `LICENSE_DELIVERY_ENCRYPTION_KEY`
(or `ONRAMP_ENCRYPTION_KEY` fallback, including Patreon-only deployments), and working
Proton Mail SMTP configuration. Enable both existing minute timers:
`eaf-crypto-deliveries.timer` (now also Patreon and expired checkout-agreement cleanup)
and `eaf-onramp-deliveries.timer`. Monitor failed queues and mail bounces; repeated
SMTP failures require operator action and must not be treated as fulfilled confirmations.

New paid orders with outstanding confirmations continue retrying beyond seven days.
Unpaid/legacy delivery addresses and Banxa tracking secrets still expire after seven days;
a subsequently verified new payment can restore its delivery address from the retained
order reference. Successful delivery removes the outbox copy. Unbound checkout agreements
expire for browser use after one hour and are purged by the crypto timer after one day.
Review and delete order-linked evidence/PDFs manually when contractual and legal retention
purposes end. Apply deletion to stored order contacts, outboxes, PDFs and backups as appropriate.

The public `/withdrawal` page now implements the electronic withdrawal function under
§ 356a BGB as described below, alongside bilingual instructions and the model form.

### Electronic withdrawals

`/withdrawal` is publicly linked as **Vertrag widerrufen / Withdraw from contract**
outside the collapsible navigation and in the age gate. The first form collects name,
contract/partial-contract identification and receipt email. A second page displays the
exact declaration and has the separate **Widerruf bestätigen / Confirm withdrawal**
button. It works without JavaScript, login, order-number validation or an unexpired
purchase link. There is no age/checkout gate or automated 14-day rejection.
The existing school-referral block also permits the withdrawal flow and its privacy/provider notices.
On the read-only onion mirror, the link opens the configured HTTPS website.

Final confirmation commits the declaration, original UTC receipt time and immutable
bilingual receipt before attempting mail. Names, email and declaration/receipt contents
are encrypted with the existing stable delivery key; drafts are encrypted hidden form
values, not plaintext cookies or URL parameters. Replaying the same confirmation reuses
the receipt. The receipt is emailed as text and a UTF-8 text attachment, with a private
POST download on the acknowledgment page. The token grants access: do not log or share it.
A separate email to `support@echteralsfake.me` notifies the operator. Both deliveries
have independent leases and retry states, so an operator notification failure does not
resend an already-sent consumer receipt. SMTP failure never withdraws the received declaration.

Before serving this version, run `uv run flask --app main db upgrade` to revision
`c482e16d09a2`, keep the existing encryption key available, configure Proton Mail SMTP,
and install/enable `deploy/eaf-withdrawals.service` and `deploy/eaf-withdrawals.timer`.
The timer runs `retry-withdrawal-deliveries` every minute, independently of payment timers.
No emails are sent by the migration. Monitor pending/failed deliveries and bounced emails;
a successful SMTP handover does not prove receipt, and SMTP retries may duplicate a message
if a process crashes after handover but before recording success.

Local operator commands (run under the service environment):

- `uv run flask --app main list-withdrawals`: pending manual reviews with reference,
  receipt time and delivery state; no names/emails. `--all-records` includes reviewed entries.
- `uv run flask --app main show-withdrawal --reference WR-...`: decrypt the complete
  declaration for processing. Its output is personal data; do not copy it into logs.
- `uv run flask --app main mark-withdrawal-reviewed --reference WR-...`: record completed
  manual review. This does not refund payments, cancel Patreon membership or revoke a license.

Match the contract, determine the applicable rights and arrange any required reimbursement
manually; receipt of a declaration is not automatic approval or rejection of the claim.
Review retention after processing, including legal evidence/retention periods. When lawful,
remove both `withdrawal_deliveries` entries and their `withdrawal_requests` row and account
for correspondence and backups. These records are not purged by the seven-day checkout job.

### Separate cryptocurrency refund agreement (2026-11-01)

All three website checkout routes now require the separate, unchecked
`refund_method_accepted` confirmation. `checkout-v3` invalidates earlier browser
confirmations; `contract-2026-11-01-v3` includes the exact bilingual declaration and
refund agreement. New crypto and Banxa orders retain that evidence in their existing
snapshot and confirmation PDF. Older orders/PDFs acquire no retrospective consent.
No additional migration is introduced by this change.

`/checkout/agreement` provides a session-protected, no-store PDF receipt while the
one-hour checkout confirmation remains valid. Links are shown in crypto/card checkout
and both Patreon preview variants. The receipt is not a purchase or identity proof.
Unbound evidence still expires after one day through the existing cleanup timer.

Patreon webhooks cannot correlate website consent to a member. Do not infer consent
from a webhook, membership or an unverified receipt. Direct Patreon purchases can
bypass the website. Without attributable evidence, obtain an individual agreement
before using a different refund method. This limitation is also stated in Patreon
license benefit confirmations. No Patreon OAuth integration is introduced.

Refunds remain manual: use Patreon to refund its original payment method within 90
days of each original charge; afterward use cryptocurrency only under an applicable
agreement. Match existing refunds/disputes before paying again. Agree currency, network,
recipient address and any conversion quote, preserve the full amount legally owed,
and cover necessary refund costs. If a timely cost-free alternative cannot be arranged,
statutory repayment remains due; do not extend legal deadlines or treat 90 days as a
claims cutoff. See the dated legal-review supplement for scope, sources and open issues.

### Patreon Shop email activation

`/activate` accepts only a purchase email and never exposes a license in the browser.
This is independent of membership webhooks. One eligible Shop order receives one
normal annual Keygen license; repeated claims resend it, and another order gets a
new license. Technical Patreon failures grant a normal fallback license, once per
email; confirmed missing/ineligible purchases do not. This deliberately permits
unverified claims during outages. Shared IP limits and mailbox cooldowns reduce abuse.

Setup, cookie rotation, failure handling and retention are documented in
[Patreon Shop operations](docs/PATREON_SHOP.md). Activation defaults to disabled.
