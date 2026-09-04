# Porn Fetch Server

> [!CAUTION]
> This repository is almost 100% AI-generated. Guys, if I were to do all this myself too,
> I would probably run out of time in my life before publishing my first app. Going to school, writing the final exams,
> while running a commercial site and doing fun side projects isn't possible without AI.

This repository contains the Flask service behind Porn Fetch and several related project pages. It serves release metadata and documentation, handles license purchases and signed license files, receives NOWPayments and Patreon webhooks, exposes a small CI status API, and maintains a public development checklist.

For a human-readable explanation of the refactor, its design decisions, and the new request flows, see [REFACTORING_GUIDE.md](REFACTORING_GUIDE.md). The provider-document audit, hardened retry rules, and privacy-safe logging design are documented in [docs/WEBHOOK_AND_LOGGING_HARDENING.md](docs/WEBHOOK_AND_LOGGING_HARDENING.md); canonical provider snapshots are in [docs/provider_api/](docs/provider_api/). The tax-country evidence design, sanctions-policy limitations, and official legal sources are collected in [docs/CHECKOUT_COUNTRY_COMPLIANCE.md](docs/CHECKOUT_COUNTRY_COMPLIANCE.md).

Production addresses:

- Website: <https://echteralsfake.me>
- Documentation: <https://docs.echteralsfake.me>
- Payment webhooks: <https://api.echteralsfake.me>
- Onion service: <http://i3vtbgg6dufszjzbccyzd3wk4v2on3k6ljzjpg2ppzapgqmjmsxlvkid.onion/>

For payment creation only, middleware temporarily uses the trusted Cloudflare client address for a local country check. It then removes that address, `REMOTE_ADDR`, and common forwarding headers before Flask and its extensions see the request. Other requests are stripped without a lookup. Keep reverse-proxy and process-manager access logs disabled if the deployment must retain this no-IP-log property.

## Quick start

The project requires Python 3.14 or newer and uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
uv sync
cp .env.example .env
uv run flask --app main db upgrade
uv run python main.py
```

The development server listens on `127.0.0.1:8000`. At minimum, set `SECRET_KEY`, `CHECKLIST_AUTH`, and `LICENSE_PRIVATE_KEY_B64` in `.env` before exercising authenticated or license-related flows.

Run the automated checks with:

```bash
uv run python -m unittest discover -s tests -v
uv run python -m compileall -q main.py pf_server docs/build.py api_tests.py
```

Rebuild the generated API documentation with:

```bash
uv run python docs/build.py
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
uv run flask --app main db upgrade
uv run flask --app main db current
```

The initial migration describes only the current schema and is intended for a fresh database. If you created a test database with an earlier schema, move it aside and run `db upgrade` against a new database instead of trying to adopt it.

For a model change:

```bash
uv run flask --app main db migrate -m "Describe the schema change"
uv run flask --app main db upgrade
uv run flask --app main db check
```

Always review an autogenerated revision before applying it. Commit the model change and migration together. The baseline downgrade removes the complete application schema and is destructive.

## Configuration

Configuration is read and validated centrally by `pf_server/config.py`; `python-dotenv` loads a local `.env` automatically. Invalid origins, SMTP ports, and incomplete production payment credentials fail fast during startup. See `.env.example` for a copyable template.

| Variable | Purpose | Default |
| --- | --- | --- |
| `SECRET_KEY` | Signs Flask sessions and CSRF tokens | Persisted locally in `.flask_secret` |
| `PF_SERVER_DATA_DIR` | Database, secret, and invoice directory | Repository root |
| `PF_SERVER_DB` | SQLite database path override | `$PF_SERVER_DATA_DIR/server.db` |
| `CHECKLIST_AUTH` | Password for the landing-page gate and checklist editor | Unset; landing page fails closed |
| `CI_TOKEN` | Authorizes `POST /ci/<test_name>` | Unset; CI writes fail closed |
| `KILL_TOKEN` | Authorizes the local poweroff endpoint | Unset; endpoint is unavailable |
| `RATELIMIT_STORAGE_URI` | Flask-Limiter storage backend | `memory://` (per process) |
| `LOG_LEVEL` | Application warning/error verbosity | `INFO` |
| `CHECKOUT_IP_HEADER` | Trusted checkout client-address header; only `CF-Connecting-IP` or empty is accepted | `CF-Connecting-IP` |
| `GEOIP_DATABASE_PATH` | Local DB-IP City Lite MMDB path | `$PF_SERVER_DATA_DIR/geoip/dbip-city-lite.mmdb` |
| `GEOIP_DATABASE_LABEL` | Optional retained release/source label | Derived from MMDB build date |
| `GITHUB_TOKEN` | Raises the GitHub release API rate limit | Unset |
| `LICENSE_PRIVATE_KEY_B64` | Base64-encoded raw 32-byte Ed25519 private key | Unset |
| `APP_DOMAIN` | Canonical public website origin used for payment redirects | `https://echteralsfake.me` |
| `API_DOMAIN` | Public origin dedicated to payment webhooks | `https://api.echteralsfake.me` |
| `NOWPAYMENTS_SANDBOX` | Uses the sandbox API and enables local payment simulation | `true` |
| `NOWPAYMENTS_API_KEY` | Creates NOWPayments invoices/payments | Unset |
| `NOWPAYMENTS_IPN_SECRET` | Verifies NOWPayments callbacks | Unset |
| `PATREON_SECRET` | Verifies Patreon callback signatures | Unset |
| `PATREON_LICENSE_TIER_IDS` | Optional comma-separated eligible tier IDs | All paid entitled tiers |
| `LICENSE_SMTP_*` | SMTP host, port, credentials, sender, TLS, and SSL settings | See `.env.example` |

Generate a development signing key with:

```bash
uv run python -c 'import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())'
```

Treat this value as a secret and keep the matching public key in the client. Replacing it invalidates the signature chain expected by clients.

## HTTP surface

Public pages include `/porn_fetch`, `/donation`, `/stats`, `/impress`, `/terms`, `/refund_policy`, `/privacy_policy`, `/datenschutz`, and `/legal-statement`. `/` is protected by the `CHECKLIST_AUTH` access gate; `/access` performs the login.

The main API groups are:

- Releases: `GET /update` and `GET /appcast.xml`
- Licenses and payments: `GET /buy_license`, `POST /create-crypto-payment`, `POST /create-fiat-payment`, `GET /check-payment-status`, `GET /download_license`, `GET /download_invoice`, and `POST /check_license`
- Webhooks: `POST /nowpayments-ipn` and `POST /patreon-webhook`
- CI: `POST /ci/<test_name>`, `GET /ci/<test_name>`, `GET /ci/<test_name>.json`, and `GET /ci/<test_name>/badge.svg`
- Checklist: `/checklist`, `/checklist/login`, `/checklist/api/*`, and `/checklist/progress.svg`
- Documentation: `/docs/` on the main origin or `/` on a `docs.*` host
- Operations: `GET /ping` and `POST /killswitch`

`POST /simulate-payment-success` exists only while `NOWPAYMENTS_SANDBOX=true`; production returns 404.

Both payment-creation endpoints require a JSON `country` containing an ISO
alpha-2 code from the checkout list. The customer selection must agree with
the local IP-country evidence before a provider transaction is created.

Both payment webhook routes require the hostname configured by `API_DOMAIN`. Configure the tunnel/DNS route for that host to reach this Flask service, then use:

- NOWPayments IPN: `https://api.echteralsfake.me/nowpayments-ipn`
- Patreon webhook: `https://api.echteralsfake.me/patreon-webhook`

Subscribe Patreon to `members:create`, `members:update`, `members:pledge:create`, and `members:pledge:update`. The update events allow delivery when an initially pending charge later becomes paid or an eligible pledge changes. Delivery is idempotent per Patreon member and retries reuse the same license.

## Production deployment

A minimal Gunicorn launch is:

```bash
uv run gunicorn --bind 127.0.0.1:8000 main:app
```

After installing a release, run the migration and runtime initialization once before restarting Gunicorn:

```bash
uv run flask --app main db upgrade
uv run flask --app main init-runtime
```

The intended topology is a TLS-terminating Cloudflare Tunnel/reverse proxy in front of that loopback listener. `ProxyFix` trusts one forwarded scheme/host/prefix hop but intentionally trusts no forwarded client address. Do not enable Gunicorn access logging or proxy logging that records visitor IPs if operating under the stated zero-log policy.

Before enabling payments:

1. Review `geoip/README.md`, install the local database over an appropriate connection, and restart all workers. Checkout fails closed with `503` while it is absent.
2. Set `NOWPAYMENTS_SANDBOX=false` and configure both NOWPayments secrets.
3. Route `API_DOMAIN` to this service and verify webhook hostname isolation.
4. Configure the Patreon secret and SMTP delivery settings.
5. Review the German and English email catalogs; their `reviewed` flags currently document review state.
6. Name any third-party mail provider in both privacy-policy templates and verify its data handling.
7. Obtain professional review of the tax-evidence and geographic policy documented in `docs/CHECKOUT_COUNTRY_COMPLIANCE.md`.
8. Back up `server.db`, the invoice directory, the signing key, and the Flask secret.

Flask-Limiter currently uses its in-memory backend, so limits are enforced per process. Configure a shared supported backend before scaling to multiple workers if globally consistent rate limits are required.

## Operational notes

- Alembic owns the managed SQLite schema. Importing the application does not query or mutate the database.
- `flask --app main init-runtime` explicitly resets aggregate request/traffic counters and their start timestamp; run it once per deployment, not once per Gunicorn worker.
- The payment schema retains the session/provider identifiers, expected amount/currency values needed to validate callbacks, selected country, evidence method, database label, processing state/lease, and timestamps. IP addresses, subdivisions, and card-flow email addresses are not stored locally; the email is forwarded only to the provider.
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
