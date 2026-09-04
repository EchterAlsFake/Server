# Porn Fetch Server Refactoring Guide

This document explains the server refactor in human terms. It describes what
changed, why it changed, how the pieces now work together, and what you should
know before running or extending the application.

The short version is that the server changed from one very large Flask module
into a small application entry point surrounded by focused route, service,
configuration, model, migration, and test modules.

## 1. The big picture

### Before

Most application responsibilities lived directly in `main.py`:

- Flask setup and extension construction
- Environment-variable parsing
- Database models and schema creation
- HTML and API routes
- NOWPayments and Patreon integration
- License creation and email delivery
- Invoice storage and PDF rendering
- Update-feed generation
- CI, checklist, statistics, and shutdown logic

This made unrelated features depend on the same module. Importing or testing
one feature also pulled in most of the application. Database changes were not
versioned, and it was difficult to see where a behavior belonged.

### After

`main.py` is now a 143-line assembly and deployment module. Its main job is to:

1. Load the environment.
2. Create a Flask application.
3. Load validated configuration.
4. Initialize shared extensions.
5. Register feature Blueprints.
6. Register request hooks and error handlers.
7. Expose `main:app` for Gunicorn.

The application now follows this structure:

```text
Request
  -> Flask application factory (main.py)
    -> Feature Blueprint (*_routes.py)
      -> Business service (*_service.py, licensing.py, invoice_service.py)
        -> SQLAlchemy model (models.py)
          -> SQLite schema managed by Alembic (migrations/)
```

The practical benefit is separation of concerns: HTTP code handles HTTP,
business logic handles business rules, and persistence code handles stored
state.

## 2. New repository structure

| File | Responsibility |
| --- | --- |
| `main.py` | Application factory, extension setup, middleware, and deployment entry point |
| `pf_server/config.py` | Environment parsing, normalization, validation, and secret persistence |
| `pf_server/countries.py` | Static ISO country names used by checkout |
| `pf_server/country_service.py` | Local IP-country evidence and geographic checkout policy |
| `pf_server/extensions.py` | Unbound Flask extension instances |
| `pf_server/models.py` | Active SQLAlchemy models |
| `pf_server/page_routes.py` | Public pages and landing-page access control |
| `pf_server/docs_routes.py` | Safe serving of generated documentation |
| `pf_server/payment_routes.py` | Payment, invoice, license, and webhook HTTP endpoints |
| `pf_server/checklist_routes.py` | Checklist pages, editing API, and progress badge |
| `pf_server/ci_routes.py` | CI status API and SVG badges |
| `pf_server/update_routes.py` | GitHub release metadata and Sparkle appcast |
| `pf_server/operations_routes.py` | Health, statistics, runtime initialization, and kill switch |
| `pf_server/nowpayments_service.py` | NOWPayments requests, signatures, and payment completion |
| `pf_server/patreon_service.py` | Patreon eligibility and idempotent license delivery |
| `pf_server/licensing.py` | License keys, Ed25519 signing, email validation, and SMTP delivery |
| `pf_server/invoice_service.py` | Atomic invoice storage and PDF generation |
| `pf_server/webhook_models.py` | Strict third-party webhook payload models |
| `pf_server/http.py` | Shared hostname normalization |
| `pf_server/time_utils.py` | Consistent RFC 3339 timestamps |
| `pf_server/tax_service.py` | Country-level completed transaction summaries |
| `migrations/` | Versioned database schema |
| `tests/_support.py` | Isolated shared application/database test fixture |
| `tests/test_application.py` | Pages, CI, updates, operations, and factory tests |
| `tests/test_config.py` | Configuration parsing and validation tests |
| `tests/test_payments.py` | Payment, invoice, and license tests |
| `tests/test_patreon.py` | Patreon webhook and delivery tests |

## 3. Flask application factory and Blueprints

The application is constructed by `create_app()` instead of being configured
piece by piece at module scope.

```python
from main import create_app

app = create_app({"TESTING": True})
```

Each call creates an independent Flask application and reloads the current
environment-backed configuration. Tests can therefore create isolated apps
without accidentally sharing configuration or database setup.

Routes are grouped into Blueprints by feature. For example, payment routes are
registered by `payments_bp`, while CI routes are registered by `ci_bp`. A route
module no longer needs to own or import the complete application.

Benefits:

- Smaller modules are easier to navigate.
- Features can be tested independently.
- Circular imports are less likely.
- Route names clearly show ownership, such as `payments.nowpayments_ipn`.
- Adding a new feature normally means adding one Blueprint rather than growing
  `main.py` again.

The module-level `app = create_app()` remains so the deployment command stays
simple:

```bash
uv run gunicorn --bind 127.0.0.1:8000 main:app
```

## 4. Shared Flask extensions

Flask-SQLAlchemy, Flask-Migrate, CSRF protection, rate limiting, and Talisman
are created without an application in `pf_server/extensions.py`.

The factory later calls each extension's `init_app()` method. This is the Flask
factory pattern: extension objects are reusable, but their state belongs to the
specific application being constructed.

This replaces extension instances that were permanently tied to one global
application.

## 5. Centralized and validated configuration

All environment-backed configuration is now read by
`load_environment_config()` in `pf_server/config.py`.

The loader:

- Normalizes data and database paths.
- Creates the configured data directory when needed.
- Normalizes public application and API origins.
- Extracts the expected API webhook hostname.
- Parses booleans strictly.
- Validates ports and URL ports.
- Validates the raw 32-byte Ed25519 private key.
- Rejects mutually enabled SMTP SSL and STARTTLS.
- Requires an SMTP password when an SMTP username is supplied.
- Requires both NOWPayments secrets when sandbox mode is disabled.
- Parses the optional Patreon tier allow-list.

Configuration errors now stop startup with a clear error. For example,
`NOWPAYMENTS_SANDBOX=treu` is rejected instead of silently behaving like
`false`.

If `SECRET_KEY` is not configured, a random key is stored in `.flask_secret`.
The file is locked while being created, flushed safely, reused on later
startups, and restricted to mode `0600`. This avoids invalidating every Flask
session whenever the process restarts.

The new `.env.example` documents the supported settings and provides a safe
starting point for local configuration.

## 6. Database migrations and clean schema

Database creation is no longer performed implicitly with `db.create_all()` at
application startup. Flask-Migrate and Alembic now own the schema.

Create a new database with:

```bash
uv run flask --app main db upgrade
```

Check that models and migrations agree with:

```bash
uv run flask --app main db check
```

### Current tables

| Table | Purpose |
| --- | --- |
| `stats` | Aggregate request and traffic counters |
| `ci_status` | Latest result for each CI test name |
| `transaction` | Payment correlation/expectations, fulfillment state, lease, and timestamps |
| `checklist` | Development checklist tasks |
| `license` | Signed-license identity, state, and issuance reference |
| `patreon_license_deliveries` | Patreon delivery state used for retries and idempotency |

### Fresh-schema decision

The migration baseline deliberately targets a fresh database. Compatibility
with experimental pre-refactor schemas was removed because the service is
still in test mode and has no real payment records.

The following old fields and tables are not present:

- `transaction.trans_id`
- `transaction.purchase_id`
- `transaction.email`
- `license.transaction_id`
- `report`
- `write_log`

The replacements are:

- `transaction.provider_payment_id`
- `license.issuance_reference`

Provider payment IDs and license issuance references are unique. Required
fields are non-nullable, which moves invalid-state detection closer to the
database.

If you created `server.db` using an earlier test schema, move that file aside
and create a new database. Do not expect the clean baseline to adopt it.

## 7. Payment flow changes

The HTTP endpoints remain in `payment_routes.py`, while NOWPayments-specific
work lives in `nowpayments_service.py`.

### Creating a payment

1. The route validates the incoming request.
2. The service creates a random `NP-...` session ID.
3. The service calls NOWPayments with a configured API callback URL.
4. A minimal pending transaction plus callback-validation expectations is stored.
5. The client receives the session ID and provider URL.

Only these transaction values are retained locally:

- Internal session ID
- Provider payment ID
- Whether the provider reference is a payment ID or invoice ID
- Expected fiat amount and currency
- Expected crypto amount/currency where the direct flow makes them known
- Payment status and processing lease
- Creation timestamp

An email address submitted for the optional card-assisted flow is validated
and passed to the provider, but it is no longer stored in the transaction
table. The English and German privacy policies were updated to match this
behavior.

### Completing a payment

NOWPayments callbacks are accepted only on the hostname configured by
`API_DOMAIN`. The callback signature is checked before the payload is trusted.
Strict payload models then validate types, required identifiers, lengths, and
numeric ranges without silently coercing invalid values.

For a fulfillment-ready callback:

1. The server finds the known local transaction or returns a retryable `503`.
2. It matches the provider payment/invoice ID, expected price, currency, and
   direct-payment asset/amount.
3. It rejects repeated or wrong-asset deposits carrying `parent_payment_id`.
4. It atomically claims a ten-minute processing lease.
5. It builds and atomically saves (or reuses) the invoice.
6. It marks the transaction as `finished`.
7. Repeated successful callbacks do not create another invoice.

The stored transaction state has one success value, `finished`. Only the
provider's documented `finished` webhook value triggers completion; `paid` is
not treated as final.

### Sandbox simulation

`POST /simulate-payment-success` is available only when
`NOWPAYMENTS_SANDBOX=true`. In production mode the route responds as if it does
not exist.

## 8. License generation

License work lives in `pf_server/licensing.py`.

A license file is canonical JSON signed with Ed25519. Its important fields are:

```json
{
  "schema": 1,
  "product": "porn-fetch",
  "kid": "v1",
  "alg": "ed25519",
  "license_key": "PF-...",
  "issuance_reference": "...",
  "created_at": "...",
  "features": ["full_unlock"],
  "sig": "..."
}
```

The old Stripe-named `stripe_session_id` field was removed. The neutral
`issuance_reference` works for both NOWPayments purchases and Patreon-issued
licenses.

Repeated downloads reuse the license associated with the same issuance
reference instead of generating more licenses.

Recipient email validation rejects overly long addresses, header injection,
invalid local parts, malformed internationalized domains, and invalid DNS
labels before SMTP is used.

SMTP delivery uses bilingual JSON message catalogs from `i18n/` and attaches
the signed license as `porn_fetch.license`.

## 9. Patreon delivery

Patreon handling is split between strict webhook models, the HTTP webhook
route, and `patreon_service.py`.

The webhook route:

1. Requires the configured API hostname.
2. Validates the Patreon MD5 signature before JSON processing.
3. Accepts only supported membership events.
4. Validates the payload structure and data types.
5. Verifies that the member is paid and entitled.
6. Applies the optional configured tier allow-list.
7. Delivers the license when a usable email address is present.

The delivery table provides idempotency. A Patreon member can receive at most
one associated license, and webhook retries reuse it. A short database-backed
lease prevents concurrent webhook deliveries from sending multiple messages.
Failed email attempts release the delivery for a later retry.

The raw Patreon webhook and email address are not retained locally. Only the
member ID, license mapping, state, and delivery timestamps are stored.

## 10. Invoice handling

Invoice work was moved to `invoice_service.py`.

Invoices are first represented as validated dictionaries. JSON persistence is
atomic: data are written to a temporary file in the target directory, flushed,
and then replaced into the final location. This reduces the chance of leaving
a partially written invoice after an interruption.

Stored invoice data are validated before they are used. PDF rendering is
isolated from the route, and downloaded filenames are normalized.

Unreadable or missing invoices now produce controlled HTTP responses instead
of unhandled exceptions.

## 11. Authentication and request security

Several authentication and request-handling behaviors were tightened:

- Landing-page and checklist passwords are read from Flask configuration.
- Successful logins store keyed markers rather than a plain `True` flag.
- Changing `CHECKLIST_AUTH` invalidates existing login markers.
- Secret comparisons use `hmac.compare_digest()`.
- The landing-page `next` target allows only safe local paths.
- Authentication pages use private, no-store cache headers.
- CI writes fail closed when `CI_TOKEN` is missing.
- The kill switch fails closed when `KILL_TOKEN` is missing.
- The kill switch has explicit token authentication and does not depend on a
  browser CSRF token.
- Request bodies are limited to 200 KiB.
- Rate-limit and oversized-payload errors return consistent JSON.
- Flask-Talisman applies security headers, cookie settings, and a restricted
  content security policy.

## 12. Privacy-preserving request handling

`CheckoutCountryMiddleware` temporarily uses the trusted client address only
when a payment-creation form is submitted. It compares the customer-selected
country with a local DB-IP database, retains only the country-level result, and
then removes the address fields before Flask and Flask-Limiter inspect the
request. On every other request it removes them without performing a lookup:

- `CF-Connecting-IP`
- `CF-Connecting-IPv6`
- `True-Client-IP`
- `X-Forwarded-For`
- `X-Real-IP`
- `Forwarded`
- WSGI `REMOTE_ADDR`

`ProxyFix` still trusts one forwarded scheme, host, and prefix hop so URLs work
behind the intended proxy, but it trusts zero forwarded client-address hops.

The local database lookup never calls an external geolocation API. The IP and
Ukraine subdivision result are not persisted or logged; transactions keep only
the selected country name, evidence-method label, and database release label.
Checkout fails closed when evidence is missing, mismatched, or restricted. The
full tax rationale, known sanctions-policy overreach, and operating procedure
are documented in `docs/CHECKOUT_COUNTRY_COMPLIANCE.md`.

The development request logger records the method, path without query string,
and response code through the privacy-safe logging formatter. It does not
record the remote address or query parameters. Warnings and exceptions include
tracebacks where useful, while common email/IP/query/credential patterns are
redacted from the final rendered log. Raw user and webhook data must still
never be intentionally passed to a logger.

These application changes cannot prevent a reverse proxy, Cloudflare, Gunicorn,
the operating system, or an ISP from logging independently. Their logging must
still be configured separately.

## 13. Documentation serving

Documentation routes now use safe path joining and verify that resolved files
remain inside `docs/dist`. Traversal attempts cannot use `..` to read arbitrary
project files.

The server supports both:

- `/docs/...` on the normal application origin
- `/...` when the request host is the documentation subdomain

Generated documentation is still written to `docs/dist`. Edit the files in
`docs/content/` and the templates, then rebuild:

```bash
uv run python docs/build.py
```

## 14. Release and update reliability

GitHub release metadata is cached for five minutes. The update service now:

- Uses a configured GitHub token when available.
- Handles unavailable GitHub responses without crashing.
- Reuses stale cached data when a refresh fails.
- Ignores malformed asset entries.
- Handles missing expected assets.
- Uses the configured public application origin for generated URLs.
- Normalizes RFC 3339 timestamps.

The Sparkle appcast validates release metadata. A missing local Sparkle
signature returns a controlled `503` response instead of crashing. Invalid
release timestamps and sizes receive safe fallback values.

The release checklist now includes database migration and one-time runtime
initialization steps.

## 15. Statistics and operational routes

Request and byte counters are updated with SQLite upserts and SQL expressions,
reducing lost updates compared with read-modify-write Python code.

`GET /stats` provides HTML by default and JSON when requested. Timestamp output
is normalized to RFC 3339 without producing invalid values such as
`+00:00Z`.

Runtime statistics are initialized explicitly:

```bash
uv run flask --app main init-runtime
```

This command uses a filesystem lock and should be run once during deployment,
not independently in every Gunicorn worker.

`POST /killswitch` runs `poweroff` asynchronously only after its dedicated
token is validated. The endpoint should still be protected by network controls.

## 16. CI and checklist improvements

CI status writes validate authentication, names, statuses, and details. SVG
badge content is escaped so user-controlled test names cannot inject markup.

Checklist mutations now:

- Require the password-derived session marker.
- Validate JSON types.
- Trim task text.
- Limit tasks to 500 characters.
- Return `404` when toggling or removing a missing task.
- Invalidate authentication after password rotation.

## 17. Tests and verification

The old monolithic payment/webhook test module was replaced with focused test
suites sharing an isolated temporary database fixture.

At the time of this guide, 64 deterministic tests cover:

- Application-factory isolation
- Configuration parsing and failure cases
- Public pages and privacy text
- Authentication and password rotation
- Documentation path containment
- CI authentication and SVG escaping
- Statistics and timestamps
- GitHub update failure handling
- Sparkle metadata handling
- NOWPayments hostname and signature validation
- Strict webhook payload types and ranges
- NOWPayments provider-ID, amount, asset, retry, and idempotency behavior
- Privacy-safe log redaction and correlation
- Payment simulation and invoice downloads
- License signing and reuse
- Patreon eligibility, tier filtering, retries, leases, and idempotency
- Email catalog consistency
- The exact clean transaction schema
- Local country evidence, IP-field removal, and fail-closed checkout behavior
- Geographic restriction policy and privacy-minimizing tax summaries

Run them with:

```bash
uv run python -m unittest discover -s tests -v
```

Additional checks used during the refactor were:

```bash
uv run python -m compileall -q main.py pf_server docs/build.py api_tests.py
uv run flask --app main routes
uv run flask --app main db check
uv lock --check
```

The migration was also tested against a temporary database for a complete
upgrade, schema inspection, drift check, and downgrade. No live database was
modified by that verification.

## 18. Dependency and asset audit

Direct dependencies in `pyproject.toml` were normalized and sorted. Each one is
used either by application code, documentation generation, database migration,
or the production Gunicorn command. No dependency was removed merely because
it is also transitively installed by another package when the project imports
it directly.

Templates and static assets were checked against route rendering, template
inheritance, documentation generation, and deployment usage. No active asset
was removed.

The generated `docs/dist` directory remains committed output, while
`docs/content` and the documentation templates remain the editable sources.

## 19. Important breaking changes

Because compatibility layers were intentionally removed, these changes require
attention:

1. Old test databases are not supported by the new baseline migration.
2. The transaction schema no longer has `trans_id`, `purchase_id`, or `email`.
3. The license table uses `issuance_reference`, not `transaction_id`.
4. License JSON uses `issuance_reference`, not `stripe_session_id`.
5. The unused `report` and `write_log` tables are gone.
6. Stored successful transaction status is consistently `finished`.

For this test deployment, the intended transition is to create a fresh
database rather than write data-conversion migrations for records that do not
exist.

## 20. How to start the refactored server

```bash
uv sync
cp .env.example .env
```

Edit `.env`, then create the clean schema:

```bash
uv run flask --app main db upgrade
```

For local development:

```bash
uv run python main.py
```

For a Gunicorn deployment:

```bash
uv run flask --app main init-runtime
uv run gunicorn --bind 127.0.0.1:8000 main:app
```

## 21. A suggested learning path

If you want to understand the new codebase, read it in this order:

1. Start with `main.py` to see how the application is assembled.
2. Read `pf_server/config.py` to understand startup settings and validation.
3. Read `pf_server/extensions.py` and `pf_server/models.py` to see shared state.
4. Pick one small Blueprint, such as `ci_routes.py`, and trace a request.
5. Follow `payment_routes.py` into `nowpayments_service.py` to see the route and
   service separation.
6. Read `licensing.py` and `invoice_service.py` to see reusable business logic.
7. Read `webhook_models.py` before `patreon_service.py` to see how untrusted
   JSON becomes validated data.
8. Compare `models.py` with the baseline migration.
9. Read the matching test file after each feature module.

When adding a new feature, a useful rule is:

- Put request parsing and HTTP responses in a Blueprint.
- Put reusable business rules in a service.
- Put persistent structure in a model and migration.
- Put environment parsing in the configuration loader.
- Add a focused regression test alongside the related feature suite.

## 22. Overall benefits

| Area | Benefit |
| --- | --- |
| Organization | Features have clear ownership and smaller files |
| Maintainability | Changes require less unrelated context |
| Testability | Apps and databases can be isolated predictably |
| Configuration | Invalid deployments fail early with clear messages |
| Database | Schema changes are explicit, reviewable, and reproducible |
| Payments | Provider logic, persistence, and HTTP handling are separated |
| Security | Authentication, signatures, paths, redirects, and payloads are validated |
| Reliability | Retries, atomic writes, caching, and controlled errors are tested |
| Privacy | Less personal data are stored and visitor headers are stripped |
| Documentation | Setup, deployment, configuration, and release work are recorded |

The most important long-term rule is to keep `main.py` small. New functionality
should extend the relevant feature module or introduce a focused module instead
of rebuilding the original monolith.
