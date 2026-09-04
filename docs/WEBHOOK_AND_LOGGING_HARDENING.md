# Webhook and logging hardening

This document explains the Patreon and NOWPayments audit performed on
2026-09-01, the defects found, the implemented changes, and how retries now
behave. It is intended as a learning and operations guide rather than only a
change list.

## 1. Sources used

Only first-party provider material was used for protocol decisions:

- Patreon API reference: `https://docs.patreon.com/`
- NOWPayments API help page: `https://nowpayments.io/help/api`
- NOWPayments' published Postman reference:
  `https://documenter.getpostman.com/view/7907941/2s93JusNJt`
- Raw NOWPayments Postman collection endpoint:
  `https://documenter.gw.postman.com/api/collections/7907941/2s93JusNJt?segregateAuth=true&versionTag=latest`

The raw snapshots and checksums are kept in `docs/provider_api/`. No community
examples, blog posts, or unofficial SDK behavior were treated as authoritative.

## 2. Provider requirements found during the audit

### Patreon

Patreon signs the exact request body with the webhook secret using HMAC-MD5.
The hexadecimal digest is sent in `X-Patreon-Signature`; the event name is sent
in `X-Patreon-Event`.

The current v2 membership triggers include:

- `members:create`
- `members:update`
- `members:delete`
- `members:pledge:create`
- `members:pledge:update`
- `members:pledge:delete`

`members:update` includes charging-event changes, so it is important for a
member whose initially pending charge later becomes paid. This application
issues new paid-member licenses and therefore accepts create/update events. It
acknowledges deletion and unrelated events without issuing a license; it does
not currently implement automatic license revocation.

Patreon documents a progressively delayed retry sequence after failed delivery:
approximately 30 seconds, 5 minutes, 15 minutes, 1 hour, 3 hours, 1 day, and
1 week, after which a manual retry is required. Failed events are queued. This
means transient application failures must return a failure response, while an
irrelevant or permanently ineligible event should return success.

### NOWPayments

NOWPayments signs a recursively key-sorted JSON representation with the IPN
secret using HMAC-SHA512. The hexadecimal digest is sent in
`x-nowpayments-sig`.

The documented payment lifecycle includes `waiting`, `confirming`, `confirmed`,
`sending`, `partially_paid`, `finished`, `failed`, `refunded`, and `expired`.
Only `finished` is treated as fulfillment-ready here. The undocumented value
`paid`, which the old handler also accepted, no longer grants a license.

NOWPayments' raw documentation says that an error response starts recurrent
notifications according to the timeout and count configured in the merchant
dashboard. It also says callbacks stop after payment expiration. The server
therefore uses non-2xx responses only for conditions that a later delivery can
reasonably fix.

The provider specifically warns about repeated and wrong-asset deposits. Such
payments carry `parent_payment_id`; their amount can differ from the original
payment, and the provider recommends checking the parent, amount, and asset
before providing service. The application never fulfills callbacks containing
a parent payment ID.

## 3. Defects found in the previous NOWPayments handler

The earlier code correctly verified the signature before parsing the trusted
payload, but fulfillment had several important gaps:

1. A signed `finished` event was correlated only by the locally generated
   `order_id`.
2. The callback's provider payment or invoice ID was not matched against the ID
   returned when the payment was created.
3. Expected fiat amount and currency were not stored or checked.
4. The direct-payment asset and actually paid amount were not checked.
5. The nonstandard status `paid` could trigger fulfillment.
6. An unknown `order_id` returned `200`, so a callback racing the initial local
   transaction insert could be lost permanently.
7. Concurrent callbacks could both begin invoice creation because there was no
   atomic processing claim.
8. Logs contained raw order/session identifiers.

All eight issues are addressed.

## 4. New NOWPayments transaction state

When creating a provider payment, the application now stores the minimum data
needed to validate a later callback:

| Field | Purpose |
| --- | --- |
| `session_id` | Random local correlation ID |
| `provider_payment_id` | Payment ID or invoice ID returned by NOWPayments |
| `provider_reference_type` | Tells validation whether to compare `payment_id` or `invoice_id` |
| `expected_price_amount` | Original fiat price, stored as decimal text |
| `expected_price_currency` | Original fiat currency |
| `expected_pay_amount` | Expected crypto amount for direct-payment flow |
| `expected_pay_currency` | Expected crypto asset for direct-payment flow |
| `customer_country` | Canonical customer-selected country name |
| `country_evidence` | Evidence methods that agreed at checkout |
| `geolocation_database` | Local database release/source label |
| `status` | `pending`, `processing`, or `finished` |
| `processing_started_at` | Start of the retry-recoverable processing lease |
| `finished_at` | Completion time used for year-based tax summaries |
| `created_at` | Creation timestamp |

Amounts use decimal text in SQLite and `Decimal` during comparison. This avoids
making a security decision with binary floating-point approximation.

The optional card-flow email is still forwarded only where required for that
flow and is not stored in the transaction table.

## 5. New NOWPayments fulfillment flow

For a `finished` callback, processing is now:

1. Verify the HMAC-SHA512 signature using the canonical sorted JSON.
2. Parse the payload with strict types and bounded identifiers.
3. Reject every callback with `parent_payment_id` without fulfillment.
4. Find the local transaction by `order_id`.
5. Match the stored provider reference to `payment_id` for direct payments or
   `invoice_id` for hosted invoices.
6. Match the original fiat amount and currency.
7. For direct payments, match the crypto asset and require `actually_paid` to
   be at least the amount returned when the payment was created.
8. Atomically change `pending` to `processing`. A second worker cannot acquire
   the same transaction.
9. Load an existing invoice after a recovered interruption, or atomically save
   a new invoice.
10. Mark the transaction `finished` and clear the lease.

A processing lease becomes reclaimable after ten minutes. If invoice storage
or database completion fails, the handler attempts to restore `pending` and
returns a retryable response. If a process dies between invoice storage and the
database update, a later callback reuses the already stored invoice instead of
creating a second invoice number.

### Response and retry decisions

| Situation | HTTP result | Reason |
| --- | --- | --- |
| Server signing secret missing | `503`, `Retry-After: 30` | Configuration can be repaired before retry |
| Bad or missing callback signature | `401`/`403` | Never trust or process the body |
| Invalid signed schema | `400` | Provider payload cannot safely be interpreted |
| Non-`finished` payment state | `200` | Status update received; no fulfillment yet |
| Repeated/wrong-asset deposit | `200` | Permanent automatic-fulfillment rejection |
| ID, amount, or currency mismatch | `200` | Permanent rejection; retries cannot make it valid |
| Unknown local order | `503`, `Retry-After: 30` | Local insert may have raced the callback |
| Another worker owns the lease | `503`, `Retry-After: 30` | Retry after current processing completes |
| Storage/database exception | `503`, `Retry-After: 30` | Transient failure should be retried |
| Successfully completed or already finished | `200` | Idempotent success |

Returning `200` for a permanent security rejection does not mean the payment is
accepted: it only prevents an endless provider retry loop. A warning with a
non-reversible correlation reference is emitted for operator review.

## 6. Patreon verification and retry behavior

The Patreon implementation already had the correct central design and was
retained:

- Signature verification uses the exact raw request bytes before JSON parsing.
- Eligibility requires an active patron, a paid last charge, positive current
  entitlement, no free trial, no gifted membership, and optionally a configured
  eligible tier.
- A database record provides member-level idempotency.
- Failed delivery reuses the same license on retry.
- A ten-minute `sending` lease prevents simultaneous requests from sending two
  emails.
- Delivery failures and busy leases return `503`; successful, previously sent,
  irrelevant, or ineligible events return `200`.

The audit added `members:pledge:update` to the accepted events and added
exception logging at the HTTP boundary. Patreon `members:delete` and
`members:pledge:delete` remain acknowledged and ignored because automatic
revocation is outside the current issuance-only product behavior.

SMTP cannot provide a true distributed exactly-once guarantee: if SMTP accepts
the email and the process dies before recording `sent`, a later retry may send
the same license again. The important properties are that no second license is
created and delivery is at least once after transient failures.

## 7. Privacy-safe application logging

Application-owned warning, error, and exception reporting now uses Python's
logging system consistently. `LOG_LEVEL` is centrally validated and defaults
to `INFO`.

The formatter redacts common accidental disclosures from both messages and
formatted exception tracebacks:

- Email addresses
- IPv4 and IPv6 addresses
- URL query strings
- Values assigned to common credential names such as token, secret, password,
  cookie, authorization, and API key

Exception stack frames and the exception class are retained, but the exception
message itself is omitted because database, SMTP, and HTTP libraries may embed
runtime identifiers or other user data in that text.

Payment and Patreon identifiers are not logged directly. Where correlation is
useful, the application logs the first 12 hexadecimal characters of a SHA-256
digest. This is stable enough to connect retries in logs without retaining the
original identifier.

The development HTTP logger records only method, path without query string,
and response status. `CheckoutCountryMiddleware` uses the trusted client
address only for payment-creation country verification, then removes it,
`REMOTE_ADDR`, and common forwarding headers before Flask extensions inspect
the request. All other request paths have the address fields removed without a
lookup. See `CHECKOUT_COUNTRY_COMPLIANCE.md` for the complete data flow.

The formatter is a final safety net, not permission to log payloads. Code must
still never intentionally log request bodies, email addresses, license keys,
session cookies, authorization headers, raw payment/member/session IDs, or
SMTP credentials.

### Deployment boundary

The application cannot control logs produced before a request reaches it.
Gunicorn access logs are disabled by default and should remain disabled. The
Privex VPS, WireGuard endpoints, reverse proxy, operating system, and hosting
platform must also be configured not to retain visitor IPs or query strings.
Their settings must be reviewed separately.

## 8. Tests added for this work

The deterministic suite now covers:

- Completed hosted invoices and idempotent callback replay
- Direct payments with string and integer provider IDs
- Provider-reference mismatch
- Fiat amount and currency mismatch
- Direct-payment asset mismatch and underpayment
- Repeated deposits and the nonfinal `paid` value
- Unknown-order and busy-lease retry responses
- Exact transaction schema additions
- Invalid `LOG_LEVEL` startup failure
- Redaction of emails, IPv4, IPv6, query strings, credentials, and exception
  messages
- Stable non-reversible log correlation references

Run verification with:

```bash
uv run python -m unittest discover -s tests -v
uv run python -m compileall -q main.py pf_server docs/build.py api_tests.py
uv run flask --app main db check
```

## 9. Operational checklist

Before enabling live payments:

1. Start with a fresh test database and run `flask --app main db upgrade`.
2. Configure `NOWPAYMENTS_IPN_SECRET` and verify the provider test callback.
3. Set the NOWPayments recurrent-notification timeout/count in the dashboard.
4. Subscribe Patreon to `members:create`, `members:update`,
   `members:pledge:create`, and `members:pledge:update`.
5. Verify that SMTP failures produce `503` and a later retry reuses the same
   license.
6. Keep application, Gunicorn, proxy, and platform access logging aligned with
   the no-user-data policy.
7. Monitor warning/error counts without adding raw webhook payloads to logs.
8. Re-download and review provider documentation before moving from test mode
   to live payments.
