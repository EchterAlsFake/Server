# Banxa annual-license checkout

The optional `/buy_card` flow charges real money and grants the same annual-update
entitlement as other live methods: one year from first activation, continued use of
eligible versions, and no automatic Porn Fetch license renewal. New consent records
use `banxa-annual-v1` with `beta=false`. Historical `banxa-beta-v1` orders retain their
stored beta flag, original notices and email terms; no release-day deletion is automated.
NOWPayments crypto remains recommended. The separate delivery mailbox is not sent
to Banxa. Patreon membership itself must be cancelled to stop recurring Patreon bills.

## Enablement

1. Apply migrations with `uv run flask --app main db upgrade`.
2. Configure production NOWPayments credentials, its signed `/nowpayments-ipn`
   webhook, Keygen issuance and SMTP. Verify the annual policy and its match to the
   shipped client using `flask --app main verify-license-policy --client-config /path/to/production.json`. `NOWPAYMENTS_SANDBOX` must be false for
   real-money Onramp checkout. Sandbox API addresses can never receive real
   customer funds. To offer a separate crypto sandbox, run it separately with
   sandbox credentials; the checkout notice never promises the live crypto route
   is simulated.
3. Generate `ONRAMP_ENCRYPTION_KEY` using `Fernet.generate_key()` and store it
   securely outside source control. Preserve it in protected backups until all
   encrypted records have been purged. Changing it prevents pending delivery
   and checkout recovery. Do not use Flask's signing secret as this key.
4. Before setting `ONRAMP_POLYGON_USDC_VERIFIED=true`, verify the exact USDC
   contract and network delivered by Onramp-Pay against NOWPayments' `usdcmatic`
   payment. Polygon address syntax alone does not establish token compatibility:
   native USDC and bridged USDC are distinct. Verify that the optional email
   parameter can be omitted and Banxa collects verification email directly.
5. Verify fee behavior and a complete production deposit with a controlled
   annual-license purchase before opening public traffic. Set `ONRAMP_ENABLED=true` only
   for that operator-run test, then leave enabled after successful validation.
   The test costs real money. No automated test calls a live creation endpoint.
6. Install `deploy/eaf-onramp-deliveries.{service,timer}` in `/etc/systemd/system/`
   and enable with `systemctl enable --now eaf-onramp-deliveries.timer`. It runs
   `flask --app main retry-onramp-deliveries` every five minutes, even if new
   purchases are disabled. Without this timer, retry/retention guarantees do not
   hold. Monitor `systemctl status` and the unit journal for failures.

All three feature settings default to disabled/empty. Startup refuses enabled
checkout without production payment, token verification, encryption, SMTP,
HTTPS origins and Keygen configuration. Set `ONRAMP_ENABLED=false` to stop new
checkouts; keep existing NOWPayments callbacks and the retry job working.

## Funding and callbacks

The server requests a floating-rate €19.99 NOWPayments payment in `usdcmatic`.
A USD-to-USDC estimate converts the required crypto amount into USD and divides
by 0.97, rounding up to cents, to cover the documented 3% deduction. Banxa's
final quote can add processing/network fees and currency conversion costs.
There is no documented guaranteed net-settlement quote; do not describe this
as one. Verify the 3% deduction behavior before launch.

Banxa must be active in the provider directory and the USD charge must meet
its minimum. No other provider is selected automatically. An unexpected
provider redirect fails closed; the known HTTPS API wrapper redirect to
`api.paygate.to` on the same endpoint path is allowed. Checkout links use only
`checkout.onramp-pay.com/process-payment.php`, with `provider=banxa` and the
encrypted `address_in` returned by wallet creation. No affiliate endpoint is
used. Ambiguous creation failures are not retried automatically.

Onramp's GET callback stores only a receipt timestamp, ignoring all payment
fields. It cannot fulfill orders. Signed NOWPayments `finished` or settled `partially_paid` events must
match the stored payment ID, €19.99 price and currencies and report at least
90% of the original quoted crypto amount. The stored €19.99 order price must
still match exactly; the tolerance applies to actual crypto received, not to
replacement order metadata. Overpayments issue one license. Lower
payments, failures and expiry are displayed for support review. Direct crypto
payments retain their existing full-payment validation.

The customer opens the payment link explicitly in a separate tab and keeps the
original status URL. This URL is a bearer credential: anyone holding it can
access the license. There is no dependency on an undocumented provider return
URL. Do not enable proxy access logging of query strings or log provider URLs,
mailboxes, response bodies, callbacks or tracking tokens.

## Delivery, retention and support

A confirmed payment creates one stable Keygen issuance reference and signed
license before fulfillment completes. Browser delivery works independently of
SMTP. The encrypted outbox uses ten-minute fenced leases; SMTP failures are
retried without another license. A deterministic Message-ID helps suppress
repeat emails in the SMTP-accepted/database-commit crash window; exactly-once
SMTP delivery cannot be guaranteed.

Recipient data is removed on successful send, or purged seven days after order
creation. Encrypted checkout/tracking references and callback secrets are also
purged after seven days. Consent version/time, offer designation and accounting
references remain. Existing database backups can contain encrypted historical
records and require the same access protection and backup retention policy.

Review warnings for checkout failures and deferred emails, pending/failed
outbox rows, underpayments, and timer failures without printing PII. A failed
checkout can leave an unused NOWPayments address; never send funds to it.
For a delayed payment retain the session reference and reconcile NOWPayments
before asking the customer to pay again. Banxa handles card authorizations and
KYC disputes. Release-day license deletion remains a separate explicit task.

## Provider references

- [Onramp-Pay gateway API](https://www.onramp-pay.com/api-docs)
- [Banxa KYC tiers](https://docs.banxa.com/reference/global-kyc-framework)
- [NOWPayments fees](https://nowpayments.io/pricing)
- NOWPayments API snapshot: `docs/provider_api/nowpayments-api.postman_collection.json`

## Automated verification

Run `uv run python -m unittest discover -s tests -q`. The optional Chromium
smoke test runs with `uv run --with playwright python scripts/test_onramp_browser.py`
after `uv run --with playwright python -m playwright install chromium`.
It blocks third-party traffic, mocks all provider requests and SMTP, and covers
CSRF, closing/reopening the timer, explicit payment-tab launch, signed receipt,
browser delivery and mobile overflow. Screenshots go to `/tmp`, outside the repo.

## Offer compatibility

`POST /create-onramp-payment` requires `annual_terms_acknowledged: true` instead of
the former beta acknowledgment. Consent tokens with an obsolete offer version are
rejected before any provider request. Existing ready/paid orders remain recoverable
through their original status URL and retain their accepted terms.

Creation and status responses identify card checkout with `payment_method: "banxa"`.
The `beta` field reflects the stored order, independently of the payment method.
Success-page rendering and email retries must never infer beta status merely from
an Onramp record being present. No historical rows need migration: the existing beta
column retains its legacy default, while the new acknowledgment route explicitly
sets false. No live payments, licensing mutations or deployment are part of this edit.

## Current preview UI

All payment methods are selectable for inspection. The card form and KYC disclosure
can be viewed before the merchant configuration is ready; its acknowledgment and
creation endpoints still return an explicit unavailable response without contacting
providers until the existing configuration checks pass. This is not a direct Banxa
integration and does not introduce a provider sandbox.

The selector and generated Banxa link use `/payment-preview/...` to show an explicit
no-payment warning. Acknowledged external navigation goes through a same-origin
launch page so `form-action 'self'` remains in place. The no-JavaScript fallback
shows the same warning followed by an explicit provider link. The public routes
never create payment records or call providers by themselves.


## Live customer progress

Run `flask db upgrade` before using this checkout. The `payment_progress` table
stores minimal provider observations and a shared polling lease. Both payment
methods use `/buy_success?session_id=…` as a recovery and progress page, with the
provider checkout opened in a separate tab. Keep that URL for recovery.

Signed NOWPayments IPNs update intermediate states for both direct crypto and
card purchases. Each event is bound to the stored order, provider reference,
price and asset. For hosted invoices, the first matching IPN supplies the payment
ID; an invoice ID is never used as a payment ID. Once the ID is known, the server
can also read NOWPayments' payment-status API to supplement progress.

The server reads Onramp Pay's `/control/payment-status.php` using the encrypted
tracking token already stored at creation. `paid` with a positive amount indicates
receipt; a Polygon payout transaction hash indicates forwarding. No separate Banxa
payment-authorization or email-verification status is exposed by this API, so the
page does not invent those steps. Unsupported or unavailable data preserves the
last known observation.

Provider reads are cached for 60 seconds per order and protected by a database
lease across processes/tabs. The browser polls the local server every 5 seconds,
pauses in hidden tabs, and retries temporary failures. Signed webhooks can update
the display between provider reads. No background progress job is required.

**API observations and unsigned Onramp callbacks never approve payment or issue
licenses.** Only the signed, fully matched NOWPayments receipt goes through the
existing fulfillment checks and the durable receipt worker. Completion reported by an API alone remains pending.
Provider launch links are hidden/blocked once receipt or forwarding is observed,
to reduce accidental duplicate payments. Partial, failed, expired and wrong-asset
payments show support instructions instead of a successful purchase.

Provider references:
- https://www.onramp-pay.com/api-docs
- https://nowpayments.zendesk.com/hc/en-us/articles/21345824322717-API-and-endpoint-description
- https://docs.banxa.com/reference/global-kyc-framework
- https://support.banxa.com/en/support/solutions/articles/44002216503-how-long-will-my-order-take-

The card page presents Express verification conditionally, offers a Patreon
alternative for customers without a Tax ID, and distinguishes the 10-minute
expectation from Banxa's published 90-minute typical processing window. Connection
advice is the merchant's precaution; it cannot guarantee Express eligibility.

## Durable receipt worker and deployment

Apply `flask --app main:app db upgrade head` before running the updated webhook.
Signature and schema verification precede persistence. Native Polygon USDC
metadata (network, exact contract and deposit availability) is checked before
creating an Onramp payment. Final receipts are normalized
to payment fields only and committed to `payment_receipts` before HTTP 200; no
Keygen or SMTP request runs in the HTTP acknowledgment path. Persistence failures
return HTTP 503 so the provider can redeliver.

Run `flask --app main:app process-nowpayments-receipts` every 15 seconds. Atomic
ten-minute leases prevent concurrent processing; interrupted work is recovered
after lease expiry. Failures retry with 30-second to five-minute backoff without
requiring another webhook. Duplicate receipts and stable license issuance IDs
prevent duplicate fulfillment. Terminal receipts are removed after 30 days;
pending receipts are retained. Database/configuration backups preserve this queue.

Keep the minute crypto-email and five-minute Onramp-email retry/retention jobs
running independently. All jobs must use the web application's credentials and
database. Rootless Podman definitions live in the infrastructure repository at
`ops/user-systemd/pornfetch-{receipts,crypto-deliveries,onramp-deliveries}.*`.

The provider directory request uses HTTPS `/control/provider-status/` including
the trailing slash. Keep the redirect allowlist: the slashless endpoint has been
observed redirecting to HTTP with affiliate parameters, which must be rejected.
Native Polygon USDC compatibility and supported forwarding still need provider
confirmation before enabling live checkout.

The 90% floor applies to the Onramp route; ordinary direct crypto payments retain
their existing full-payment checks. Overpayments have no upper rejection boundary
and still issue only one license. Do not change the merchant payout destination
when integrating: NOWPayments' non-custodial payout to the configured Kraken
Polygon USDC wallet is separate from the per-order incoming payment addresses.
