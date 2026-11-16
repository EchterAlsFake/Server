# Stripe checkout preparation

New Mollie checkouts and launch links are permanently disabled in application code,
even if old Mollie flags/keys remain configured. Historical records, recovery,
fulfillment and provider reconciliation remain available. No production changes
were made as part of this preparation. Crypto and Patreon retain their existing
configuration.

Stripe is disabled by default. New orders use Stripe Managed Payments and hosted
Checkout for a one-time lifetime license at the server-defined EUR price,
including applicable tax. Stripe controls available payment methods and local
currency presentment. No publishable key, browser Stripe
SDK or externally configured Price ID is needed. The product name sent to Stripe
is explicitly `Porn Fetch lifetime Premium license`.

Managed Payments must be activated separately in each Stripe environment. New
sessions explicitly request `managed_payments[enabled]=true`, classify the product
as downloadable software for personal use (`txcd_10202000`), and use an inclusive
price so applicable tax is included in EUR 29.99. The integration does not set
`automatic_tax`, `payment_method_types`, or `adaptive_pricing`: Managed Payments
controls these settings. The service rejects a session that silently drops
Managed Payments. Existing reserved ordinary Stripe orders retain their original
payload and invoice behavior.

Stripe / Link supplies the buyer's payment receipt and tax invoice. The server
stores authenticated Stripe invoice/receipt references and redirects the buyer
to those documents; it does not generate a separate seller invoice or attach
the old section-19 tax exemption to a Managed Payments purchase. License delivery
continues even while Stripe's document is being finalized. License and benefit
confirmation emails come from Porn Fetch; payment documents come separately
from Link. Checkout's terms and product disclosure describe these roles.

## Account and environment setup

Complete account verification and accurately disclose the product/business to
Stripe. Confirm eligibility with Stripe during onboarding:
https://stripe.com/legal/restricted-businesses . Account verification alone does
not establish product eligibility.

Configure secrets through the deployment's environment/credential mechanism:

- `STRIPE_TEST_ACCOUNT_ID`: the sandbox's `acct_...` account associated with its key.
- `STRIPE_TEST_API_KEY`: preferably a restricted `rk_test_...` key; `sk_test_...` is also supported.
- `STRIPE_TEST_WEBHOOK_SECRET`: `whsec_...` for the sandbox webhook endpoint.
- `STRIPE_TEST_PASSWORD_HASH`: a Werkzeug password hash for private tester access.
- `STRIPE_TEST_ENABLED=true`: exposes the tester form on `/porn_fetch`.

Keep `STRIPE_LIVE_ENABLED=false` during sandbox validation. Existing SMTP,
recipient-encryption, Keygen, country database and Tor-list settings are also
required. Sandbox success currently issues a real lifetime license, with sandbox
provenance and test documents; use controlled test recipients.

An MCP OAuth connection authorizes the assistant; it does not provide persistent
API credentials to the web service. Create a separate backend restricted key in
the selected sandbox. It needs read access to account details and Charges,
write access to Checkout Sessions and PaymentIntents, and the Product/Price
permissions needed for inline Checkout prices. Validate
these permissions in a sandbox; the service never falls back to a different key.
Keep the assistant's OAuth authorization separate from this application key.
Store the key and webhook signing secret in the deployment credential store,
never in source control, browser code, chat, or command-line arguments.

Sandbox and production may have different account IDs. Set
`STRIPE_TEST_ACCOUNT_ID` and `STRIPE_LIVE_ACCOUNT_ID` separately. The older
`STRIPE_ACCOUNT_ID` remains a fallback for either environment when its specific
ID is empty. Existing sandbox orders always retain their sandbox account/key.

Create a snapshot webhook endpoint at
`https://api.pornfetch.to/stripe/webhook` (the deployment's `API_DOMAIN`) with API version
`2026-10-28.endive`. Subscribe to:

- `checkout.session.completed`
- `checkout.session.async_payment_succeeded`
- `checkout.session.async_payment_failed`
- `checkout.session.expired`
- `charge.refunded`
- `charge.dispute.created`
- `charge.dispute.closed`

An endpoint inheriting the account's default event version is also supported:
the webhook only uses event references to queue reconciliation, and authenticated
payment reads explicitly use `2026-10-28.endive` regardless of event version.

The endpoint verifies the raw-body signature, a five-minute timestamp tolerance
and the signing secret's environment. Events queue an authenticated provider read;
redirect query parameters and event payment-status fields cannot issue licenses.
Unknown references are acknowledged without provider calls. Configure independent
webhook endpoints and signing secrets for sandbox and production.

## Migrations and worker

Apply migrations before deploying the application. Revision `b871f925a603` creates
independent Stripe grant/checkout tables and merges the three existing tracked
migration branches. It does not depend on the unrelated, unfinished local
`6a402c11e905_checkout_evidence_and_withdrawal.py` migration. If that local migration
is also retained, resolve the resulting migration heads and its model drift before
production deployment; do not blindly apply all local files.

Schedule `flask --app main process-stripe-payments` every minute. Systemd examples
are provided in `deploy/eaf-stripe-payments.{service,timer}` and
`deploy/rootless/pornfetch-stripe-payments.{service,timer}`. Install the pair matching
the production layout. The worker creates/retries durable sessions, verifies
payments and retries license/email delivery independently of visitors. It continues
reconciling orders when new checkout access is disabled, provided their credentials
remain available.

Test: unlock checkout; create a payment; save the private recovery link; pay with
Stripe test details; verify exactly one license and benefit confirmation, a
license delivery email without a duplicate seller invoice, and the receipt or
tax invoice supplied by Stripe / Link; test expiry, duplicate webhooks, refund/dispute notifications
and temporary provider/email outages. Payment creation retries retain their payload
and idempotency key. Ambiguous creation after 55 minutes requires manual review,
preventing a fresh second session after provider idempotency retention expires.

Refunds are initiated through Stripe's Dashboard; this change does not add a refund
administration UI or automatically revoke licenses after reversals. Reversals are
recorded from authenticated charge reads and prevent new fulfillment when observed
before license issuance. Finished orders are refreshed by reversal notifications;
provider-dashboard review is needed for missed events.

## Go live after account setup

For the rootless production stack, install a reviewed root-owned copy of
`deploy/configure-stripe.py` and provide the private settings as a JSON object
on stdin. It validates separate test/live keys and account IDs, backs up the
running deployment, encrypts the credentials with the existing systemd host/TPM
mechanism, and prepares the installed web Quadlet. It explicitly disables new
Mollie checkouts and public tester access. It does not restart the web service.
No private configuration or secrets belong in GitHub.

Push the tested application commit to GitHub, then use `pfctl update web` on
the origin so the deployment is built from that exact published commit. After
successful migration and health checks, install the Stripe worker service/timer
from the same commit under the `pornfetch` account's systemd user directory and
enable `pornfetch-stripe-payments.timer`. Check the public Checkout page, webhook
signature rejection, worker status, and recorded deployed commit against GitHub.

Set `STRIPE_LIVE_ACCOUNT_ID=acct_...`, `STRIPE_LIVE_API_KEY=rk_live_...`
(or `sk_live_...`) and the production endpoint's
`STRIPE_LIVE_WEBHOOK_SECRET=whsec_...`, then explicitly enable
`STRIPE_LIVE_ENABLED=true`. The flag, key, signing secret and account ID are all required.
Disable tester access if no longer needed. `/porn_fetch` then serves public Stripe
checkout, with crypto/Patreon alternatives. Existing sandbox orders keep their
sandbox credentials and documents. Setting the live flag false removes public
checkout without losing existing order recovery.

Provider references:
- https://docs.stripe.com/api/checkout/sessions/create
- https://docs.stripe.com/checkout/fulfillment
- https://docs.stripe.com/webhooks
- https://docs.stripe.com/payments/managed-payments/update-checkout
- https://docs.stripe.com/payments/managed-payments/how-it-works
