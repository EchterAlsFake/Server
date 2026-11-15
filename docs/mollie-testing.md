# Private Mollie sandbox checkout

Patreon and NOWPayments retain their current configuration. Mollie is disabled by
default and never accepts a live API key. The production Keygen lifetime policy
issues real licenses; `lifecycle=test` records provenance and does not reduce validity.
Simulated refunds and chargebacks are recorded without revoking those licenses.

## Configure and deploy

1. Back up the database, deploy code, and apply the additive migration:
   `python -m flask --app main db upgrade 7d921a6c0b53`.
2. Configure the profile-specific Mollie **test** API key in `MOLLIE_TEST_API_KEY`,
   and `MOLLIE_PROFILE_ID=pfl_QGqZL2B4xY`. No organization MCP credential is used
   by the application. SMTP and `LICENSE_DELIVERY_ENCRYPTION_KEY` must already work.
3. Generate a strong tester password and its hash locally (the prompt does not echo):

   ```sh
   .venv/bin/python -c 'import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass.getpass("Tester password: ")))'
   ```

   Set the resulting hash as `MOLLIE_TEST_PASSWORD_HASH` in the private environment
   file. Set `MOLLIE_TEST_ENABLED=true` and restart the app. Invalid configuration
   hides/disables only this experiment. Use Redis for shared rate limits across workers
   (`RATELIMIT_STORAGE_URI`), as for the existing payment routes.
4. Install `deploy/eaf-mollie-payments.service` and `.timer` alongside the existing
   service units, then `systemctl enable --now eaf-mollie-payments.timer`. It runs
   `python -m flask --app main process-mollie-payments` every minute. Existing
   delivery timers can continue unchanged. For the existing rootless Podman
   deployment instead, install `deploy/rootless/pornfetch-mollie-payments.service`
   and `.timer` in the same user service directory as `pornfetch-web.service`,
   then run `systemctl --user enable --now pornfetch-mollie-payments.timer`.
   Use the deployment's existing container wrapper to run the migration/configuration
   steps in the web container.
5. Open `/porn_fetch`, expand **Tester access**, and enter the password. Review
   the required email, country and consent. Save the private recovery link, open
   Mollie checkout, and select a simulated successful result. Confirm the real
   signed license downloads and the test email arrives. No actual money is paid.

Every unlock allows one order for fifteen minutes. Creation retries reuse that
order, payload and idempotency key. A new test requires unlocking again. Rotate the
password hash to invalidate unused unlocks. Locking access does not remove order
recovery. Set `MOLLIE_TEST_ENABLED=false` to stop new tests while existing orders
continue reconciliation and delivery with the configured test key.

The API webhook is `API_DOMAIN/mollie/webhook`, outside browser/password/CSRF
checks but restricted to the configured API hostname. It accepts only known payment
IDs and durably queues a read. The worker retrieves authoritative state from Mollie
and checks order, profile, test mode, payment ID, exact amount and currency. Only
`paid` can issue a license; `authorized` cannot. Repeated notifications and failed
SMTP/Keygen operations are retryable and reuse the same license identity.

## Operations and limitations

Check `systemctl status eaf-mollie-payments.timer` and service journal for deferred
processing. Inspect `mollie_checkouts.next_attempt_at`, `checked_at`, `attempts`,
`last_error`, and delivery status using trusted database tools; do not export
customer email ciphertext, recovery tokens, grants or secrets into logs. A growing
due backlog or repeated `provider_or_delivery_unavailable` requires attention.
`verification_failed` means no license was approved from that observation.

`creation_reconciliation_required` means the result of a creation request was
not recovered within 55 minutes. Automatic recreation stops before Mollie's
one-hour idempotency cache expires. Use the stored opaque order reference and
Mollie dashboard to investigate; do not blindly reset `first_attempt_at` or create
a replacement payment. Orders older than seven days stop automatic pending
reconciliation in line with recovery expiry; handle late payment issues manually.

The shared password permits issuance of real licenses. Its holders can simulate
success; keep it private. Browser and address rate limits reduce automated abuse
but are not individual tester accounts. Email validation checks format, not mailbox
ownership. Recovery links grant access to the license and documents.

Regional pricing is not active. `quote(country)` is the extension point; each
order stores its amount, currency, country and pricing version. New pricing rules
must preserve quotes already accepted and must be reviewed for applicable rules
before rollout.

Mollie's current policy excludes digital pornographic content and individually
assesses other activities. The profile's verified status does not confirm approval
of Porn Fetch's downloader business model. Obtain written confirmation about the
actual product and each intended method before planning a live release. This code
has no live-mode switch, and the password gate is not a compliance mechanism.

- https://help.mollie.com/hc/en-us/articles/115000939369-Which-products-and-services-does-Mollie-not-accept
- https://www.mollie.com/legal/user-agreement
- https://docs.mollie.com/reference/testing
- https://docs.mollie.com/reference/webhooks
- https://docs.mollie.com/reference/api-idempotency

## Local validation

`python -m unittest discover -s tests -p test_mollie.py` covers the server and
worker without external payments. `python scripts/test_mollie_browser.py` checks
the HTTPS checkout on desktop and mobile with CSRF enabled; payment-provider,
Keygen and SMTP calls are mocked and external browser traffic is blocked.

## Current production server (192.168.178.201)

The rootless production installation provides a root-owned helper at
`/usr/local/sbin/pornfetch-mollie`. The deployed application starts with Mollie
**disabled**. To supply credentials and enable private testing:

```sh
ssh -t asuna@192.168.178.201
sudo pornfetch-mollie configure
```

The hidden prompts request the profile-specific **test API key**, a new shared
tester password of at least sixteen characters, and password confirmation. Obtain
the test API key from the Mollie dashboard for the `pornfetch.to` website profile;
never use a live key. The configured profile defaults to `pfl_QGqZL2B4xY`.

The helper hashes the tester password using Werkzeug in the running container,
encrypts the API key and hash using the existing host+TPM2 systemd credential
scheme, and updates the live and infrastructure-source web Quadlets. It takes an
online backup first and briefly restarts only the web application. It preserves
NOWPayments, Patreon, SMTP, signing and data-encryption settings. Existing SMTP
and Keygen credentials supply real licenses and email delivery.

```sh
sudo pornfetch-mollie status
sudo pfctl status
```

Then open `https://pornfetch.to/porn_fetch`, expand **Tester access**, enter your
new tester password, and complete a sandbox test. The Mollie reconciliation timer
runs every minute. The webhook URL is
`https://api.pornfetch.to/mollie/webhook`; the application sets it per payment,
so a separate dashboard webhook subscription is unnecessary.

To close new tester access while preserving pending fulfillment:

```sh
sudo pornfetch-mollie disable
```

Run `configure` again to rotate the API key/password. Keep the same website
profile while payments are pending. Credential ciphertext files are
`server_mollie_test_api_key.cred` and `server_mollie_test_password_hash.cred` in
`/var/lib/pornfetch/.config/containers/systemd/credentials/`. Secret values are
never stored in unit definitions, source control, shell arguments or chat.

## Public checkout and final live switch

The production-ready checkout is available to password-unlocked testers at
`/mollie/test` while using the test key. Test orders remain visibly labeled and
retain sandbox wording in their documents. Public checkout at `/porn_fetch`
uses the new mobile layout automatically when BOTH `MOLLIE_LIVE_ENABLED=true`
and a separate valid `MOLLIE_LIVE_API_KEY=live_…` are configured. Crypto is a
secondary alternative; Patreon is under “Other options”. Existing purchase
activation and recovery routes remain available.

After deploying this version, the final activation on the rootless server is:

```sh
sudo pornfetch-mollie configure-live
```

The hidden prompt takes the live key, creates an online backup, encrypts it as
`server_mollie_live_api_key.cred`, updates source/live Quadlets and briefly
restarts the web service. Test credentials are retained. Each order continues
using the credential and verification mode for its original environment; the
live key is never substituted for a pending sandbox order. `status` reports
whether live checkout is enabled. `disable` closes live and test entry points
while retaining credentials and workers for pending delivery.

Live receipts, invoices, emails and recovery pages omit sandbox claims. The
existing test banner remains on genuine sandbox orders. Live refunds and
chargebacks are recorded; license revocation remains an operator decision and
is not automatic. Provider eligibility and a supervised first real purchase
remain separate from sandbox verification. No live payment is created by the
activation command itself.
