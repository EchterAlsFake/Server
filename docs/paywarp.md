# PayWarp checkout

PayWarp is an alternative to the recommended Patreon Shop purchase. It uses the
server's EUR lifetime price in integer cents. Only US and EU residents can start
checkout, with the same local country evidence and network checks as direct
crypto purchases. Email verification, phone, address and the EU Tax ID requirement
are explained before payment. Those verification checks happen at the hosted
provider; the documented API does not expose verification flags or a processor
selection field.

## Configuration

- Keep `tokens.env` at the project root, readable only by the service user. It is
  ignored by Git. `API_KEY` and `WEBHOOK_SECRET` in that file map only to
  `PAYWARP_API_KEY` and `PAYWARP_WEBHOOK_SECRET`. Explicit environment variables
  take precedence. Public key and push token are not needed by this integration.
- Every API call sends `X-Paywarp-Site-Url` using `PAYWARP_SITE_URL`, which
  defaults to `APP_DOMAIN`. It must match the origin registered in PayWarp
  (`https://pornfetch.to` for this site); PayWarp ignores a leading `www.`.
  This value is server configuration, never a visitor-controlled request header.
- Optionally set `PAYWARP_SITE_ID` in payment creation requests. It does not
  replace the required site URL header.
- PayWarp enables by default when both secrets exist and `NOWPAYMENTS_SANDBOX`
  is false. `PAYWARP_ENABLED=false` disables new purchases without disabling
  completion webhooks for existing orders. Explicitly enabling it in a sandbox
  still creates **real PayWarp payments**; there is no PayWarp simulation.
- Retain the existing license SMTP/encryption and Keygen configuration.
- On the PayWarp site registered for `APP_DOMAIN`, enable **Stripe (Link) only**,
  disable other providers/fallback routing, and configure the stated verification
  requirements. This cannot be enforced using the supplied API fields.
- Register `API_DOMAIN/paywarp-webhook` as the site's webhook URL with the same
  site webhook secret. Use the actual HTTPS API origin, e.g.
  `https://api.echteralsfake.me/paywarp-webhook`. Return URLs use `APP_DOMAIN`
  and must match PayWarp's registered HTTPS site domain.

## Settlement and recovery

Orders are committed before contacting PayWarp. Retries from the same browser
with the same order details reuse the order reference, recovery token and
idempotency key. Provider failure never switches to a simulated payment. Opening
the return page cannot approve a payment.

Completion webhooks verify HMAC-SHA256 against the raw request body, signed event
ID and timestamp (within five minutes, including future skew). Webhook handling
then reads the payment from PayWarp and compares link ID, order reference, integer
amount and currency. Only completed, sufficiently paid orders can acquire the
existing database fulfillment claim. Duplicate notifications for a finished order
are acknowledged without issuing another license. Failures return a retryable
response; the existing license issuance reference prevents duplicate licenses if
an attempt is interrupted. Status polling can recover a missed webhook, with
provider checks limited to once a minute per order.

The existing encrypted delivery worker sends the license, invoice and confirmation.
Private recovery links also provide downloads. No new database tables are needed.
The site stores the delivery email encrypted and shares it with PayWarp for
checkout and receipts. Phone, address and Tax ID are entered at the provider.

## Validation

Run `.venv/bin/python -m unittest discover -s tests -p test_paywarp.py`.
The tests use mocked provider responses and never create a real charge.

### Authentication requirement confirmed (2026-11-17)

PayWarp support confirmed that site-bound API keys require both headers on
**every** API call:

```http
Authorization: Bearer <secret API key>
X-Paywarp-Site-Url: https://pornfetch.to
```

Without the site URL header, the API returned HTTP 401 with
`This API key is not valid for this site.` This was a missing site context, not
an invalid dashboard key or incompatible key prefix. The earlier suspicion of
a key-type or PayWarp-side binding problem was incorrect.

With the rotated key and the required header, both `/api/v1/ping` and
`/api/v1/providers` returned HTTP 200 with `ok: true`. The provider list includes
`smart` (Paywarp Smart) and `stripe` (Stripe US/EU). This list does not establish
which route is enabled for this site; retain the Stripe-only site configuration
requirement above. No live payment was created during validation.

The verified rotated credentials from `tokens_new.env` were copied to the ignored
`tokens.env` that the application loads. Existing explicit `PAYWARP_API_KEY` and
`PAYWARP_WEBHOOK_SECRET` environment values still take precedence and must also
be updated if configured. Restart the deployed service after updating code and
credentials. Webhook delivery and an end-to-end payment still need live validation.
