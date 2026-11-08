# Porn Fetch 3.9 release review

Reviewed on 8 November 2026 against the local application source at commit
`b763aa1`. Changes in this report are prepared in the Server working tree;
they have not been deployed to production or used to take a real payment.

## Result

The website implementation now supports the commercial €29.99 lifetime offer,
enforces its checkout declarations on the server, blocks new cryptocurrency
checkout for identified Tor exits, and supports receipt-authenticated Patreon
license retrieval in the browser.

An unconditional legal or operational launch clearance is **not established**.
The subsequent [SSH infrastructure review](INFRASTRUCTURE_REVIEW_2026-11-08.md)
verified the running services, proxy, backup records, runtime configuration and
permanent Keygen policy. It also confirmed that these website changes are not
deployed and that the diagnostic receiver still needs its v3.9 update. Actual
live-provider settlement, inbox delivery and new release binaries remain
unverified. Patreon verification still uses a private sales endpoint without
provider authorization.

## Changes

- Both legal-disclosure translations and new invoices include VAT ID
  **DE463457168**. New invoices use the VAT ID instead of the former tax-number
  field; older stored invoices retain their original details.
- Author-facing copy uses I/my and ich/mein. The statutory model withdrawal
  form retains its consumer-side “I/We” wording; it is not a statement by the
  seller. Blanket liability exclusions in the disclosure and API documentation
  have been replaced by wording preserving statutory responsibilities.
- Marketing and guides describe 3.9, the fifteen actual providers, the 720p /
  one-download / five-public-video free limits, account-collection exception,
  ten-installation lifetime entitlement and platform limitations. The terms
  now describe the application's actual private sharing permission. CLI
  instructions mention signed self-updates; portable GUI updates remain manual.
- The shared EUR price is 29.99. No current product copy advertises EUR 19.99.
  Existing historical transaction/contract snapshots are not rewritten.
- Live mode omits sandbox acknowledgments and previews. The live crypto button
  clearly names the paid order and price. The Patreon handoff uses the configured
  specific product URL, retains the required website declarations, and explains
  receipt-based recovery. A Shop homepage is rejected as the live product URL.
- Saved consent expires after one hour and is bound to the payment route,
  country, database evidence and current offer text. Boolean JSON fields alone
  cannot replace it. Changes to the offer require fresh consent. A read-only
  lifetime-policy check runs before creating a NOWPayments invoice.
- Both the onion service and identified exits visiting HTTPS cannot create
  crypto payments. This includes the optional card-to-crypto route and donation
  widget. Unknown routes or an unavailable/stale exit list fail closed. Payment
  recovery remains readable, but does not expose a payment continuation link
  over Tor. No visitor address is sent to the Tor Project or saved by this check.
- `/activate` accepts purchase email plus the public order ID from the Patreon
  receipt for browser retrieval. The worker checks both against one eligible,
  fulfilled, unrefunded purchase of the configured product. Internal order IDs,
  email-only requests and unverified outage claims cannot reveal a key. The
  existing purchase mapping prevents a second license on repeat requests.
- Browser lookup records retain keyed lookup values, a random session-bound
  request ID, time, state and license association. Browser access lasts fifteen
  minutes. The worker removes expired records. Pages, status and download
  responses use no-store/no-referrer; forms and downloads require CSRF tokens.
- New email claims wait during verification outages instead of receiving free
  licenses. Existing license and historical fallback records are preserved.
- New fields fit narrow screens, support browser autocomplete and native input
  validation, and retain visible keyboard focus. Mobile navigation starts closed
  without JavaScript. Device safe areas and reduced motion are respected.
  License files use a binary attachment type so WebKit saves them instead of
  opening their JSON as a page.

## Deployment and activation

1. Back up the application database and stable encryption/lookup keys. Deploy
   this complete source tree, including generated `docs/dist`, and apply
   `python -m flask --app main db upgrade`. The new revision is
   `e8b42f930d16`, after `e1839c02aa41`; it adds only browser lookup records.
2. Run `python -m flask --app main update-tor-exits`. Install and enable the
   supplied hourly timer: `pornfetch-tor-exits.timer` for the rootless Podman
   deployment, or `eaf-tor-exits.timer` for the legacy deployment. The list is
   unusable after twenty-four hours. A failed refresh preserves the previous
   file; it never silently disables the block. The timer needs the same data
   volume as the web process. Do not put this file under `static/`.
3. Retain the minute Patreon Shop worker and the NOWPayments receipt,
   license-delivery and withdrawal workers. The Patreon worker now processes
   browser requests as well as emails. Confirm its health and cookie validity
   with the read-only `verify-patreon-shop` command. Keep the lookup key stable.
4. Set the published Patreon product's EUR price to 29.99, copy its specific
   product URL to `PATREON_SHOP_PRODUCT_URL`, and set the matching
   `PATREON_SHOP_PRODUCT_VARIANT_ID`. Prepare the listing using
   [PATREON_PRODUCT_V39.md](PATREON_PRODUCT_V39.md). Do not assume website consent
   automatically applies to a purchase made directly on Patreon, or that
   activating a key by itself eliminates statutory withdrawal rights.
5. Configure production NOWPayments API and IPN secrets, SMTP and the stable
   delivery encryption key, Redis, Keygen's lifetime policy, the local GeoIP
   database and HTTPS origins. Configure the IPN URL as
   `https://api.pornfetch.to/nowpayments-ipn`, matching the verified production
   `API_DOMAIN`. The proxy must replace inbound
   forwarding headers with the real connection address and keep the app
   listener private. Tor detection is not meaningful if it receives the proxy's
   address instead of the visitor's.
6. Run `python deploy/preflight.py` in the actual deployment environment. It
   checks configuration, reviewed email catalogs, GeoIP and Tor data without
   sending emails or creating transactions. Also run:

   ```sh
   python -m flask --app main verify-license-policy --client-config /path/to/Porn_Fetch/src/licensing/production.json
   python -m flask --app main verify-patreon-shop
   ```

7. Switch `NOWPAYMENTS_SANDBOX=false` and keep
   `NOWPAYMENTS_LOCAL_SIMULATION_ENABLED=false`, then restart the web process.
   `PATREON_SHOP_ENABLED=true` requires the real product URL in this mode.
   Confirm the live pages, signed webhook receipt processing, durable delivery,
   withdrawal acknowledgment and known Tor-exit block in that environment.
   Local synthetic verification does not establish real provider settlement or
   inbox delivery. Do not send live funds to a sandbox invoice.

## Publishing the app

The public website catalog returned no releases during this review. The public
CLI target metadata reported 3.8.1. Neither observation proves that a new v3.9
binary has been built or tested.

The existing application workflow supports publishing both destinations. Use a
fresh build of the reviewed app source, `release_version=3.9.0`, and the stable
website channel. The workflow's `create_release` and `deploy_website` inputs
control GitHub and website publication; repository/CLI update publication have
their own inputs and signing requirements. Complete the workflow's existing
artifact/legal review before setting its review flag. Recheck published version
metadata before dispatch if another build has been released in the meantime.

The server's staged publisher verifies each artifact's digest and size before
making the release catalog visible. No placeholder binaries, fake release
records or fabricated checksums were published during this audit. The app's
build/signing/device checks remain the responsibility of its release workflow;
this website review does not replace them.

## Verification

- Server suite: 314 tests run successfully; one optional live Keygen integration
  test was skipped because no live test credentials are configured.
- Chromium, Firefox and WebKit: 42 public pages at six viewport sizes each
  (756 page/viewport checks), from 320px phones to 1440px desktops. Live consent,
  Patreon handoff, receipt-based recovery, license download, Tor blocks, reduced
  motion, touch-screen video loading and no-JavaScript forms also passed.
- Independent download browser suite: synthetic CI publication, artifact digest
  checks, downloads, platform/architecture selection, installers and no-JavaScript
  access passed.
- Changed Python files: Ruff and compilation passed. The promo source passed
  ESLint/TypeScript checks.
- Installed server environment: pip-audit reported no known vulnerabilities.
- Re-rendered the forty-second product tour to correct the ISP privacy claim.
  The website copy is H.264, 1920×1080, 60 fps, 2,400 frames, no audio, with
  fast-start metadata; eleven decoded frames matched reviewed stills with
  SSIM above 0.98. The web file is approximately 4.4 MB. Phones, touch screens,
  reduced-motion and reduced-data settings do not automatically load it.
The deterministic server suite includes the new migration and browser-proof,
live-consent, changed-offer, policy-outage and Tor boundaries. Browser checks
use synthetic purchases and block external traffic; the Tor updater was also
checked against the live Tor Project endpoint (2,296 addresses).

## Legal and provider limits

- [DDG § 5](https://www.gesetze-im-internet.de/ddg/__5.html) requires disclosure
  of an existing VAT identification number; the supplied ID has been added.
- [BGB § 312j](https://www.gesetze-im-internet.de/bgb/__312j.html),
  [§ 312f](https://www.gesetze-im-internet.de/bgb/__312f.html) and
  [§ 356(6)](https://www.gesetze-im-internet.de/bgb/__356.html) were checked for
  order wording, durable confirmations and the conditions for ending digital
  withdrawal rights. The existing electronic withdrawal flow remains available.
- [Patreon's security policy](https://www.patreon.com/policy/security) requires
  checking with Patreon before automated scraping for a feature. The private
  `/api/sales` integration has no such authorization; its successful operation
  does not resolve this policy conflict.
- [Patreon's current Shop guidance](https://support.patreon.com/hc/en-us/articles/16303719836813-Selling-one-time-purchases-on-Patreon)
  supports one-time purchases and the creator's ninety-day refund window.
  Mandatory refund rights and deadlines are not limited to that window.
- The existing § 19 UStG treatment and country-evidence approach are preserved.
  A VAT ID alone neither confirms nor disproves eligibility for that treatment.
  Tax status, cross-border obligations and the deployed data-retention practice
  have not been independently established by editing these pages. See the
  existing country-compliance and privacy operations documentation.
- Tor detection covers the onion service and addresses in a fresh public exit
  snapshot. An additional VPN/proxy can conceal a Tor exit. An already issued
  provider invoice may also be reachable directly on the provider's website;
  this server cannot control that external checkout.
