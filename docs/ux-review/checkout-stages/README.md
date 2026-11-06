# Shared confirmations and crypto-only country collection

The Legal label now links to the legal information page. The payment-method
picker contains exactly three shared declarations: age/terms, the separate
cost-free cryptocurrency refund agreement, and the test-checkout acknowledgment.

Country/tax information and immediate-supply consent appear on the crypto page.
The shared crypto selection is temporary session state, not authorization to
create a payment. The crypto confirmation step requires a valid country, explicit
supply consent, unexpired shared confirmations and the accepted offer digest.
The existing local country check still runs before provider payment creation.
Changes to country after a failed attempt require fresh crypto confirmation.

Patreon does not request or store a tax-country declaration. Its instructions link
directly to https://pornfetch.to/activate. The redundant activation sentence and
receipt section are removed from both the dialog and the no-JavaScript handoff.
The internal receipt endpoint and stored consent evidence are retained.

## Verification

159 tests passed across checkout stages, payment refresh, contracts, country
compliance, payments, Onramp, Patreon Shop, marketing and application behavior.
New coverage checks pending-selection isolation, explicit crypto consent, stale
offers, expiry, CSRF and separation between Patreon and crypto confirmations.

Playwright MCP checked 1440 × 900 and 390 × 844: Legal link navigation, exactly
three shared checkboxes, Patreon without country, dialog content, Cancel/focus,
crypto field placement and submission, and absence of horizontal overflow.
The final provider-payment request was intercepted in browser validation; no
external payment was created. The no-JavaScript Patreon handoff was also checked.

| Page | Desktop | Mobile |
| --- | --- | --- |
| Shared checkout | [View](shared-desktop.png) | [View](shared-mobile.png) |
| Crypto checkout | [View](crypto-desktop.png) | [View](crypto-mobile.png) |
| Patreon dialog | [View](patreon-desktop.png) | [View](patreon-mobile.png) |
