# Mollie legal integration — 15 November 2026

This is an implementation and source-review record, not a lawyer's opinion or a
certification of legal compliance. The review concerns adding Mollie to existing
policies, checkout evidence and contract confirmations. Historical accepted terms
are retained; uncommitted older policy prototypes are not deployed.

## Primary sources checked

- [Mollie privacy statement](https://www.mollie.com/legal/privacy), dated
  2 November 2026, and its [German version](https://www.mollie.com/de/legal/privacy):
  provider processing, retention, cookies, automated decisions and transfers.
- [Mollie controller guidance](https://help.mollie.com/hc/en-us/articles/360002761193-Do-I-have-to-sign-a-data-processing-agreement-with-Mollie):
  the Payments integration is an independent-controller relationship; it must
  not be described as the merchant's instructed processor or confused with
  Mollie's separate Invoicing product, which this application does not use.
- [Dutch central-bank register](https://www.dnb.nl/en/public-register/information-detail/?registerCode=WFTEG&relationNumber=F0038):
  registered Mollie B.V. address is Keizersgracht 126, 1015 CW Amsterdam.
- [Mollie refunds documentation](https://docs.mollie.com/docs/refunds):
  merchant-initiated refunds and independent refund statuses; insufficient
  merchant funds can queue a refund. The website must not claim that such a
  queue extends a consumer's legal deadline or that a request is already paid.
- [Mollie refund support](https://help.mollie.com/hc/en-gb/articles/115000014489-How-do-I-refund-a-payment):
  provider processing windows and fees are operational matters, not a reduction
  in statutory rights or a fee automatically passed to a consumer.
- [BGB § 357](https://www.gesetze-im-internet.de/bgb/__357.html):
  withdrawal reimbursement timing and original payment method.
- [BGB § 327n](https://www.gesetze-im-internet.de/bgb/__327n.html) and
  [§ 327o](https://www.gesetze-im-internet.de/bgb/__327o.html):
  digital-product price reduction and termination reimbursements.
- [BGB § 356](https://www.gesetze-im-internet.de/bgb/__356.html) and
  [§ 312f](https://www.gesetze-im-internet.de/bgb/__312f.html):
  immediate digital supply, withdrawal conditions and durable confirmation.
- [BGB § 312j](https://www.gesetze-im-internet.juris.de/bgb/__312j.html):
  clear payment action and prominent essential information before ordering.
- [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng), especially Articles
  5, 6, 13, 15–22 and Chapter V: transparency, purpose-specific legal bases,
  retention criteria, rights and international transfers.

## Implementation decisions

Mollie refunds use the original method; crypto/Patreon alternative-refund
agreements explicitly exclude Mollie. The policy preserves statutory remedies,
withdrawal conditions and provider/bank dispute rights. No blanket loss of
withdrawal rights on payment, blanket “no refunds”, forced cryptocurrency refund,
consumer processing-fee deduction or provider-window statutory cutoff is added.

The privacy wording follows the actual Payments API payload, response handling,
encrypted email/outbox, country/Tor checks, necessary checkout session/grant
records, rate limits, recovery links and manual retention processes. Delivery
email is not in the payment-creation request. Responses are processed in memory;
the integration does not persist full responses or collect card/CVV/bank-login
fields on the merchant page. Mollie receives the actual product description.
No claim of exclusively EU processing, anonymous payments or automatic erasure
of all order records after seven days is made.

The English Mollie refund partial is shared by the public refund policy and
accepted terms. The German summary uses a corresponding translation. Mollie
snapshots include these rules in `terms_en`, while the separately accepted crypto
refund field stays empty/false. Bumping the contract version invalidates stale
forms; existing order snapshots and saved PDFs are not rewritten.

## Operator responsibilities and remaining review

Refunds remain manual through the Mollie dashboard. Maintain funds sufficient
for owed refunds, follow failed/queued refunds, and meet statutory deadlines.
Payment notifications record reversal amounts but do not automatically revoke
licenses; legal consequences of termination and any credential revocation require
individual handling. No refund or charge was triggered by this policy update.

Privacy requests, order-email erasure, claims evidence and statutory accounting
retention require manual review. The notice describes that fact; wording does not
create an automated retention system. Keep disclosure and actual operations in
sync and apply retention/deletion processes to backups and correspondence too.

A qualified adviser should review the full sales model, contract formation,
English-language contracting, cross-border consumer rules/tax treatment, digital
content versus any service components, and the end-to-end hosted ordering and
confirmation sequence. Mollie's acceptance of the actual downloader business is
a separate question; these policy changes do not establish provider approval.
