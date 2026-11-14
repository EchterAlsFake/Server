# v3.9 website and diagnostic receiver deployment

Completed on 8 November 2026, after the owner's deployment request. The TPM
units were left unchanged, as requested. NOWPayments remains in provider sandbox
mode; local payment simulation remains disabled. No live payment, customer
license issuance or customer email was triggered by deployment verification.

## Website

- Deployed source snapshot `9ff693d042f77c7439d781dc00b6c64a9ee68b5e` through
  the existing `pfctl` build, test, backup, migration and activation flow.
- The candidate image ran all 314 server tests successfully, with one optional
  live integration test skipped. A coordinated pre-cutover backup was taken.
- Applied database revision `e8b42f930d16`, adding the browser lookup table.
- Refreshed the Tor exit list, installed the hourly user timer and registered
  it in the standard maintenance lifecycle. The active list contained 2,296
  addresses at verification.
- Public checks confirmed the v3.9 pages, VAT ID, Patreon receipt-ID form and
  private-cache headers. Fifteen representative public pages returned HTTP 200.
- Trusted-loopback requests representing a known Tor exit received HTTP 403
  for crypto checkout creation, card-to-crypto creation and the donation widget.
- Missing CSRF tokens were rejected for activation and checkout. An unrelated
  browser session received an expired lookup status without a license.
- A read-only Patreon sales scan completed successfully and found an eligible
  order with a public receipt ID. No customer's credentials or key were printed.
- The lifetime Keygen policy still matches the app. Both the web application
  and the diagnostic receiver report healthy containers.

The exact snapshot was transferred to the server without pushing to GitHub.
The remote Server checkout was fast-forwarded to the deployed commit. The local
working branch and staging area were preserved; the snapshot is retained under
a local `refs/codex/deploy-v39-*` reference. Reconcile/push that snapshot before
using the regular upstream update flow: its ahead-of-upstream check prevents an
accidental deployment of older upstream code.

## Diagnostic receiver

- Updated the rootless PocketBase hook and installed
  `1793750400_full_error_reports.js` in both infrastructure source and runtime.
- Applied the migration explicitly with the existing sealed encryption
  credential. The message maximum is 1,048,576 and collection CRUD rules remain
  locked.
- Increased only the `/error_log` proxy body limit to 1,048,576 bytes. Caddy
  passed validation with its real sealed credentials in isolated network/storage
  before reload. Existing ECH, TLS, routing and proxy trust configuration were
  preserved.
- Created a stopped, consistent receiver rollback copy and matching hook,
  migration, proxy and maintenance-tool copies. Recovery locations are recorded
  privately on the server under the managed rollout state.
- All eleven isolated receiver tests passed, including verbatim tracebacks,
  UTF-8 byte boundaries, oversized chunked requests, access restrictions,
  rate limiting and the 100,000-record storage ceiling.
- Public checks returned GET 405, invalid schema 400, wrong content type 415,
  a full synthetic report 204 and an oversized body 413.
- The 9,390-byte synthetic traceback, including its URL, query string and Unicode,
  was verified unchanged in storage. Only that exact synthetic record was then
  removed from the active collection. Existing customer diagnostics were left
  intact. A minute backup could retain the harmless synthetic test data under
  the normal backup-retention rules.

The current public diagnostic endpoint is
`https://api.pornfetch.to/error_log`.

## Final operational checks

Managed files match the infrastructure source. There are no failed application
user units. Payment receipt, license delivery, withdrawal, Patreon and Tor timers
are active. Recent local backups and NAS replication report healthy status.

The remaining commercial steps are configuration of the published Patreon product
URL, deliberate activation of live payments with the corresponding credentials,
and building/publishing the actual v3.9 app artifacts. The previously documented
Patreon policy and disaster-recovery limitations remain separate from this rollout.
