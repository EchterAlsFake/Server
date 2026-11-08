# Production infrastructure review, 8 November 2026

This review used SSH and privileged metadata checks against the production origin.
It did not deploy code, change payment modes, create payments, issue licenses or
read customer records. Secret values were excluded from the output. The review
supplements the [v3.9 release review](V39_RELEASE_REVIEW.md).

My assessment is approximately **90/100 for infrastructure**, and **85/100 for
overall release readiness** while the prepared changes remain undeployed. These
are engineering judgments, not a certification or availability guarantee.

## Verified strengths

- The web application, Keygen API and worker, PostgreSQL, Redis, PocketBase and
  dashboard services are running. Container health checks are healthy where
  supplied. The application user manager reports no failed units; the inspected
  services report no automatic restarts.
- Application backends bind to loopback or the internal container network.
  The web processes run as the unprivileged app user in a rootless user namespace.
  Inspected containers are not privileged and enable no-new-privileges.
  Container root filesystems remain writable; the bootstrap container-user value
  is root, so process identity was checked separately for the web application.
- Main ingress requires PROXY protocol before TLS, replaces forwarding headers,
  uses TLS 1.3 and HTTP/1.1–2, and forwards to loopback backends. The separate
  public IPv6 listener is scoped to the direct-download hostname.
- The firewall has default-drop input and forwarding chains, with explicit
  interface/source restrictions for administration and backend access.
- WireGuard, Rosenpass, Tor and the onion proxy are active. The host reports
  approximately thirteen days of uptime and 28% filesystem utilization.
- Production uses shared Redis rate limits, a local GeoIP database, encrypted
  delivery credentials and TLS for SMTP. Required payment, license, email and
  release-publishing credentials are present in the runtime wrapper; their
  values were not printed. Presence does not prove live-provider validity.
- A read-only Keygen query verified the permanent licensing policy, including
  null duration, ten installations, ED25519_SIGN, priceEur 29.99 and the
  permanent commercial model. Its policy ID matches the application's public
  configuration.
- Scheduled payment receipts, crypto delivery, withdrawal and Patreon jobs are
  active. The most recent recorded Patreon verification succeeded about four
  hours before the audit, with no recorded verification failure or backoff.
- The backup timer runs every minute. Recent local snapshots completed in
  approximately 14–15 seconds, with successful NAS replication shortly after.
  The recorded restore rehearsal from 7 November checked SQLite integrity,
  resealing and round-tripping 38 portable credentials, PostgreSQL restoration,
  Redis recovery, Weblate recovery and required distribution/proxy/onion files.

## Remaining release work

1. **Deploy the prepared website changes.** The running image still lacks the
   Tor checkout module, Tor exit data/timer, browser license lookup and VAT ID.
   The live database is at `e1839c02aa41`; the new lookup migration is
   `e8b42f930d16`. The active release record identifies Server commit
   `74ec504c486c85b4d81ee98a2988b62e78860fec`.
2. **Deploy the diagnostic receiver update together.** The active Caddy route
   for `api.pornfetch.to/error_log` has a 4,000-byte limit. The current app's
   optional Full reporting requires the prepared 1 MiB proxy limit, PocketBase
   hook and message-field migration. See [the receiver deployment guide](../deploy/pocketbase/README.md).
3. **Finish the commercial channel configuration.** NOWPayments is correctly
   still in sandbox, with local simulation disabled. Patreon is enabled but
   its configured URL is not a specific Shop product. Before live startup with
   the new code, configure the published product URL/variant or leave Patreon
   purchases disabled. The actual production webhook origin is
   `https://api.pornfetch.to`, so the NOWPayments callback is
   `https://api.pornfetch.to/nowpayments-ipn`.
4. **Publish the actual app build.** The public website catalog has no releases.
   Synthetic publisher tests do not replace the real build, artifact review,
   signing and publication workflow.

## Operational limits

- Restore records explicitly say replacement-hardware and offsite recovery have
  not been tested. NAS replication is verified; it is not proof of geographically
  separate disaster recovery. A recovery-key escrow confirmation is recorded.
- Routine minute snapshots are hot backups (`coordinated=false`). Their success
  does not prove a single transaction-consistent recovery point across every
  service. Use the deployment helper's coordinated pre-cutover snapshot for
  application updates.
- Four host units remain failed: `systemd-pcrlogin@1000`,
  `systemd-pcrlogin@1001`, `systemd-pcrproduct` and
  `systemd-tpm2-setup-early`. TPM2 support itself reports available, and the
  application credential wrapper works. The cause and reboot implications of
  those failures were not established by this review.
- Software-download logs hash IP fields and remove headers/query data. They
  therefore retain pseudonymous download metadata, as described in the privacy
  policy; this is not a blanket no-access-log deployment.
- The known Patreon private-sales API policy conflict remains. No new Patreon
  sales scan was requested during this audit; the existing health record was read.

No release or live-payment approval is implied while these rollout items remain.
