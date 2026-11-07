# Lifetime Premium deployment — 7 November 2026

The running website combines GitHub `main` through `0329e31` with the local
issuance and provisioning safeguards. The GitHub implementation is authoritative
for the offer, checkout wording, shared price constant, retired Patreon membership
webhooks, request security and documentation.

New purchases cost EUR 29.99 once and include Premium in all future releases.
The policy duration and new-license expiry are null. Activation, ten installations
and signed seven-day offline permits remain. There are no paid license renewals.
Card consent uses `banxa-lifetime-v1` and `lifetime_terms_acknowledged`.

The retained local changes explicitly request null expiry during issuance and
verify the saved policy on bootstrap instead of creating a policy with a new
name. New policy metadata matches the live permanent commercial model. The
container also includes generated documentation and the changelog used by update
routes; testing the actual built image caught the missing changelog.

## Live identity and image

Commercial policy: `7038281b-2429-4aa4-81db-4f04a87e7184`.
Metadata: `commercialModel=pornfetch-permanent-v1`, `priceEur=29.99`.
Account, product, signing keys and policy ID remain the same. No additional
Keygen configuration change or beta-license migration was made during this sync.

Web and migration image:
`localhost/pornfetch-server-sync@sha256:3424a98cb507f4d0439219613ae8869d01de0a7b168aa39c294ef20218401bb9`.
Build instructions are recorded in the infra repository at
`msi/podman/application/Containerfiles/pornfetch-server-sync.Containerfile`.
The build uses the merged public server sources and uv 0.13.7. It retains the
existing OS/native-library fixes, installs the committed dependency resolution,
and rebuilds Pillow against system libraries.

Both live Quadlets and their infra source copies select this image. The SQLite
schema is `e1839c02aa41`. Worker timers were stopped for the switch and restarted
after the migration and web health check. Runtime credentials, provider modes,
networking and release artifacts were preserved. NOWPayments remains sandboxed;
Banxa checkout remains disabled. Patreon membership webhooks have been removed and return HTTP 404;
the separate Patreon Shop activation queue remains enabled.

## Backup and verification

Pre-sync encrypted backup:
`/var/lib/private/pornfetch-licensing-backups/20261107T173823.537842Z.aesgcm`.
Authenticated decrypt, archive inventory and PostgreSQL dump catalogue verification
passed. The new migration also passed on an isolated copy of the live SQLite
state, with integrity checked afterward. Previous web and migration images remain
available locally. The migration is additive; rollback must preserve accepted
purchase evidence and must not discard later payments.

Validation passed: 301 server tests (one opt-in test skipped), the same suite
inside the actual deployment image, eight security tests under optimized Python,
Ruff, and both security and lifetime browser checks. Live verification checks the
public lifetime offer, documentation, retired membership webhook, current SQLite
schema and the read-only Keygen policy/client-configuration check.

The original pre-sync local changes remain recoverable in the named Git stash.
The current app source is handled separately by the other agent.
