# Keygen operations

Production: `/srv/keygen`; API: `https://licenses.echteralsfake.me`.
The loopback API listens on port 8004. PostgreSQL and Redis have no host port bindings.
Docker restarts all four services after reboot. Caddy manages TLS through the existing
DNS challenge and relay arrangement. Public routes accept only license credentials;
administration uses local operator commands.

The image is pinned by digest. Its Docker tag is `keygen/api:v1.7.2`, while its startup
banner reports Keygen 1.8.0 revision 055c872. Treat the recorded digest as the deployment
identity; do not silently upgrade using a moving tag.

## Configuration

The private `.env` and `postgres.env` contain generated credentials. Account signing keys
live in PostgreSQL; Rails encryption keys live in `.env`. Preserve both together.
`credentials/product.json` contains the product API token and public integration IDs.
The purchase service has the token and policy ID in its own restricted `.env`.
`license_client/production.json` is the public-only copy intended for shipping.

The product token has the product's CE permissions and no expiry; rotate it explicitly
by creating a replacement locally, updating the purchase service, verifying issuance,
and revoking the old token. CE does not provide EE's granular permission management.

The bootstrap script provisions a protected perpetual Ed25519 policy, strict with ten
machines, license authentication, no heartbeat or check-in requirement, and unique UUIDs
per license. Do not regenerate the account or signing keys during deployment.

The `Gemfile` override retains bundled telemetry dependencies so the upstream image's
frozen lockfile remains valid when NO_SENTRY and NO_JUDOSCALE are set. Their runtime
integrations remain disabled. `privacy.rb` disables request logs, suppresses operational
message contents, caps checkout TTL at seven days, and serializes machine writes under
a PostgreSQL license-row lock. Re-test these overrides on every image upgrade.

Redis is an ephemeral cache and background queue. Restarts can discard internal jobs;
purchase issuance/delivery retry state remains in the purchase database. No customer
emails are sent by Keygen. The existing purchase service still sends Patreon email.

## Routine checks and support

```sh
sudo docker compose --project-directory /srv/keygen ps
curl -fsS https://licenses.echteralsfake.me/healthz
sudo systemctl status eaf-keygen-backup.timer
sudo /srv/server/.venv/bin/python /srv/keygen/admin.py machines LICENSE_UUID
sudo /srv/server/.venv/bin/python /srv/keygen/admin.py deactivate MACHINE_UUID
sudo /srv/server/.venv/bin/python /srv/keygen/admin.py suspend LICENSE_UUID
sudo /srv/server/.venv/bin/python /srv/keygen/admin.py reinstate LICENSE_UUID
```

A license UUID is in its signed key and in the purchase database's `keygen_id`.
Support must verify purchase ownership through the existing channel before resetting
someone's installation. Do not request hardware identifiers.

## Backups and recovery

The daily timer creates authenticated AES-256-GCM encrypted archives under
`/srv/keygen/backups`, retains seven days, and also runs after a missed scheduled time.
The decryption key is `/srv/keygen/backup.key`. Copy encrypted archives off this server
and store that key separately using your chosen secure storage; local backups alone
cannot recover a lost disk. No external destination was configured.

Archives contain Keygen's PostgreSQL dump, deployment/configuration/signing-encryption
secrets, product token, and a snapshot of the purchase database and environment.
They do not replace the website's full deployment/invoice backups. SQLite is captured
before PostgreSQL so completed issuance identities are included in the later Keygen dump.
Recovering older snapshots can lose recent activations/payments; reconcile provider
events and local issuance identities before reopening fulfillment.

```sh
sudo /srv/server/.venv/bin/python /srv/keygen/backup.py backup
sudo /srv/server/.venv/bin/python /srv/keygen/backup.py extract \
  --archive /srv/keygen/backups/TIMESTAMP.aesgcm \
  --destination /srv/keygen-recovery --key /srv/keygen/backup.key
```

Extraction authenticates before writing and requires a new protected destination.
For a rehearsal, change the extracted Compose project name and loopback port, start its
PostgreSQL/Redis, restore `keygen.dump` using `pg_restore --no-owner --exit-on-error`
into the empty database, then start web/worker. Never run `keygen:setup` over a restored
or populated database. Check a previously issued signed key and perform an activation.
The repository's `scripts/test_keygen_live.py` tests an isolated restored instance.
Remove only that disposable project and its files/volumes when finished.

For production recovery, stop purchase issuance first, restore matched deployment and
database snapshots with the same account keys, check health and issuance reconciliation,
then reopen the purchase service. Restoring website code and its database together uses
the existing `eaf-deploy` rollback procedure.

## Updates

Keep source changes under `deploy/keygen`; install reviewed overrides into `/srv/keygen`.
Take a backup first. Test candidate image and migration on a restored isolated project,
including simultaneous activations, signed permits, privacy logs, and issuance retries.
Change the pinned image digest, migrate once, then restart web/worker. Roll back code and
database together if a migration was applied.

Deploy purchase code with `sudo eaf-deploy server`. Preserve existing sandbox/live mode
and provider credentials. No schema-1 license compatibility is provided.
