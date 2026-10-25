# Porn Fetch onion gateway and Android updates

Public onion origin:
`http://pornfetchc5ct7s7uiervf4ziymmus5gy33gyqc6vkdtqyr5pbxrxmid.onion`

## Gateway deployment

Keep the live chain: Tor port 80 → dedicated Caddy on `127.0.0.1:18081` →
Porn Fetch container on `127.0.0.1:18080` → Gunicorn/Flask port 8000.
Integrate `deploy/pornfetch-onion.caddy` into the existing dedicated Caddy
configuration. It owns port 18081; merge its routes into the existing listener
instead of installing a second listener on that port. Keep the hidden-service
identity and keys in their existing Tor-managed storage.

Set `ONION_ORIGIN` to the origin above in the container's environment, without a
trailing slash. Keep `APP_DOMAIN=https://pornfetch.to` and the existing payment
`API_DOMAIN`. Rebuild the application image with the new Python dependencies.
No database migration is required for this feature.

The website container and both Caddy sites need the same persistent download
storage. Mount `/srv/pornfetch-downloads` read/write in the app and read-only in
Caddy, at the paths used by the Caddy fragments. Retain the directory ownership
and traversal permissions documented in `WEBSITE_DOWNLOADS.md`. The metadata
pointer under `android-updates/current` must resolve inside this same mount.

The gateway provides:

- Website, static assets, documentation, release notes and direct downloads.
- Read-only `/repo/*` forwarding to the existing HTTPS updater service.
- Local Android metadata and targets under `/repo/android/`.
- `/licensing/v1/*`, restricted to the client license/machine operations and
  forwarded to `https://licenses.pornfetch.to` with TLS verification enabled.

The website also enforces the read-only boundary when reached through its
configured onion host. CI, administration and payment endpoints are unavailable
there. Checkout pages explain the boundary and offer an explicit link to the
regular HTTPS store. Purchases retain the existing country checks and provider
integration. Do not change their IP evidence to the Tor listener's loopback IP.

Mirrored public HTTPS pages advertise `Onion-Location`. Checkout/session URLs are
excluded. Canonical product URLs remain on pornfetch.to; onion responses are
noindex. The onion pages do not load the aggregate visit script. Secure-cookie
settings remain unchanged; this phase requires no onion purchase session.

## Android update publication

`POST /ci/android-updates` accepts `Authorization: Bearer WEBSITE_RELEASE_TOKEN`.
Its JSON body is `{"files": {"root.json": "<base64>", ...}}`, with exactly the
root, targets, snapshot and timestamp JSON files. The limit is 2 MiB for this
endpoint; ordinary request limits remain unchanged.

The pinned public root is `pf_server/android_update_root.json`, copied from the
app's `src/cli/update_root.json`. Keep these trust roots aligned. The server
stores no update-signing private key. It verifies signatures, expiry, metadata
hashes/version relationships and monotonic metadata versions. Every APK target
must match the release catalog's filename, size, digest, architecture and release
timestamp. Changing the update root requires the normal dual-signed TUF root
rotation; an arbitrary replacement is rejected.

After verification, APKs are hard-linked into the hash-prefixed TUF target store
and a new metadata snapshot is exposed through an atomic `current` symlink.
Existing public targets remain available. Keep snapshots, targets, immutable
releases and the catalog backed up together. Metadata is served without caching;
versioned APK content is immutable. Caddy serves the files in production, with
Flask fallback routes for development and tests.

The app workflow publishes this feed after a website release containing Android
APKs. It uses the existing `CLI_UPDATE_SIGNING_KEY`, website publisher token and
the four Android APK signing secrets. The scheduled update-metadata refresh also
refreshes Android. If the schedule misses an expiry, the publisher can recover
using authenticated expired metadata to preserve counters; clients still reject
expired feeds. Root-key expiry requires operator attention.

## Verification and rollout

1. Deploy the application and storage mounts; validate and reload the Caddy
   configuration through the existing deployment process.
2. Publish a signed Android website release and confirm the public TUF feed.
3. Release the Tor-enabled clients after gateway and update-feed verification.

Local checks without Tor or provider requests:

```bash
uv run python -m unittest discover -s tests -v
uv run python scripts/test_onion_host.py --caddy /path/to/caddy
uv run python scripts/test_download_host.py --caddy /path/to/caddy
```

Then use Tor Browser to check public pages and a ranged download through the
actual onion. Check licensing with a test license and Android installation with
a signed test APK on a device. Monitor aggregate errors, metadata refresh jobs,
disk capacity and Tor bootstrap failures without recording license keys or
visitor IPs. No production service is reloaded by the local checks.
