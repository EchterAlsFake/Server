# Independent website downloads

The website catalog and binary host are independent of the working application
updater at `api.pornfetch.to`. Existing `/repo/*` and `/ci/deploy/*` contracts,
update signatures, and GitHub Release publishing are unchanged.

## Production setup

Prepare configuration and validate it before installing/reloading services. This
repository does not install secrets, change DNS, or publish a real release itself.

1. Point `pornfetch.to` and `www.pornfetch.to` to the intended server. Set
   `APP_DOMAIN=https://pornfetch.to`. Keep `API_DOMAIN` at the existing **payment**
   API origin; it is not the website publisher setting.
2. Create storage outside the deployable application tree:

   ```sh
   sudo install -d -o eaf-server -g eaf-server -m 0751 /srv/pornfetch-downloads
   sudo install -d -o eaf-server -g eaf-server -m 0700 /srv/pornfetch-downloads/staging
   sudo install -d -o eaf-server -g eaf-server -m 0755 /srv/pornfetch-downloads/public
   ```

   Caddy needs traversal of the root and read access to `public`, but must not be
   able to read `staging`, `catalog.json`, or the publisher lock. The app account
   needs write access to this root. Keep it on one filesystem for atomic renames.
3. Set `WEBSITE_RELEASES_DIR=/srv/pornfetch-downloads` and a long random
   `WEBSITE_RELEASE_TOKEN` in the server environment. Add the same value as the
   `WEBSITE_RELEASE_TOKEN` GitHub environment secret used by the app build job.
   Do not put it in workflow arguments, URLs, files in Git, or release notes.
4. Review/install the updated `eaf-server.service` write-path allowance. Import
   `deploy/pornfetch-site.caddy` beside `managed-sites.caddy`, in an import that
   defines `application_defaults` first. If copied into `conf.d`, name the file
   `pornfetch-site.caddy`. Validate the complete Caddy configuration before reload.
   The new site never handles `api.pornfetch.to`.
5. The default per-file upload cap is 2 GiB. Adjust
   `WEBSITE_MAX_ARTIFACT_BYTES` and the Caddy upload matcher limit together if
   required. Existing 200 KiB application limits remain unchanged. Give your
   reverse proxy/CI enough upload time for the largest package.

Versioned files (including a public `manifest.json` release snapshot) are served
directly by Caddy, including Range/HEAD requests. It
sets attachment, nosniff, noindex, and immutable cache headers. Missing files must
return 404, not a cached 200 or a product HTML page. Directory browsing stays off.
The Flask `/downloads/<version>/<filename>` fallback supports development/tests;
it is not the production binary-transfer path.

## Publishing

In the app repository's existing Cross-Platform Build Pipeline, choose the build
target/version, retain the existing legal-review acknowledgment, and enable
`deploy_website`. `website_channel` defaults to `beta`; choose `stable` only for
an intended stable release. The optional `WEBSITE_ORIGIN` GitHub variable defaults
to `https://pornfetch.to`.

A separate job consumes successful build artifacts, includes their legal archives,
bundles CLI executables with their helpers, includes a tracked-source archive with
the stamped version, and uploads without needing a GitHub Release. Existing GUI,
CLI updater, and GitHub publishers have no dependency on this website job. Android
APK names follow `PornFetch_android_GUI_<ABI>.apk`. The app workflow now builds
all four Android ABIs with the existing patch/build scripts, Python 3.14 wheels,
SDK 36 and NDK r28c. The website publisher waits for those builds except on CLI-only
runs. Select `build_target: android` for Android-only iteration or publication.
Public Android releases require `ANDROID_KEYSTORE_BASE64`,
`ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` and `ANDROID_KEY_PASSWORD` in the
app repository's `beta` environment, in addition to the website publisher token.
Build-only unsigned APKs stay in CI artifacts. See the app repository's
`docs/ANDROID_CI.md` for setup and diagnostics.

The standard-library publisher also supports `--dry-run`, producing packages and
`manifest.json` without reading a token or contacting the server. It is at
`Porn_Fetch/packaging/publish_website_release.py`.

### Website publishing API

All writes use `Authorization: Bearer <WEBSITE_RELEASE_TOKEN>` and do not use
browser session or CSRF credentials. An unset token disables publishing (503).

- `POST /ci/website-releases`: submit a schema-1 JSON manifest; create private
  staging, or acknowledge an identical prior submission. A conflicting version
  returns 409.
- `PUT /ci/website-releases/<version>/files/<filename>`: stream one declared file.
  Size and SHA-256 must match; partial/failed uploads never replace a verified
  file. Published files cannot be overwritten.
- `POST /ci/website-releases/<version>/publish`: verify every file again, generate
  per-file `.sha256` sidecars and `SHA256SUMS`, rename the release into `public`,
  and replace `catalog.json` atomically. A retry repairs a catalog update that was
  interrupted after the directory rename.
- `GET /download/catalog.json`: public release metadata, cached for 60 seconds,
  with `X-Robots-Tag: noindex`. The optional `?version=<version>` filter returns
  just that release, so CI verification does not fetch an ever-growing history.
- `GET /downloads/<version>/<filename>`: immutable download URLs. A missing build
  does not receive an invented URL or automatic GitHub fallback.

Manifest: `schema: 1`, numeric `version` (optional alpha/beta/rc suffix), `channel`
(`stable`/`beta`), timezone-aware `published_at`, hex `commit`, plain-text `notes`,
and 1–150 `artifacts`. Each artifact declares `filename`, `platform`, `arch`,
`kind`, positive byte `size`, lowercase hex `sha256`, optional `min_os`, and boolean
`experimental`. Qt installers must set `experimental: true`. Kinds: `gui`, `cli`,
`installer`, `apk`, `source`, `notices`. Architectures: `x64`, `arm64`, `x86`,
`armv7`, `x32`, `riscv64`, `universal`, `any`. Android ABI labels are normalized by
the CI publisher; the page and guide show their familiar names.

Recommended downloads select stable per platform/architecture/package variant,
otherwise the newest beta. A new GUI-only or CLI-only release retains the other
variants from prior releases and shows their original version. Historic releases
remain accessible; artifacts are never relabelled as a newer version.

## Recovery and monitoring

Keep public versioned files and the private catalog backed up outside the deploy
checkout. No automatic deletion of published releases is configured. Failed
uploads remain in private staging; inspect and remove an abandoned version only
when no job is writing it. Immutable public files must not be changed in place.
Retry publication to recover an interrupted catalog update. Restore a matching
catalog and public tree together from backup if needed.

Check disk capacity, download 404/5xx counts, CI failures, and publication latency.
Keep access logging/visitor-level tracking disabled as in the existing setup.
Checksums detect corruption; they do not claim a new code-signing identity.

## Product SEO launch

Public product pages and guides are readable without the age dialog. Purchase
pages retain the existing age/terms/withdrawal confirmations. Test/sandbox pages
remain noindex; use live mode only with the already required production payment
configuration. Canonical URLs derive from `APP_DOMAIN`, not request headers.

The sitemap includes the product, downloads, substantive guides, About/help and
published release notes. It excludes purchases, binary files and API endpoints.
Software structured data uses a Person publisher and real capabilities, without
invented reviews, ratings, or free-price claims. Adult-content metadata is kept.

The managed-site redirect migrates only GET/HEAD marketing URLs from the old
commercial origin. Payment POSTs, active checkout URLs, API/docs and licensing
hosts are not blanket-redirected. Test old-session recovery URLs before cutover.
Verify both site origins in Search Console, submit the new sitemap, and inspect
rendered product/platform pages after deployment. Indexing/rankings are not
promised. Keep permanent redirects while older links are in use.
