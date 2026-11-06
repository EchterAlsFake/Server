# Porn Fetch search visibility and launch operations

Research and source review: **25 October 2026**. Initial audience: English-speaking
adults looking for a supported video-downloading workflow. Canonical product
origin: `https://pornfetch.to`.

## Current implementation: 5 November 2026

The October launch findings below are historical. A fresh live crawl covered all
34 sitemap URLs: all returned HTTP 200, matching self-canonicals, and indexable
HTML/HTTP directives. Search Console reported no sitemap errors or warnings.
The local SEO and release regression suites cover these contracts.

### Release accuracy and content

The published **3.8.82 beta** catalog identifies source commit
`7ec6ddb759cd5a7dbd259ef92344cfb8afdb15f0` in the sibling Porn_Fetch repository.
This is a beta from the 3.9 development cycle, not the vulnerable legacy 3.8 release.
Guides and homepage identify the published version. Desktop Video URL/Get Video/
Download Selected and Android Add videos/Get Video/Output folder/Choose folder
were checked against that exact commit. Android now saves completed downloads
to the selected output folder automatically, without a separate Save action.
The public-collection preview is limited to the first five entries before filters;
account collections are exempt. Source inspection does not establish live provider
success. An earlier local draft targeted 3.8.2 (b38c98e), whose Android Save action
differs; that draft was superseded before deployment.

The exact `3.8` release is excluded from current package selection, including
stable-channel and architecture fallbacks. Historical release pages retain their
files with a security warning; no artifacts or historical terms are deleted.
This rule does not classify 3.8.1, 3.8.2, or every 3.8.x build as vulnerable.

All guides offer explicit platform installation choices near the introduction,
including the iOS sideloading limitation and CLI. Links use recommended channel
selection instead of forcing beta. Existing provider-specific URL guidance and
troubleshooting remain intact. Metadata descriptions use provider summaries.
Four editorially related workflows replace the first-five-provider bias.

The real desktop download-controls screenshot contains no video URLs or account
data. Responsive 480/960 WebP derivatives preserve the original and supply a
visible Article/social image. The caption identifies this as the shared interface,
not evidence of a successful provider download. The maintainer supplied a real Android Account-tab screenshot on 5 November.
It contains empty login fields, with PornHub selected, and is displayed on the
Android download page and the three account-capable provider guides only. Its
caption distinguishes account collections from individual video downloads. The
original JPEG is preserved; 360/720 WebP delivery copies contain no EXIF metadata.
Publication dates remain 25 October; the actual editorial revision is 5 November.

The footer and /transparency redirect now target the working documentation host.
Privacy/terms retain their text with only one page-level H1. Decorative images
retain empty alt text; automated audit warnings do not justify redundant labels.

### Measurement and repeatable checks

No Google Analytics, new visitor identifiers, or new page-level tracking has been
added. Search Console measures search visibility; aggregate download requests,
partial requests, and bytes measure delivery activity separately. Neither clicks
nor requests prove installation or completed downloads. The current visitor script
groups every guide into `guides`, so it cannot attribute individual guide journeys.
Prepared patches under deploy/dashboard-privacy remain outside this change and
must not be described as activated. Deployment examples are not live-state proof.

The dated Search Console snapshot is `seo-search-baseline.json`. To refresh it,
use GSC Wizard generate_seo_report (compact, 28 days, includeSitemap), query_top_pages
(limit 100, paginate if needed), and query_search_analytics by device/country.
Record the returned date range and settledThrough; use property totals, not summed
query rows. Retain unknown/hidden query coverage and compare full equivalent windows.
Review after two weeks for regressions and after 28 complete days for associations;
country, device, release changes and short history prevent causal claims.

For repeatable live mobile lab checks (homepage, two leading guides, download hub,
Android and iOS), install Lighthouse as developer tooling and run:

```sh
CHROME_PATH=/path/to/chromium python scripts/audit_seo_performance.py --lighthouse /path/to/lighthouse --output /tmp/seo-performance.json
```

This measures the actual live catalog, visit script and production compression.
The live pre-deployment run is recorded in `seo-live-lab-results.json` (Lighthouse
13.5.0, simulated mobile throttling). All six pages scored 98–100 for performance
and 100 for accessibility and SEO. LCP ranged from 1.11 to 1.44 seconds; CLS and
total blocking time were zero. No broad performance rewrite is justified by this
sample. Re-run after deploying the responsive guide image to compare delivery cost.

Results are lab observations, not field INP or proof that local changes are deployed.
CrUX readings through GSC Wizard require its API key; absence of that configuration
is not evidence of poor performance. Do not add visitor tracking to fill that gap.

Local verification uses synthetic test state and writes screenshots to /tmp:

```sh
.venv/bin/python -m unittest discover -s tests -p test_seo.py -q
.venv/bin/python -m unittest discover -s tests -p test_website_releases.py -q
uv run --with playwright python scripts/check_seo_browser.py
```

Deploy accuracy/link fixes first, then guide improvements. Re-run the crawl and
mobile lab measurements after deployment. Keep staging unindexed, private flows
excluded, adult classification accurate, and canonical URLs unchanged. Record
release dates alongside future comparisons without bulk sitemap resubmissions.

## Historical launch findings (25 October 2026)


The live audit on 25 October found HTTP 200 for the product homepage, but its HTML
contained `noindex, nofollow`. The robots file returned `Disallow: /`, and the
sitemap returned 404. The code tied all three behaviors to payment sandbox mode.
Those are direct barriers to discovery; keyword changes alone could not fix them.
The live `www` host also served a duplicate HTTP 200 homepage, although the checked-in
Caddy configuration already specified a permanent redirect. A plain HTTP client
could reach the site even though the research browser could not; that browser's
fetch failure was not evidence of a general outage.

The site already had server-rendered HTML, canonical URLs, descriptions, an
explicit-content rating, local download pages, source links, and a maintainer
page. It lacked practical provider-specific articles matching queries such as
“how to download videos from PornHub.” The main work is therefore crawlability,
useful documentation, internal discovery, and accurate launch expectations.

The app source is 3.9 while its context file warns that older published 3.8
binaries can differ substantially. Guides identify the 3.9 beta workflow and
consult the website release catalog for availability. A missing package is never
replaced with an invented download link. No live provider-download tests were run
as part of the website work: static source review establishes implemented behavior,
not a claim that every upstream video currently downloads successfully.

## Current search guidance and implementation decisions

### Search intent and editorial quality

Google recommends content that actually completes the reader's task and shows
relevant experience and trustworthy sourcing. It discourages bulk pages made
primarily to manipulate rankings, arbitrary word-count targets, and cosmetic date
changes. Apply that here through real app labels, useful limitations, individual
provider details, and direct answers. Shared download steps are appropriate because
the underlying application workflow is shared; each provider also gets its own
URL and capability explanation.

Source: [Creating helpful, reliable, people-first content](https://developers.google.com/search/docs/fundamentals/creating-helpful-content).

The primary query belongs to one provider guide, rather than many near-duplicate
pages for “free,” “MP4,” each year, every operating system, and every resolution.
Existing platform installation pages handle installation intent. Guide titles,
H1s, descriptions, and natural link text describe the actual page. There is no
fixed title or description character limit imposed by this implementation.

Sources: [SEO starter guide](https://developers.google.com/search/docs/fundamentals/seo-starter-guide),
[title-link guidance](https://developers.google.com/search/docs/appearance/title-link).

### Adult content and SafeSearch

Google's explicit-content guidance covers accurate classification and access for
crawlers. Public guides and marketing content are available without an age-confirmation
session, and carry the existing `rating=adult` metadata. Purchase confirmation
remains in place. The same public content is served to visitors and crawlers;
there is no user-agent-only gate bypass. SafeSearch can limit visibility for the
audiences that enable it. Removing accurate adult classification to chase traffic
is not part of this work. The product tour is not a collection of hosted adult
videos, so an adult-video sitemap is not added.

Source: [Guidelines for sites with explicit content](https://developers.google.com/search/docs/specialty/explicit/guidelines).

### Crawling, indexing, and canonicalization

`SEO_INDEXING_ENABLED` defaults to `true`, as requested for launch, independently
of `NOWPAYMENTS_SANDBOX`. It controls indexability of explicitly public pages on
`APP_DOMAIN` and availability of the product sitemap. Configure it as `false` on
staging. Sandbox payment warnings, payment behavior, and consent are unaffected.

When disabled, pages send `noindex, nofollow`; robots still allows crawling so
Google can see that directive. A robots disallow is not a reliable removal
mechanism. Private responses remain unindexed, and the sitemap excludes private
flows, APIs, binaries, and unknown routes. Onion copies remain unindexed with HTTPS
canonicals. The docs subdomain retains its separate policy.

Sources: [Robots introduction](https://developers.google.com/search/docs/crawling-indexing/robots/intro),
[robots meta and HTTP directives](https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag).

All canonicals derive from configured `APP_DOMAIN`, not a visitor-supplied host
or query string. The product `www` alias redirects permanently, retaining the path
and query. Caddy remains the primary redirect layer; Flask handles the product
`www` alias too. Existing old-host product redirects now include guides. Unrelated
personal routes, documentation, updater protocols, and checkout sessions keep
their existing routing.

Source: [Canonical URL guidance](https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls).

### Structured data and obsolete advice

Use JSON-LD describing visible content: website identity, maintainer, the software,
guide articles, and breadcrumbs. HTML titles and social titles share one metadata
source. Article dates and visible bylines agree with the page, and breadcrumb
markup agrees with visible guide navigation. There are no fabricated ratings,
reviews, or guarantees of rich results, including for adult-related pages.

Google's current changelog says FAQ rich results stopped appearing on 7 May 2026.
Helpful visible questions remain worthwhile, but FAQ or HowTo markup is not a
ranking project. The same changelog states that `llms.txt` is not needed for Google
Search and does not improve visibility. Neither is added as an SEO shortcut.

Sources: [Structured-data policies](https://developers.google.com/search/docs/appearance/structured-data/sd-policies),
[Search documentation updates](https://developers.google.com/search/updates).

### Performance

Google recommends LCP within 2.5 seconds, INP below 200 ms, and CLS below 0.1.
Performance scores are diagnostic and do not guarantee ranking. Local Lighthouse
results are laboratory observations, not measurements of actual visitors or proof
of field INP. Check Search Console field data once there is sufficient traffic.
The guides are HTML-first and add no new client-side framework or tracking code.

Source: [Core Web Vitals and Search](https://developers.google.com/search/docs/appearance/core-web-vitals).

The 25 October local mobile lab runs used Lighthouse 13.5.0, Chromium, default
simulated mobile throttling, an empty release catalog, and payment sandbox mode.
The before-run served the prior Git revision `ec0fdb9`; the after-runs served this
working tree. Both used the same Flask test fixture, with the analytics script
replaced by an empty response. Production proxy compression was not simulated.

| Page | Performance | Accessibility | SEO | LCP | CLS | Transfer |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Homepage before | 93 | 97 | 69 | 3.1 s | 0 | 792 KiB |
| Homepage after | 98 | 100 | 100 | 2.1 s | 0 | 175 KiB |
| Guides hub | 99 | 100 | 100 | 1.8 s | 0 | 121 KiB |
| PornHub guide | 99 | 100 | 100 | 1.8 s | 0 | 125 KiB |
| Download page | 99 | 100 | 100 | 1.8 s | 0 | 254 KiB |

All five runs measured 0 ms total blocking time; that is not a field INP result.
The SEO score checks technical basics and does not measure content quality or
predict rankings. Machine-readable observations are in
[seo-lab-results.json](seo-lab-results.json). The first audit's biggest image
finding was the full 1920×1080 logo being delivered for a small header mark.

The delivered assets now use a smaller lossless logo, a compressed poster, and
responsive WebP screenshots while preserving all originals and full-size links.
Platform icons load lazily, and the homepage no longer loads the download-page
stylesheet. The iOS text link now has an underline. To rebuild image derivatives
after changing original artwork, run:

```sh
uv run --with pillow python scripts/build_web_images.py
```

Pillow is optional build tooling, not a new server runtime dependency. Generated
delivery assets are checked in, so deployment does not need to rebuild them.

## Guide inventory and source checklist

All paths below the guide hub use `/guides/download-<provider>-videos`.
The five featured providers are an editorial priority requested for this launch,
not a search-volume estimate. Search Console will supply real query evidence.

App references are relative to the sibling `Porn_Fetch` repository. Baseline
capabilities: `docs/WEBSITES.md`; source version and publishing caveat: `CONTEXT.md`.
URL kinds and forms: `src/shared/provider_routing.py` (`HOST_PATTERNS`,
`PROFILE_SEGMENTS`, `COLLECTION_SEGMENTS`, `route_url`, `_is_video_url`).

| Provider | Specific guide coverage and source checks |
| --- | --- |
| PornHub | Video and short routing; playlists and profile tabs; account history, recommendations, feed and favorites; CLI-only albums. Check routing plus account UI and CLI album flow. |
| XHamster | Videos, moments/shorts, profiles; liked videos and authenticated account playlists. Check account UI's playlist field and `fetch_account_videos`; do not describe a public playlist flow. |
| XVideos | Videos, profiles and collections; session-token/browser-cookie login and account lists. Check account UI. `route_url` explicitly rejects Quickies fragments. |
| Eporner | Case-sensitive video IDs, supported localized video and profile paths; quality caveat. Check `eporner_video_id`, `resolve_video`, and `UI/AppStrings.qml` quality help. |
| XNXX | Individual videos and profile/user/performer pages. Check routing and capability table; there is no app keyword-search or login feature. |
| SpankBang | ID/locale-prefixed profiles and supported individual video forms. A single-video path containing `playlist` does not imply collection fetching. Check `_content_section` and `_is_video_url`. |
| YouPorn | Watch/embed URLs and individual `collection(s)/videos/ID` paths; unknown-resolution MP4 entitlement caveat. Check collection routing, shared preparation, and license gates. |
| Beeg | Signed numeric video IDs; no profiles. Check video routing and `UI/AppStrings.qml` strict-language/API caveat. |
| Porntrex | Numeric video pages, supported model/channel pages, filters and result limits. Check routing, GUI processor, and settings. |
| XFreeHD | Video input and SD/HD mapping; CLI-only albums. Check `src/shared/media.py::xfreehd_quality`, routing, and CLI single-download flow. |
| RedTube | Numeric videos, playlists, profile types, restricted user-feed caveat. Check routing and `docs/URL_TEST_FIXTURES.md`. |
| Thumbzilla | Watch links, playlists, performer/channel/amateur pages; no app account login. Check routing and capability table. |
| Tube8 | Video paths and profile types, with public user-feed limitations. Check routing and `docs/URL_TEST_FIXTURES.md`. |
| EMPFlix | Supported legacy/numeric video forms and profile/performer pages. Check video routing; do not assume TNAFlix channel support. |
| TNAFlix | Legacy/numeric video forms plus profile/performer/channel pages. Check video and profile routing. |

Common instructions were checked against:

- `src/frontend/UI/DownloadsPage.qml`: Video URL → Get Video; quality per row;
  Download and Download Selected; distinct Model URL and Playlist URL inputs.
- `src/frontend/UI/AndroidDownloadsPage.qml`: Add videos; URL-kind selector;
  Get Video/Get Videos; quality per card; Download; automatic output-folder saving; folder control (published 3.8.82).
- `src/frontend/UI/SettingsPage.qml`: Output Path, Max Result Limit.
- `src/frontend/UI/AccountPage.qml` and `AndroidAccountPage.qml`: provider-specific
  account authentication and lists. Avoid implying browser-cookie import is
  available in every device/browser combination.
- `src/backend/video_processor.py`: filtering and selected quality;
  `src/backend/download_manager.py` and `src/cli/downloads.py`:
  download/entitlement enforcement; `src/shared/media.py`: 720p free maximum.
- `src/cli/wizard.py`, `flows/single_download.py`, `flows/scrape.py`,
  `flows/accounts.py`, `downloads.py`, and `batch.py`: terminal workflows.

Do not advertise HQporner or MissAV based on the separate API documentation: they
are not supported app providers. Native iOS 15+ GUI support is now available through a sideloaded IPA. Do not imply universal
account access, every source resolution, or in-app keyword search.

## Updating content

Edit `pf_server/guide_content.py` and the guide templates; do not edit generated
API docs to change these user guides. Maintain a distinct explanation for each
provider rather than replacing its name in generic marketing paragraphs.

`GUIDE_DATE` is the initial publication date. For a substantive change to one
provider, add/update that record's ISO `updated` date. The visible date, Article
`dateModified`, and sitemap `lastmod` read that same value. Do not refresh dates
on deployment. If shared instructions change materially, update affected records.

Recheck the source checklist when the app's URL routing, account workflows,
quality gates, or interface labels change. Keep beta wording aligned with the
actual release status. Prefer accurate limitations over a promise the app cannot
fulfill. Use source links, release notes and maintainer information to make the
project verifiable; never claim an upstream test passed unless it actually ran.

## Deployment and public verification

Deploy this checkout using your existing server update procedure, with
`APP_DOMAIN=https://pornfetch.to` and `SEO_INDEXING_ENABLED=true`. Payment sandbox
mode can remain enabled. This SEO work needs no database migration and no new
runtime dependency. The deployment helper may still apply pre-existing migrations.

The documented helper currently points to `/home/asuna/Dokumente/Server`, while
this checkout is `/home/asuna/PycharmProjects/Server`. Confirm the deployed source
path before using `eaf-deploy`; deploying the other checkout would omit this work.
The workstation used for implementation has no `/srv/server` installation or
local Caddy service configuration, so repository changes alone do not update the
public server.

Install the reviewed Caddy site changes using your existing configuration process.
Validate the complete configuration before reloading; keep existing TLS, ECH,
WireGuard, and trusted-proxy settings. The `www` redirect in Flask supplies a
fallback if the product alias reaches this application.

Check public responses after deployment:

```sh
curl -fsS https://pornfetch.to/robots.txt
curl -fsS https://pornfetch.to/sitemap.xml
curl -fsSI https://pornfetch.to/guides/download-pornhub-videos
curl -fsSI 'https://www.pornfetch.to/guides/download-pornhub-videos?source=check'
```

Expect `Allow: /` and the sitemap URL; sitemap HTTP 200; public guide HTTP 200
with `X-Robots-Tag: index, follow`; and a permanent `www` redirect to the same
path/query on `pornfetch.to`. Inspect HTML too: one correct canonical and matching
robots metadata. Check both a public page and a private checkout page before
calling the cutover complete. Confirm new guides on the former product host
redirect while unrelated personal and documentation routes keep their routing.

## Search Console: owner setup

1. Open [Google Search Console](https://search.google.com/search-console/about)
   with the Google account that should own the site. Add a **Domain property** for
   `pornfetch.to`.
2. Copy the TXT record Google supplies into your DNS provider, leave it in place,
   and complete verification. Do not paste the record into source code. See
   [Google's verification instructions](https://support.google.com/webmasters/answer/9008080).
3. Submit `https://pornfetch.to/sitemap.xml` in Sitemaps after the public checks
   pass. Use URL Inspection → Test live URL for the homepage, guide hub, PornHub
   guide, and download page. Confirm that crawling and indexing are allowed and
   inspect the rendered page. Request indexing for the priority entry pages.
4. Save the deployment date and a baseline of indexed URLs, sitemap status,
   manual actions/security issues, and available Performance data. A new domain
   property may initially have little or no data. Do not interpret a `site:` query
   or one personal search as a complete indexing/ranking report.
5. Around two weeks after launch, review indexing reasons and impressions by page
   and query. Around six weeks, compare equivalent date ranges and review clicks,
   CTR, device/country differences, and download-guide relevance. Investigate
   exclusions rather than resubmitting every URL repeatedly.

Measurement: [Search Console performance report](https://support.google.com/webmasters/answer/7576553).
Search Console setup requires your Google account and DNS control; the website
does not add visitor tracking or collect additional identifiers for it.

Keep project profiles and release announcements accurate and link to the relevant
official guide where appropriate. Useful documentation and real release news can
earn citations over time. Purchased backlinks, bulk directory submissions, fake
reviews, and automated promotional messages are excluded.

Source: [Google Search spam policies](https://developers.google.com/search/docs/essentials/spam-policies).

There is no guaranteed ranking, traffic quota, or indexing deadline. Success begins
with eligible, accurate pages and is evaluated using actual query impressions,
relevant clicks, and whether visitors can complete their intended download.
