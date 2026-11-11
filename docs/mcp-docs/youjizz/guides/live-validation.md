---
title: "Live validation \u2014 YouJizz API"
summary: "Recorded validation evidence, commands and per-quality reconciliation."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Live validation \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "guides", "live-validation"]
---

# Live validation — YouJizz API

The following is preserved implementation evidence from 2026-11-10; these live
checks were not rerun during the documentation maintenance.

# Live validation

Date: 2026-11-10. Target: public `https://www.youjizz.com` from this Linux environment.

## Environment and commands

```bash
uv venv .venv --python 3.13
uv pip install --python .venv/bin/python -e ../eaf_base_api -e '.[test]'
.venv/bin/python -m pytest -q -n 4 --junitxml=/tmp/youjizz-final-parallel.xml
uvx ruff check youjizz_api --select F
uv build --out-dir dist
```

The authoritative local backend is `eaf-base-api` 4.2.6. Runtime dependencies include `selectolax` and the backend's `m3u8` extra. FFmpeg/ffprobe validate finished media. There are no offline fixtures, synthetic parser tests, mocks, skipped network gates, or browser cookie reads.

Final full-suite result: **63 passed, 0 failed, 0 errors, 0 skipped**, in **198.64 seconds** with four test workers. The suite emitted 899 deprecation warnings from the shared backend's existing Tenacity `initial` parameter; these do not represent failed requests or skipped checks.

Recorded pytest summary:

```text
63 passed, 899 warnings in 198.64s (0:03:18)
```

This successful full run completed before the VPN connection changed. Temporary logs were no longer present after the interruption; the recorded tool result and the per-quality matrix below preserve the validation evidence. The commands above reproduce the checks on the current connection.

The final run followed fixes identified during earlier live checks: incomplete Auto HLS quality coverage, an empty legacy API thumbnail, and newly uploaded videos with an empty slug and no VideoObject JSON-LD. The complete metadata/listing/profile rerun passed 50 tests before the final 63-test run. The final full run revalidated every implemented capability and the complete download matrix. No required checks remained blocked.

## Observed capabilities and routes

| Capability | Live route / behavior |
| --- | --- |
| Video | `/videos/{slug}-{id}.html`; stable IDs, embed aliases `/videos/embed/{id}` |
| Structured video metadata | Matching VideoObject JSON-LD, Open Graph, hidden statistics inputs, `dataEncodings` public JSON array |
| Independent video API | `/api/thumbs?ids={id}`; a JSON list matched by `record_num`, also used by public profile UI |
| Listings | `/most-popular/{page}.html`, `/newest-clips/{page}.html`, `/top-rated/{page}.html`, `/top-rated-week/{page}.html`, `/top-rated-month/{page}.html`, `/trending/{page}.html`, `/highdefinition/{page}.html` |
| Random | `/random` returns a listing, not a single-video redirect |
| Search | `/search/{optional_order_}{query}-{page}.html`; actual Next links use normalized query spelling and retain query filters |
| Search orders | Empty/relevance, `recent`, `views`, `rating`, `length` |
| Search filters | Duration boundaries 60–180, 180–600, 600–1200, 1200+ seconds; all/any/exact phrase; title-only; explicit date bounds |
| Unsupported search-HD control | Frontend says `searchHD: false`; `/search/solo-1.html?hd=1` still includes videos whose thumbnail API says `hd=0`. Excluded from the provider's search interface, with a live regression check of the observed limitation |
| Category/tag directory | `/tags`; 12,461 observed entries, linking `/tags/{query}-1.html`; navigation also links `/categories/{query}-1.html` |
| Pornstar directory | `/pornstars/name/{A..Z}`; A has 1,352 observed entries, linking keyword search rather than profiles |
| Public users | `/profile/user/{id}` is an Angular shell; its controller fetches `/api/profile/{id}` and separately respects public profile/upload flags |
| Public uploads | `/api/socialVideos/{id}?order=recent|views|rating|length` supplies the full ID list; the UI slices by 24 and fetches `/api/thumbs?ids={joined IDs}` |
| Comments | `/api/comments/{video_id}` returns comments/replies and like/dislike action rows; the latter are excluded from typed comment results |
| Unsupported private/account features | No authentication actions implemented. The observed private favorites endpoint returned HTTP 500; no successful favorites capability is claimed |
| Collections | The site's `playlist` and `socialPlaylist` feature flags are false; no Playlist, Model, or Channel classes are advertised |

Accepted hosts are exactly `youjizz.com` and `www.youjizz.com`. The apex redirects to www and video identity/duration are verified across both. No mirror or language subdomain is confirmed. English and Chinese are client-side interface translations, not separate verified content routes. Country selectors personalize rankings rather than prove a language host.

## Source behavior and metadata variants

The suite checks API-only, HTML-only, combined, both sequential orders, deferred fields, and serialization without incidental fetches. API precedes HTML for shared fields, except thumbnails: legacy video 48914471 returns an empty API thumbnail while HTML has a real image. Empty URLs stay absent rather than resolving to the site root. HTML retains description, calendar publication date, embed/canonical identity, tag names, exact rating/votes, author references, and signed media maps. Preview and sprite metadata come from the thumbnail API. Comments have a separate lazy source; their integer timestamps are Unix seconds.

Representative metadata pages include IDs 30792291 (rich description and ratings), 83968481 (no rating/votes), 48914471 (legacy/288p and empty API thumbnail), and 75799072 (nonstandard 368p). The requested VideoObject and hidden video ID must agree. Sparse video 128889181 has an empty title slug and omits VideoObject JSON-LD; its Open Graph URL and hidden ID must both identify the requested video before ordinary Open Graph fields are accepted. The regression compares its exact duration, thumbnail, publication date, missing title, and stable identity against the live page. A real nonexistent ID 999999999999999 returns HTTP 404 and remains an error.

Private user fields are filtered according to public flags. Contact/internal fields returned by the raw endpoint are not copied into domain objects. Public uploads are governed separately by the UI's public-video flag. Required age verification or access challenges fail explicitly.

## Complete listing reconciliation

- User 15100401: **510 expected / 510 actual IDs**, **22 pages**, **6 IDs on the last page**, no duplicates, omissions, or unexpected IDs. Every 24-ID slice was independently checked against the actual thumbnail response used by the Angular UI. First, next, middle, last, and beyond-last requests agree. A separate live check confirmed that thumbnail response ordering follows the requested upload ID ordering. The user's profile is private but its uploads are explicitly public; hidden profile identity is not exposed.
- Pornstar directory entry Abby Marie: directory snapshot **1**, actual keyword listing **6 expected / 6 actual IDs** on one page; next/beyond-last is empty. The six results are keyword-search matches, not a curated upload count, so the stale directory count is not treated as an exact profile total.
- Public user 52588351: actual upload endpoint is empty; the API yields zero IDs and terminates. Banned user 51843451 remains unavailable.
- Listing comparisons establish the public session first: the initial visit can set `yjNewestShuffle` and `yjRandomThumbs` cookies. Empty-title URLs (`/videos/-{id}.html`) are included rather than discarded. General search: deterministic views sorting is used to compare two full 24-video pages. Relevance can reorder equally ranked matches between live requests, and Next URLs normalize spelling; the test does not assume an invented route or truncate an unordered sample.

## Download validation

Every tested download goes through `Video.download()` and the shared backend. Each full file is inspected with ffprobe for dimensions, duration, and audio availability. The matrix includes every source label in each representative sample, both MP4 and HLS, the presets best/half/worst, and absent numeric quality 999 with nearest-tier fallback. It also covers concurrent different-video downloads, refreshed sources, repeated selections, callbacks, HLS completion reports, remuxed MP4, original transport streams, and the CLI.

The site's Auto HLS master omits 288p on video 48914471 and 368p on video 75799072. Their actual per-quality masters contain these renditions. The implementation uses those masters, preserving the real dimensions rather than silently accepting a lower Auto rendition. Video 51957501 has a portrait 404×720 stream with **no audio in its source** (master codec list is video-only); silence is retained and tested explicitly. Video 80517371 uses a portrait 1920 encoding label.

| Video ID | Source label | Validated dimensions | MP4 seconds / bytes | HLS seconds / bytes | Audio |
| --- | ---: | --- | --- | --- | --- |
| 48914471 | 240 | 426×240 | 44.920000 / 2,122,218 | 45.000000 / 2,122,378 | Present |
| 48914471 | 288 | 512×288 | 44.920000 / 1,995,530 | 44.954059 / 1,996,903 | Present |
| 48914471 | 360 | 640×360 | 44.920000 / 3,169,372 | 45.000000 / 3,170,384 | Present |
| 48914471 | 480 | 852×480 | 44.920000 / 4,627,406 | 45.000000 / 4,627,102 | Present |
| 48914471 | 720 | 1280×720 | 44.920000 / 7,884,806 | 45.000000 / 7,887,010 | Present |
| 75799072 | 240 | 416×240 | 18.600000 / 1,064,843 | 18.666667 / 1,068,546 | Present |
| 75799072 | 360 | 626×360 | 18.600000 / 1,368,272 | 18.666667 / 1,372,490 | Present |
| 75799072 | 368 | 640×368 | 18.603000 / 1,453,400 | 18.666667 / 1,457,009 | Present |
| 51957501 | 720 | 404×720 | 12.686781 / 879,842 | 12.686778 / 889,003 | Absent in source |
| 80517371 | 240 | 134×240 | 18.922000 / 1,068,076 | 18.985633 / 1,071,844 | Present |
| 80517371 | 360 | 202×360 | 18.922000 / 644,267 | 18.985633 / 648,530 | Present |
| 80517371 | 480 | 270×480 | 18.922000 / 950,492 | 18.985633 / 954,718 | Present |
| 80517371 | 720 | 404×720 | 18.922000 / 4,416,412 | 18.985633 / 4,420,194 | Present |
| 80517371 | 1920 | 1080×1920 | 18.918900 / 23,629,680 | 18.952267 / 23,633,682 | Present |
| 55374481 | 240 | 426×240 | 9.080000 / 546,581 | 9.100000 / 549,793 | Present |
| 55374481 | 360 | 640×360 | 9.080000 / 965,448 | 9.100000 / 968,494 | Present |
| 55374481 | 480 | 852×480 | 9.080000 / 1,662,320 | 9.100000 / 1,665,390 | Present |
| 55374481 | 720 | 1280×720 | 9.080000 / 1,431,115 | 9.100000 / 1,434,155 | Present |
| 55374481 | 1080 | 1920×1080 | 9.080000 / 5,668,060 | 9.100000 / 5,671,124 | Present |

All **38 explicit quality/format downloads** and **40 preset/fallback selections** passed. Another **4 complete downloads** cover two concurrent MP4 transfers, original HLS transport-stream output, and the CLI: **82 complete files total**. No download quality gate was skipped. All source labels and actual heights matched; durations were within two seconds of the site's integer duration. Audio was retained wherever supplied. The observed HLS and MP4 duration differences reflect container timing, not truncated downloads.

## Packaging and limitations

The source archive and wheel were built successfully. Archive inspection confirms README, copied AGPL license, package exports, and `py.typed`; the wheel embeds README project metadata and the license. No publication or push was performed. Download outputs are temporary and outside the repository.

Counts are live observations rather than permanent catalog guarantees. Other operating systems, mirror hosts, translated content routes, authenticated features, and qualities not present in the sampled videos are unverified. No backend or Porn Fetch application files were changed.
