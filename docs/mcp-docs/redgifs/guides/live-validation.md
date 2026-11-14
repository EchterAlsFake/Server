---
title: "Live validation — RedGIFs API"
summary: "Exact 38-pass/12-rate-limit final suite result, per-rendition bytes/dimensions/audio, complete listing evidence and unresolved upstream ordering."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Live validation — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "validation"
  - "429"
  - "downloads"
  - "pagination"
  - "test results"
---

# Live validation — RedGIFs API

Commands below run from the `unofficial-api-for-redgifs` checkout, not the Server repository.


Run date: 2026-11-10. Linux; CPython 3.15.2; current local `eaf-base-api` 4.2.6.
Live fixtures reuse independent production/reference sessions with a two-second
request delay per core and a two-second initial bounded retry delay. All tests use real
RedGIFs requests. No mocked transport, recorded responses, account
cookies, skipped tests, or downloaded media are committed.

## Status: incomplete because of rate limits and upstream pagination

Exact command (from the repository root):

```bash
.venv/bin/python -m pytest -q -s --tb=short
```

**12 failed, 38 passed, 104 warnings in 363.26s (0:06:03)**. Exit status 1; zero skipped tests. All 12 terminal failures are
`RequestRetriesExhausted` caused by HTTP 429 after four attempts. The final paced run
completed all 50 tests. No further RedGIFs requests were made after this run.

The failures cover image search, all three video-search sorts, query/user/tag checks,
five complete-profile parameters, partial/profile-filter checks, and the single-page
profile check. In compound tests, assertions after the failed request were not reached;
those later assertions are not counted as verified in the final run.

- `https://api.redgifs.com/v2/gifs/search?tags=Amateur&order=latest&count=3&type=i&page=1`
- `https://api.redgifs.com/v2/gifs/search?tags=Amateur&order=trending&count=5&type=g&page=1`
- `https://api.redgifs.com/v2/gifs/search?tags=Amateur&order=latest&count=5&type=g&page=1`
- `https://api.redgifs.com/v2/gifs/search?tags=Amateur&order=top&count=5&type=g&page=1`
- `https://api.redgifs.com/v2/gifs/search?query=Amateur&order=trending&count=3&type=g&page=1`
- `https://api.redgifs.com/v2/users/dainty-blossomx2/search?count=6&page=1&order=new&type=g`
- `https://api.redgifs.com/v2/users/dainty-blossomx2/search?count=5&page=1&order=new&type=g`
- `https://api.redgifs.com/v2/users/naughtygardengirl/search?count=40&page=1&order=new&type=g`
- `https://api.redgifs.com/v2/users/nickiipeach/search?count=6&page=1&order=new&type=g`
- `https://api.redgifs.com/v2/users/rubycammilf/search?count=2&page=1&order=new&type=g`
- `https://api.redgifs.com/v2/users/naughtygardengirl/search?count=3&order=new&type=g&page=1`
- `https://api.redgifs.com/v2/users/dainty-blossomx2/search?count=40&page=1&order=new&type=g`

An earlier 43-test run returned **41 passed / 2 failed** before the suite was expanded
to 50 cases. Its two failures were retained completeness assertions for
`test_complete_profile[dainty-blossomx2-6]` and `[dainty-blossomx2-5]`: independent
live pages and a single-page snapshot demonstrated ten slots but only nine unique IDs.
No assertion was skipped or relaxed to count duplicate slots as complete. The final
rate limits prevent reaching these completeness assertions again, not their removal.

Outstanding conditions: the RedGIFs request quota must permit these public search and
profile requests again, and equal-timestamp pagination needs stable upstream ordering
or a stable cursor. No reset time was established during this run. No session rotation
to evade quotas, protection bypasses, or retries until a lucky page order were used
to conceal either blocker.

An earlier full run before pacing returned 6 failed / 44 passed: two upstream profile
completeness failures, three HTTP 429 failures, and one incorrect test assumption that
the site's audio flag guaranteed absence of an audio track. The legacy file was measured
with ffprobe and ffmpeg (audible AAC; mean -15.2 dB, maximum 0.0 dB). Its expected actual
audio is now asserted explicitly while preserving the inaccurate site flag. Rate-limit
failures were not skipped; the final paced suite was rerun after cooldown.

The shared backend emits Tenacity's `initial`-parameter deprecation warning. This is
reported as a dependency warning; the shared project was not altered.

## Source and capability checks

The list below describes implemented coverage exercised across the recorded runs.
Source, host, direct-download, CLI, collection and niche checks pass in the final run.
Search and user-listing gates are blocked by the listed HTTP 429 responses in that run.
The image test completes both rendition downloads before failing at image search.

- Video samples: `hotpinkacrobatickitfox`, `ivoryhauntingblackbird`, legacy
  `happyfrenchindianspinyloach`; rich metadata/download sample `toughlongtermbanteng`.
  Representative watch URL: `https://www.redgifs.com/watch/hotpinkacrobatickitfox`.
- Independent API, independent HTML, combined loading, both source load orders,
  deferred fields, serialization without fetching, explicit type mismatches and
  unavailable video responses are exercised. API dates/duration/tags/author/dimensions/
  renditions are compared to the correct live detail object.
- HTML titles/page descriptions/raw dates remain available; normalized publication
  dates, statistics, original dimensions and media URLs prefer API data. Empty and
  missing descriptions remain distinct from unloaded fields.
- Image sample: `https://www.redgifs.com/watch/deliciousfrontelephant`, with API/HTML/
  combined/deferred loading and complete HD/SD JPG downloads.
- Live page hosts: `redgifs.com`, `www.redgifs.com`; watch and embed routes.
  Live CDN identity inputs: `media.redgifs.com` HD/SD/silent MP4 and HD/SD/thumbnail JPG.
  No language variants or proxy hosts are accepted.
- Search: query, tag filter, trending/latest/top, verified videos with latest ordering,
  verified creator search; image search, complete and trending tag directories.
- Users, image/video tabs, public collection directory/details/mixed item streams,
  niche directory/details/video streams and video author/niche relationships.
- Partial stream closure, deferred iterator models, original ordering, profile tag/top
  filters and caller-owned core/session preservation.
- Two CLI invocations download real files: direct URL argument and UTF-8 URL file.

## Completed media downloads

Each reported file is a full download through `Video.download(DownloadConfigRAW(...))`
or `Image.download(...)`, inspected with `ffprobe` for format, dimensions, duration and
audio. Callbacks are exercised and caller configuration is preserved. Source URLs are
refreshed before downloads. All samples also download `best`, `half`, and `worst`;
SD is selected for the lower-middle/worst selectors and HD for best when both exist.
Legacy `happyfrenchindianspinyloach` reports `hasAudio=false` but its real MP4 has
audible AAC audio; actual audio is measured and asserted independently of that flag.
Silent is explicit. Absent silent and unsupported numeric quality requests are rejected.

| Video ID | Rendition | Bytes | Dimensions | Seconds | Audio |
|---|---|---:|---|---:|---|
| hotpinkacrobatickitfox | hd | 6145756 | 1080x1920 | 6.467 | True |
| hotpinkacrobatickitfox | sd | 1201410 | 480x854 | 6.467 | True |
| hotpinkacrobatickitfox | silent | 6057605 | 1080x1920 | 6.467 | False |
| ivoryhauntingblackbird | hd | 5456747 | 1080x1920 | 7.767 | True |
| ivoryhauntingblackbird | sd | 944146 | 480x854 | 7.767 | True |
| ivoryhauntingblackbird | silent | 5375433 | 1080x1920 | 7.767 | False |
| toughlongtermbanteng | hd | 12195647 | 1080x1920 | 31.400 | True |
| toughlongtermbanteng | sd | 3013502 | 480x854 | 31.400 | True |
| toughlongtermbanteng | silent | 11614962 | 1080x1920 | 31.400 | False |
| happyfrenchindianspinyloach | hd | 4616356 | 1280x640 | 15.000 | True |
| happyfrenchindianspinyloach | sd | 1432872 | 640x320 | 15.000 | True |

| Image ID | Rendition | Bytes | Dimensions |
|---|---|---:|---|
| deliciousfrontelephant | hd | 320398 | 1200x1600 |
| deliciousfrontelephant | sd | 122777 | 800x1067 |

The concurrent check downloads different videos simultaneously, then repeats one SD
download and compares its complete bytes. It validates durations independently to catch
cross-video source leakage. CLI files are additionally probed. No signed source URLs or
session tokens are included in this report.

HLS: actual HD/SD playlists for `hotpinkacrobatickitfox` are fetched and checked for
`EXT-X-MAP`, `EXT-X-BYTERANGE`, and `EXT-X-ENDLIST`. HLS **downloads remain unsupported**:
the current shared downloader discards required byte ranges. No HLS download or remux
success is claimed. RAW returns a boolean; HLS reports and metadata tag export are not
advertised by this integration.

## Complete listing comparisons

Each successful full comparison checks every intended page and the entire ordered ID
sequence against an independent live JSON reader. The current first-party profile and
collection JavaScript identifies these JSON responses as the rendered tab data; the
investigation notes record the relevant assets. No recommendation/boosted arrays are
mixed into the intended listing.

- collection weirdjack/d7ddef5fb0: public expected=246 actual=246; stored contentCount=258; delta=12
- niche duo-chastity: expected=5 actual=5; niche gifs=5

The final paced run reconfirms the collection and niche comparisons above.
Earlier successful full-profile comparisons recorded:

- `naughtygardengirl`: expected/actual video IDs 76/76; one public image; stored published count 78.
- `nickiipeach`: expected/actual video IDs 17/17; one image; stored published count 18.
- `rubycammilf`: expected/actual video IDs 4/4; six images; stored published count 10.
- `dainty-blossomx2` in a single page: expected/actual 10/10.

These earlier profile comparisons were not reverified in the final paced run because
of HTTP 429. They are retained as dated evidence, not counted as current passing gates.

The collection matches all 246 public records in pages of 100/100/46, including two
images on the final page. Its stored `contentCount=258` is 12 higher. The API supplies
neither those additional IDs nor reasons for the discrepancy; none are invented.
`naughtygardengirl` exposes 76 videos and one image versus 78 stored published records:
one record is not publicly accounted for, with no API reason disclosed. `nickiipeach`
(17 videos plus one image) and `rubycammilf` (four videos plus six images) reconcile their
stored published counts. `rubycammilf` covers an exact multiple at two videos per page;
`nickiipeach` covers a partial final page at six per page. Start-page ranges and
beyond-last behavior are exercised. Collections discover page 1 to avoid mistaking a
beyond-last HTTP 404 for an unavailable collection.

### Outstanding profile completeness gate

For `dainty-blossomx2`, all ten uploads have timestamp `1782281354`.

| Requested page size | Slots | Unique IDs | Repeated ID | Missing versus single page |
|---|---:|---:|---|---|
| 6 | 10 | 9 | activetiredaustralianfreshwatercrocodile | icyhappyhamadryad |
| 5 | 10 | 9 | icyhappyhamadryad | activetiredaustralianfreshwatercrocodile |
| 40 (one page) | 10 | 10 | none | none |

Exact failing endpoint family:
`https://api.redgifs.com/v2/users/dainty-blossomx2/search?count=5&page=1&order=new&type=g`
and page 2; likewise count 6. The page responses themselves overlap despite unchanged
content, no promoted cards, and `total=10`. The IDs can change as ties reorder.
The library preserves the raw sequence rather than hiding duplicates or manufacturing
missing records. Requests of count 40 are a verified workaround for this small profile.
Completion needs stable upstream tie ordering/cursors; a single-page workaround does
not prove reliable pagination for all larger profiles. The failing gates remain visible.

## Packaging

Exact command:

```bash
.venv/bin/python -m build --outdir dist
```

Wheel and sdist build successfully. The sdist includes README, LICENSE, `py.typed` and
the public package; the wheel includes README content in metadata, the AGPL license,
`py.typed`, public exports and the CLI entry point. LICENSE matches the XVideos reference
byte for byte. Nothing was published, pushed, or wired into Porn Fetch.

Gallery enumeration, private/account actions and personalized/recommendation feeds are
not implemented. These are documented capability boundaries, not successful test gates.
