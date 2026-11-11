---
title: "Live validation — Bellesa API"
summary: "Recorded 107 distinct passing final live cases across runs, 49 full files, per-quality matrix and complete profile reconciliation."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Live validation — Bellesa API", "Bellesa live validation"]
keywords: ["Bellesa", "bellesa_api", "live tests", "107", "49", "ffprobe", "pagination", "reconciliation", "validation"]
---

# Live validation — Bellesa API

The implementation validation on **2026-11-10** covered **107 distinct final live test
cases across runs**, with no unresolved final-case failures or skips, and **49 finished
media files**. This is recorded implementation evidence, not a claim that the entire
changing catalog or a new connection has just been retested by reading this document.

The initial 103-case full run had **100 passed / 3 failed / 0 skipped** in about 28 minutes.
Three test expectations were corrected: two expected bare `NotFound` instead of shared
`MediaLoadError` preserving `NotFound`; one assumed an unmatched search query even though
the site matched one of its terms. A corrected **57-case** metadata/profile/listing/search
run passed; the corrected three regressions also passed after the original process ended.
An added HLS metadata-export test and a missing-resolution-label test each passed.
The final union covers 107 distinct cases, rather than 107 passing in a single run.

The connection was mobile while travelling. Slow/transient requests were treated as
environmental uncertainty; a timeout was not evidence of a site outage. Shared Tenacity
deprecation warnings were observed. Python 3.15/Linux and FFmpeg/ffprobe were used.

## Complete files and quality matrix

Both HLS (remuxed MP4) and direct MP4 were fully downloaded for every actual quality in
four samples: 7054 (six renditions), 1189 (three), 4651 (four), and 1094 (three unusual
4:3 renditions). This accounts for 32 per-quality files. Additional complete files
covered best/half/worst/numeric fallback in both formats, two different videos concurrently
on one core, refreshed repeats, two CLI formats, and HLS title/artist metadata export.

`ffprobe` checked dimensions, audio, plausible duration and a valid container. Callbacks
reached completion and caller configuration stayed unchanged. A HEAD request or one HLS
segment was not counted as a complete download. Temporary media was removed after checks.
See [the measured quality matrix](downloading.md).

## Complete profile reconciliation

Independent extraction from the exact rendered listing state was compared page-by-page
and as a complete ordered sequence with API output. Recommendations and campaigns were
excluded. No missing, unexpected or duplicate IDs remained.

| Profile | Listing pages | Expected free IDs | API IDs |
|---|---|---:|---:|
| Lily Starfire, performer | 3 | 3 | 3 |
| Kenna James, performer | 9+9+9+9+9+9+3 | 57 | 57 |
| Belle Says, channel | 4 | 4 | 4 |
| Zero To Hero, channel | 24+6 | 30 | 30 |
| Erika Lust, channel | 24 | 24 | 24 |

Lily Starfire's profile count of 7 spans more than the free listing's 3; no unrelated
videos were added to match it. Exact full-page, partial final-page, per-page, middle,
last, beyond-last and pages="all" behavior were checked where applicable. Profile sorts
matched the rendered free listing. Channel pagination uses `/videos?providers=...` to
avoid the page-dropping channel redirect.

## Running the live suite

From the provider checkout with local backend dependencies installed:

```sh
.venv/bin/python -m pytest -q --junitxml=/tmp/bellesa-live-results.xml
.venv/bin/ruff check bellesa_api
uv build
```

Every provider test uses real requests. The full suite downloads complete files and may
transfer substantial media. The documentation build/link/catalog checks do not perform
these transfers. Historical XML artifacts were stored outside the checkout under `/tmp`;
keeping those artifacts elsewhere is the caller's responsibility.

Source-loading coverage includes API-only, HTML-only, both orders, combined/deferred
loading, field serialization, custom iterator source/field loading, missing resources,
and a real video (2013) with absent resolution labels. Both accepted page hosts preserved
identity and usable media. Representative routes include `/videos/7054`, `/videos/1094`,
`/videos/11157`, `/videos/2773`, `/performers/kenna-james`, and `/channels/zero-to-hero`.

Authenticated/premium-only playback, encrypted/DRM media, regional access bypass,
non-English hosts, proxies, non-video story/article APIs and unobserved layouts remain
outside the verified scope. See [supported hosts](../supported-platforms.md).
