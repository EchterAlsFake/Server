---
title: "Live validation — Porn.com API"
summary: "Historical 2026-11-10 implementation run: 48 passing live tests, 15 complete files, per-quality evidence and exact complete profile reconciliation."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Live validation — Porn.com API", "Live validation Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "48", "15", "live validation", "ffprobe", "reconciliation", "pagination"]
---

# Live validation — Porn.com API

The implementation run on **2026-11-10** completed **48 passed / 0 failed /
0 skipped** in **255.80 seconds**, with **15 complete media files** checked.
This is recorded implementation evidence, not a claim that writing or building
these docs reruns the website suite. Linux, CPython 3.15.2, local `eaf-base-api`
4.2.6, FFmpeg, and ffprobe were used. A separate category/source check passed
2 cases; an isolated wheel smoke check also used registry `eaf-base-api` 4.2.6.
Shared Tenacity `initial`-parameter deprecation warnings were observed.

## Complete quality matrix

Every row is a full `Video.download` through the shared backend, followed by
ffprobe checks for dimensions, duration, audio, and plausible output size.
Completed reports had no missing segments. Temporary media was removed.

| Scene / host context | Height | Dimensions | Duration | Finished MP4 bytes | Audio |
|---|---:|---|---:|---:|---|
| `208974141` / `de` | 360 | 640×360 | 345.023222 s | 20,488,660 | AAC |
| `208974141` / `de` | 480 | 854×480 | 345.023222 s | 34,698,749 | AAC |
| `208974141` / `de` | 1080 | 1920×1080 | 345.023222 s | 115,687,164 | AAC |
| `208581087` / `www` | 360 | 640×360 | 631.689889 s | 37,198,539 | AAC |
| `208581087` / `www` | 480 | 854×480 | 631.689889 s | 63,324,250 | AAC |
| `208581087` / `www` | 720 | 1280×720 | 631.689889 s | 126,479,802 | AAC |

The other nine complete files exercised five preset/fallback/repeat operations
on `208974141` (`best`, `half`, `worst`, missing 720→480, repeated `worst`), one
unremuxed TS output (23,140,168 bytes), two concurrent different-video downloads,
and one CLI download. Preset operations checked actual MP4 title/comment tags
and `metadata_written`; explicit qualities checked progress and unchanged caller
configuration. HEAD requests, URL extraction, and single segments were not
counted as completed media evidence.

## Complete profile comparisons

A separate Python `html.parser` observer enumerated every live video ID, ad
slot, and page independently of production Selectolax extraction. The entire
ordered sequence/multiset and every page matched.

| Profile | Pages | Expected HTML entries | API entries | Unique IDs | Advertised total | Native ad replacements |
|---|---:|---:|---:|---:|---:|---:|
| `/bratty-sis` | 1 | 4 | 4 | 4 | 6 | 2 |
| `/brazzers` | 14 | 1,618 | 1,618 | 1,617 | 1,660 | 42 |
| `/azumi-mizushima` | 1 | 1 | 1 | 1 | 1 | 0 |
| `/mia-khalifa` | 23 | 1,426 | 1,426 | 1,423 | 1,494 | 68 |

Entries plus native ad replacements equal advertised totals. Brazzers repeats
`202547626` on pages 6/7. Mia repeats `168759490` on pages 1/8, `176675344` on
pages 3/4, and `197990046` twice on page 6. These are website occurrences,
not additional API videos or silently deduplicated results.

Brazzers has thirteen pages of 117 entries and a final 97. Mia has seven pages
of 117, then 68, fourteen pages of 37, then 21; valid pages continue to 23 after
Next is disabled at 13. The next page is empty for Bratty Sis/Brazzers and 404
for Azumi/Mia. First/next/middle/final/beyond-last, finite/all/start-page options,
completion ordering, partial final pages, and partial stream closure were checked.

## Metadata and discovery coverage

Eager/deferred/repeated/concurrent HTML loads, serialization, unloaded fields,
listing seed preservation, unavailable referrals, real missing scenes, related
objects, search redirects, all added periods and combined filters were checked.
All twelve accepted hosts returned consistent scene identity, locale, master and
variant access, and corresponding profile/listing data. English/German contexts
were used for complete downloads. Gay/trans listing/search/directory variants
were exercised; their sampled video grids contained referrals.

Category/source indexes were compared on representative two-page samples, not
their entire catalogs. Full directory comparisons matched 2,189 performer and
448 channel entries in the established session, while the straight category
directory had 1,099 entries. Initial versus established sessions can differ.

## Run the live suite

From `unofficial-api-for-porn` beside the local backend checkout:

```sh
uv sync --group dev
uv pip install -e '../eaf_base_api[hls]'
.venv/bin/python -u -m pytest -q -s --tb=short
```

Tests make real requests and full downloads into temporary directories. The
documentation/catalog checks do not repeat those downloads. Protected streams,
REST video metadata (401), pictures (403), authenticated features, separate
Model/User/Playlist interfaces, full-video direct MP4, and unobserved layouts
remain outside verified support. See [supported platforms](../supported-platforms.md).
