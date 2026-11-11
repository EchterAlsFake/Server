---
title: "YouJizz API guide"
summary: "Complete provider API guide and source semantics."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["YouJizz API guide"]
keywords: ["YouJizz", "youjizz_api", "reference", "api-guide"]
---

# YouJizz API guide

# YouJizz API Documentation

# Features

| Capability | Public interface |
| --- | --- |
| Video metadata | `Client.get_video()`, `Video(BaseMedia)`, independent API/HTML/deferred loading |
| Video downloads | MP4 with `DownloadConfigRAW`; HLS with `DownloadConfigHLS`, optional remux and reports |
| Listings | Popular, newest, top/all/week/month, trending, HD and random via `Client.videos()` / `Client.random_videos()` |
| Search | Relevance/newest/views/rating/length, duration, phrase mode, title filter, date bounds |
| Tags/categories | `Client.categories()`, `Client.get_category(url)`, `Category.videos()` |
| Pornstar directory | Alphabetical `Client.pornstars(letter)`, `Pornstar.videos()` |
| Public user uploads | `Client.get_user()`, `User.videos()` with complete numbered pagination |
| Relationships | `Video.get_author()`, `Video.related_videos()` |
| Comments | Read-only, separately lazy `comments` source; typed comments and reply/author references |
| CLI | Metadata inspection and MP4/HLS downloads |

A pornstar is an entry in the site's alphabetical directory whose videos link to keyword search. There is no separate pornstar biography/profile endpoint. Directory counts are snapshots and can differ from current search matches. No Model or Channel classes are invented.

Networking, caching, retries, transport settings, proxies, iterator controls, cancellation, and downloads use the current `eaf-base-api` backend. A client closes its own core; an injected core remains owned by the caller. Close partially consumed generators with `contextlib.aclosing`.

# Supported Platforms

Live validation is performed on this Linux environment with Python 3.13 and FFmpeg/ffprobe. Other platforms are not yet verified.

# Installation

Install the distribution (publication is managed separately):

```bash
pip install unofficial-api-for-youjizz
```

Python 3.12+ and `eaf-base-api[hls]>=4.2.6` are required. FFmpeg is needed for HLS remuxing and ffprobe for live download tests. The local shared backend is authoritative; see [live validation](../guides/live-validation.md) for the development environment setup.

# Quickstart

```python
import asyncio
from contextlib import aclosing
from youjizz_api import Client, DownloadConfigRAW, IteratorConfig
from youjizz_api.modules.sorting import Sort

async def main():
    async with Client() as client:
        video = await client.get_video("https://www.youjizz.com/videos/video-48914471.html",
                                       load_api=True, load_html=True)
        print(video.title, video.duration, video.available_qualities)
        await video.download(DownloadConfigRAW(quality="worst", path="./downloads"))
        stream = client.search_videos("Leah Gotti", pages=2, sort=Sort.VIEWS,
                                     iterator_config=IteratorConfig(order="original"))
        async with aclosing(stream):
            async for result in stream:
                item = result.unwrap()
                await item.load_fields("title")
                print(item.video_id, item.title)

asyncio.run(main())
```

`pages` is a positive page count or `"all"`; `start_page` is one based. HTML pagination follows the site's actual Next links, retains filters, and detects repeated pages. User uploads use the site's public ID list and the same 24-ID page slices as its Angular UI. `IteratorConfig` retains item concurrency, source/field loading, error modes, and original/completion ordering. HTML pages are discovered sequentially; page concurrency does not prefetch unknown Next links. Listing objects initially contain identity only; opt into detail loading with `load_specific_sources` or `load_specific_fields`.

```python
from youjizz_api import Client

async def inspect_sources():
    async with Client() as client:
        video = await client.get_video("30792291", load_api=False, load_html=False)
        print(video.to_dict())            # no network fetch, unloaded fields omitted
        await video.load_sources("api")   # /api/thumbs?ids=30792291
        await video.load_fields("tags")   # HTML only
        await video.load_sources("comments")
        print(video.comment_count)
```

Synchronous access to an unloaded field raises the shared `DataNotLoadedError`. `None` means the loaded source knows the field is absent. Empty-title uploads with an empty URL slug are accepted; pages without VideoObject JSON-LD use Open Graph only when both the hidden ID and the Open Graph URL identify the requested video. API-only, HTML-only, both, and deferred loading are independent; loading either order gives the same precedence.

| Source | Fields and semantics |
| --- | --- |
| API (`/api/thumbs`) | Title, duration (integer seconds), length (display string), views (decimal string), thumbnail, preview URL, HD flag, thumbnail count, sprite URL |
| HTML (matching VideoObject JSON-LD, identity-checked Open Graph fallback, DOM, public `dataEncodings`) | Title/duration/length/views/thumbnail fallback; description; publish date (site calendar date, no invented timezone); canonical/embed URLs; tags; rating (nullable float out of 5); rating votes (integer); author ID and public author link/name when rendered; direct/HLS maps and available qualities |
| Comments (`/api/comments/{id}`) | Typed comments (Unix timestamps in seconds), including replies, excluding like/dislike action rows; count is the number of these returned records, not an inferred UI total |

API precedes HTML for shared fields except thumbnails: HTML takes precedence because the thumbnail API returns an empty string on some legacy videos. API-only loading reports that absence as `None`. Rating uses HTML precision; the thumbnail API's rounded score is not substituted. `available_qualities` is the sorted union of the site's numeric encoding labels; `direct_urls` and `hls_urls` give format-specific availability. Labels can include 288, 368, and portrait height 1920. Actual dimensions are checked against completed downloads in the live suite.

`m3u8_base_url` retains the site's Auto master when present, otherwise a real per-quality master. Downloads select the per-quality master: Auto can omit older renditions. Quality presets are `best`, `half` (middle sorted label), and `worst`; a missing numeric quality uses the nearest label, preferring the higher one on a tie. Signed query strings remain intact. Download configurations are copied without replacing callbacks or cancellation events. `await video.refresh_sources()` returns a new HTML-loaded Video after refreshing the core cache; use it when source URLs expire.

User profile metadata respects the site's public flags, including hidden usernames. Public upload lists remain available when the site separately marks videos public. Raw profile responses, contact information, internal fields, and private favorites are not exposed. Account management, uploads, favorites, and playlists are outside the supported public interface; the site's playlist feature is disabled and the observed favorites request failed with HTTP 500.

Only `youjizz.com` and `www.youjizz.com` are accepted. The apex redirects to www. Numeric video IDs and `/videos/embed/{id}` links are supported. No alternate mirror or language subdomain was confirmed. The site disables its search-HD feature and the rendered `hd=1` search control still returns SD videos; no HD search filter is advertised. Its separate HD listing remains available. The UI offers English and Chinese through client-side translation; this provider does not invent locale-specific routes. Access challenges and required age verification fail explicitly.

# CLI

```bash
python -m youjizz_api --download 48914471 --info
python -m youjizz_api --download 48914471 --quality 288 --format hls --output ./downloads
youjizz_api --download 48914471 --quality worst --format mp4 --output ./downloads
```

`--info` omits expiring video source URLs. HLS downloads remux to MP4; RAW downloads already contain MP4. For explicit output filenames, use the Python API with `no_title=True` and a complete `path`.

# Live Tests

```bash
.venv/bin/python -m pytest -q
```

Latest validation: **63 passed, 0 failed, 0 skipped**; **82 complete-file download checks** across MP4 and HLS.

These are real network tests, including complete downloads and ffprobe inspection; no offline fixtures or mock tests are included. See [live validation](../guides/live-validation.md) for commands, counts, quality evidence, and pagination reconciliation. Tests do not require login cookies and never read browser cookies.
