---
title: "Video \u2014 Porndoe API"
summary: "Video metadata fields, player sources, author and performer objects, related videos, and downloading."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Video \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "video"
---

# Video — Porndoe API

`Video(url=..., core=...)` is a keyword-only `BaseMedia` dataclass.
`await client.get_video(url)` loads its `html` source. This includes a JSON-LD
graph, visible page data and the player service. The service gets a per-request
Referer and a video-specific cache URL, so concurrent videos cannot share
the wrong player response. Missing detail fields are `None`; source maps/lists
are empty when no variants are available. Unknown listing fields remain unloaded.

| Field | Type | Meaning |
| --- | --- | --- |
| `url` | `str` | Resource page URL, preserving the requested host and filters. |
| `core` | `BaseCore` | Shared BaseCore networking and download backend. |
| `resolved_url` | `str \| None` | Final response URL, when recorded by the shared request helper. |
| `video_id` | `str \| None` | Public hash from /watch/<hash>. |
| `internal_video_id` | `str \| None` | Numeric player ID, represented as a string. |
| `title` | `str \| None` | Video title. |
| `description` | `str \| None` | Description or plain-text profile biography. |
| `thumbnail_url` | `str \| None` | Poster, profile image, category image, or directory thumbnail URL. |
| `preview_video_url` | `str \| None` | Short preview clip URL. |
| `publish_date` | `str \| None` | ISO upload date from JSON-LD. |
| `publish_date_relative` | `str \| None` | Relative upload time shown on the page. |
| `content_url` | `str \| None` | JSON-LD watch page URL; this is not the MP4 download URL. |
| `duration` | `int \| None` | Duration in integer seconds. |
| `length` | `str \| None` | Formatted MM:SS or HH:MM:SS duration. |
| `author_name` | `str \| None` | Producing channel name. |
| `author_link` | `str \| None` | Producing channel profile URL. |
| `pornstars` | `list[dict[str, str]] \| None` | Performer dictionaries containing name and url. |
| `pornstars_urls` | `list[str] \| None` | Featured performer profile URLs. |
| `categories` | `list[dict[str, str]] \| None` | Category dictionaries containing name and url. |
| `tags` | `list[str] \| None` | Tag names. |
| `tags_urls` | `list[str] \| None` | Tag listing URLs, in the same order as tags. |
| `views` | `str \| None` | Displayed total view count as a string. Listing summaries may use k/M abbreviations. |
| `likes` | `str \| None` | Like count as a string, from the player service. |
| `dislikes` | `str \| None` | Dislike count as a string, from the player service. |
| `rating_votes` | `str \| None` | Sum of likes and dislikes, as a string when both are available. |
| `rating_percent` | `str \| None` | Like percentage, as a string to one decimal place; None for no votes. |
| `video_quality` | `str \| None` | HD/SD label supplied by JSON-LD. |
| `is_hd` | `bool \| None` | HD flag. |
| `is_vr` | `bool \| None` | VR flag when present in a listing; None if unknown on the detail page. |
| `is_exclusive` | `bool \| None` | Exclusive flag when present in a listing; None if unknown on the detail page. |
| `license_url` | `str \| None` | License URL reported by the site; a metadata value, not an independent grant of rights. |
| `direct_download_urls` | `dict[int, str] \| None` | Playable MP4 sources as {height: signed_url}; signup links and deo sources are excluded. |
| `video_qualities` | `list[int] \| None` | MP4 heights sorted from lowest to highest, matching direct_download_urls keys. |
| `hls_download_urls` | `dict[int, str] \| None` | Playable HLS variants as {height: signed_url}; empty if none are supplied. |
| `m3u8_base_url` | `str \| None` | Highest available HLS variant URL, or None. A variant, not a fabricated master playlist. |

### Related objects

```python
channel = await video.get_author
async for star in video.get_pornstars:
    print(star.name)
async for result in video.get_related_videos(iterator_config=None):
    related = result.unwrap()
```

`get_author` is an async property returning a loaded `Channel` or `None`.
`get_pornstars` is an async-generator property yielding loaded `Pornstar` objects.
Both share the video's core. `get_related_videos` is a method returning a
`ScrapeResult[Video]` iterator from the page's related-video cards.

### download

```python
await video.download(configuration: DownloadConfigRAW | DownloadConfigHLS)
```

Returns `bool | DownloadReport`, according to the selected base downloader.
MP4 uses `BaseCore.legacy_download`; HLS uses `BaseCore.download` and requires
actual HLS variants. The supplied configuration is copied. Title-based filenames
are applied unless `no_title=True`.

Only `sources.mp4` entries of type `video` are exposed as direct MP4 sources.
Signup/upgrade entries and the separate `deo` group are excluded. Signed URLs
expire and can depend on the IP; use a freshly fetched Video for a later download.
The HTML view total is retained because the service's view counter differs.

See [downloading](../guides/downloading.md) and [errors](../troubleshooting/errors.md).
