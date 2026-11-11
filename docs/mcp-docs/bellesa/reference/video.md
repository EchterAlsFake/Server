---
title: "Video — Bellesa API"
summary: "Video source-aware metadata, measured renditions, advertised versus actual quality, relationships, download and refresh_media signatures. Symbols: url core video_id title title_tag description description_html thumbnail_url duration length publish_date posted_on views likes tags categories category_urls primary_category pornstars pornstars_urls channel_urls author author_link advertised_qualities m3u8_base_url preview_video_url source_id preview_source_id trailer_source_id access highlights canonical_url og_title available_qualities direct_sources renditions content_url Video.download Video.refresh_media Video.get_author Video.get_performers Video.related_videos. Rendition keys: quality source_quality width height bandwidth fps codecs hls_url direct_url."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Video — Bellesa API", "Bellesa video"]
keywords: ["Bellesa", "bellesa_api", "Video", "duration", "advertised_qualities", "available_qualities", "renditions", "direct_sources", "refresh_media", "download", "get_author", "get_performers", "related_videos"]
---

# Video — Bellesa API

`Video(url=..., core=..., video_id=None)` is a keyword-only `BaseMedia` dataclass.
Prefer `await client.get_video(url)`. Construction validates the URL, preserves its
accepted host, strips query/fragment, and derives a string numeric `video_id`. An
explicit `video_id` must agree with the URL. No network request occurs in construction.

## Metadata fields

Fields may be known absent (`None` or an empty list) or unresolved. Reading an unresolved
field raises `DataNotLoadedError`; inspect `is_field_loaded()` or load it explicitly.
Common fields prefer API over HTML regardless of load order.

| Fields | Type / units | Source |
|---|---|---|
| `url`, `video_id`, `core` | `str`, `str`, `BaseCore` | Identity |
| `resolved_url` | `str` or `None`, response transport metadata | Shared backend |
| `title`, `title_tag` | `str` or `None` | api, html |
| `description`, `description_html` | Plain text and original HTML; `str` or `None` | api, html |
| `thumbnail_url`, `preview_video_url` | `str` or `None` | api, html |
| `duration`, `length` | Integer seconds; `minutes:seconds` display string | api, html |
| `posted_on`, `publish_date` | Unix seconds; UTC ISO 8601 string | api, html |
| `views`, `likes` | `int` or `None`; mutable site statistics | api, html |
| `tags`, `categories` | Lists of names | api, html |
| `primary_category` | Category name or `None` | api, html |
| `category_urls` | Category URL list | api, html |
| `pornstars`, `pornstars_urls` | Performer names and URLs | api, html |
| `channel_urls` | Provider/channel URL list | api, html |
| `author`, `author_link` | First provider's name and channel URL | api, html |
| `advertised_qualities` | Integer labels supplied in metadata; possibly empty | api, html |
| `source_id`, `preview_source_id`, `trailer_source_id` | Player identifiers or `None` | api, html |
| `m3u8_base_url` | Public HLS master URL or `None` | api, html |
| `access`, `highlights` | Site-supplied access mapping and editorial list | api, html |
| `canonical_url`, `og_title` | Open Graph values or `None` | html only |
| `available_qualities` | Sorted actual shorter-dimension values, `list[int]` | media |
| `direct_sources` | Actual quality → direct MP4 URL, `dict[int, str]` | media |
| `renditions` | List of rendition mappings described below | media |
| `content_url` | Highest actual rendition's direct URL | media |

The `media` loader first resolves `m3u8_base_url` if needed, then reads the live HLS
master. It does not download the video file. A deferred object's prerequisite fields
normally select API; loading HTML first allows the media loader to reuse that data.
This dependency does not load HTML automatically.

Each rendition maps `quality`, `source_quality`, `width`, `height`, `bandwidth`, `fps`,
`codecs`, `hls_url`, and `direct_url`. `quality` is the actual shorter dimension;
`source_quality` retains the site's file label. Label 480 commonly measures 800×450.
Video 1094 has labels 360/480/720 but actual qualities 480/600/960. See
[downloads](../guides/downloading.md) before selecting numeric quality.

## Relationships

```python
async def get_author(load_api: bool = True) -> Channel | None: ...
async def get_performers(load_api: bool = True) -> list[Performer]: ...
def related_videos(*, pages=1, start_page=1, iterator_config=None) -> ScrapeStream[Video]: ...
```

Relationship methods load the required video fields and return usable profile objects.
With `load_api=False`, returned profiles are deferred. Author is the first channel,
not an individual performer. Related videos use the same channel, exclude the current
video, and use pages of 6. This stream is separate from the site's randomized autoplay
rail. If no author exists, it is empty.

## Download and refresh

```python
async def download(configuration: DownloadConfigHLS | DownloadConfigRAW): ...
async def refresh_media() -> Video: ...
```

`download()` requires `access.public == 1`, loads media, copies configuration and applies
the shared filename rule. HLS returns the shared report/boolean; RAW returns a boolean.
It does not invent media authorization. Availability and cancellation errors retain
the shared behavior described in [errors](../troubleshooting/errors.md).

`refresh_media()` invalidates this video's API text cache entry and returns a **new**
Video with fresh API and media sources. It leaves the original object's metadata and
the core's session headers unchanged. HTML-only fields remain deferred on the new object.
Shared `to_dict()` omits unresolved fields and the core by default, without fetching.
