---
title: "Video — Porn.com API"
summary: "Video fields, exact duration, listing summaries, is_playable referrals, get_qualities Rendition objects and related-object methods."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Video — Porn.com API", "Video Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "Video", "Rendition", "duration", "is_playable", "get_qualities", "get_author", "get_pornstars", "get_source", "related_videos"]
---

# Video — Porn.com API

`Video(url=..., core=...)` is a keyword-only `BaseMedia` dataclass. Prefer
`await client.get_video(url)` for eager HTML metadata, or pass `load_html=False`
for deferred loading. The stable URL ID must match the response scene identity.

| Field | Type | Meaning |
|---|---|---|
| `url` | `str` | Requested scene URL; verified host and locale are preserved. |
| `core` | `BaseCore` | Caller-configured request/download backend. |
| `resolved_url` | `str \| None` | Actual response URL recorded by the shared backend. |
| `video_id` | `str \| None` | Numeric scene ID as a string; populated from the URL. |
| `title` | `str \| None` | Target main heading, not generic WordPress metadata. |
| `thumbnail_url` | `str \| None` | Native player poster; listing image retained if absent on a referral page. |
| `length` | `str \| None` | M:SS for exact player duration, or retained rounded listing label. |
| `duration` | `int \| None` | Exact integer seconds from the native player; unknown for referral-only detail pages. |
| `language` | `str \| None` | Response HTML locale, for example de-DE. |
| `tags` | `list[str] \| None` | Category/tag labels on the target scene. |
| `categories_urls` | `list[str] \| None` | Real category URLs in the same order as tags. |
| `pornstars_names` | `list[str] \| None` | All observed performer names, including unlinked names. |
| `pornstars_urls` | `list[str] \| None` | Only performer names that have real profile links. |
| `author_name` | `str \| None` | Channel label where actually supplied; not inferred from a title. |
| `author_link` | `str \| None` | Real channel link where supplied. |
| `m3u8_base_url` | `str \| None` | Signed native HLS master, preserved intact. |
| `embed_url` | `str \| None` | No independent embed URL was verified; currently None after HTML loading. |
| `is_playable` | `bool \| None` | Whether the scene exposes the native HLS player. |
| `unavailable_reason` | `str \| None` | Real referral/no-player notice; None for the checked native scenes. |
| `thumbnail_template` | `str \| None` | Player thumbnail template where present; empty values become None. |
| `thumbnail_count` | `int \| None` | Player-reported thumbnail position count. |
| `rating` | `int \| None` | Listing-only integer rating percentage, not vote count. |
| `preview_video_url` | `str \| None` | Listing-only preview clip, not the full video. |
| `source_name` | `str \| None` | Source website label from the originating listing card. |
| `source_url` | `str \| None` | Actual source-index URL from the listing card. |
| `link_url` | `str \| None` | Original listing destination, including an outbound referral link when supplied. |

HTML-backed fields use `media_field("html")`. Unresolved fields raise
`DataNotLoadedError`; `None` means known absence after loading. Listing summaries
seed only observed fields and retain listing-only rating/preview/source/link
data when scene HTML is loaded. Direct scene getters do not fetch a listing to
invent these optional observations.

The scene document's JSON-LD, canonical link, Open Graph title, dates, and image
refer to the generic WordPress `/scene` page. They are excluded. There is no
fabricated video description, view count, upload date, or vote count.

## Renditions

`await video.get_qualities()` loads required HTML and the actual HLS master. It
returns a list of immutable `Rendition` objects, sorted by height then bandwidth:

| Field | Type | Meaning |
|---|---|---|
| `width` | `int` | Actual master-playlist width. |
| `height` | `int` | Actual master-playlist height. |
| `bandwidth` | `int \| None` | Declared rendition bandwidth. |
| `url` | `str` | Resolved variant URL, including required signature context. |

No persistent `video_qualities`, `renditions`, direct MP4 source mapping, or
separate `media` loader exists. Inspect `get_qualities()` when media information
is needed. A referral without a master raises `VideoUnavailable`.

## Relationships

```python
channel = await video.get_author(load_html=True)
performers = await video.get_pornstars(load_html=True)
source = await video.get_source(load_html=True)
async for result in video.related_videos(iterator_config=None):
    related = result.unwrap()
```

These are methods, not async properties. `get_author()` returns `Channel | None`;
`get_pornstars()` returns a list of linked `Pornstar` objects. `get_source()`
returns `Source | None` when the originating listing supplies a source URL.
Unlinked performer names are not guessed into URLs. All objects share the core.
`related_videos()` is a one-page result stream of the scene's related grid.

## Download

```python
await video.download(configuration: DownloadConfigHLS, *, refresh: bool = True)
```

Delegates to `BaseCore.download` after checking public unencrypted HLS variants.
Returns the shared boolean or `DownloadReport` according to configuration.
Caller configuration is copied; a fresh signed scene source is fetched by
default. See [downloading](../guides/downloading.md).
