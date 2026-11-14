---
title: "Video — Pornhat API"
summary: "Video fields, player_sources, media_sources, m3u8_base_url, get_available_qualities, relationships and HLS downloads."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Video — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "video"
---

# Video — Pornhat API

`Video(url=..., core=...)` is a keyword-only `BaseMedia` dataclass. Prefer
`await client.get_video(url)`. Deferred construction makes no requests until a source or
field is explicitly loaded. Loaders atomically commit field mappings through `BaseMedia`.

## Fields

| Field | Type | Source | Meaning |
| --- | --- | --- | --- |
| `url` | `str` | identity | Absolute resource URL; normalized to HTTPS while preserving the verified host. Query and fragment are removed. |
| `core` | `BaseCore` | identity | Shared networking and download backend. |
| `resolved_url` | `str \| None` | identity | Final page response URL recorded by the shared helper, when available. |
| `video_id` | `str \| None` | html | Stable numeric ID as a string; listing objects can already contain it. |
| `title` | `str \| None` | html | Matching VideoObject name; the page h1 can be empty. |
| `description` | `str \| None` | html | Matching VideoObject description. |
| `thumbnail_url` | `str \| None` | html | JSON-LD thumbnail URL. |
| `poster_url` | `str \| None` | html | Public player poster URL. |
| `preview_video_url` | `str \| None` | html | Public preview clip URL from target video setup. |
| `publish_date` | `str \| None` | html | Site ISO upload timestamp, preserving the supplied UTC offset. |
| `length` | `str \| None` | html | Displayed duration, typically MM:SS or HH:MM:SS. |
| `duration` | `int \| None` | html | Exact duration in integer seconds from the target player. |
| `views` | `int \| None` | html | Exact JSON-LD userInteractionCount, normalized to an integer. |
| `author_name` | `str \| None` | html | Producing channel name. |
| `author_link` | `str \| None` | html | Grouped channel URL under /sites/. |
| `site_url` | `str \| None` | html | Separate paysite/brand URL under /paysite/. |
| `pornstars` | `list[str] \| None` | html | Performer names in page order. |
| `pornstars_urls` | `list[str] \| None` | html | Corresponding model profile URLs in page order. |
| `tags` | `list[str] \| None` | html | Tag names in page order. |
| `tags_urls` | `list[str] \| None` | html | Corresponding tag collection URLs. |
| `embed_url` | `str \| None` | html | Public numeric embed URL matching the target player. |
| `language` | `str \| None` | html | Response html language, such as en or de. |
| `is_hd` | `bool \| None` | html | True if the labeled player sources reach at least 720p; not a substitute for master inspection. |
| `player_sources` | `list[dict] \| None` | html | Labeled endpoints containing quality (integer height), url, and type. MP4-looking endpoints may redirect to HLS. |
| `media_sources` | `list[dict] \| None` | media | Resolved sources: format, url, and quality. HLS master entries use quality=None; inspect the actual master for its renditions. |
| `m3u8_base_url` | `str \| None` | media | Resolved real HLS master URL, including its required query string. |
| `content_url` | `str \| None` | media | First resolved direct MP4 if supplied; None for all verified HLS-only samples. |

The `id` property returns the loaded `video_id`, or an ID from a loaded embed URL, otherwise
`None`; it does not fetch. Unknown fields remain unloaded and raise `DataNotLoadedError` on
synchronous access. Known missing values are `None` or empty relationship lists. No
likes/dislikes, ratings, comment counts or invented defaults are exposed.

`to_dict()` includes only loaded fields by default and never triggers requests. It omits the
core unless requested; use it for metadata inspection/export. See [source loading](../guides/source-loading.md).

## get_available_qualities

```python
async def get_available_qualities() -> list[int]: ...
```

Load resolved media, inspect the real HLS master and return sorted unique integer heights. The verified samples expose `[360, 480, 720]`.

## get_channel

```python
async def get_channel(*, load_html: bool=True) -> Channel | None: ...
```

Load `author_link` if necessary and return the related `Channel`, or `None` when absent.

## get_models

```python
async def get_models(*, load_html: bool=True) -> list[Model]: ...
```

Load `pornstars_urls` if necessary and return related `Model` objects in page order. There is no separate `Pornstar` class.

## get_site

```python
async def get_site(*, load_html: bool=True) -> Site | None: ...
```

Load `site_url` if necessary and return the separate paysite/brand `Site`, or `None`.

## download

```python
async def download(configuration: DownloadConfigHLS, *, refresh: bool=False): ...
```

Load title and media, copy the download configuration, and delegate to `core.download`. Returns `bool` or shared `DownloadReport` according to `return_report`. `refresh=True` invalidates cached page data and loads fresh sources on a separate object, leaving the original metadata state intact.

Relationship getters are awaited methods and support `load_html=False` for deferred
related objects. They share the parent core; keep that core open. Example:

```python
async def inspect_relationships(video):
    channel = await video.get_channel(load_html=False)
    models = await video.get_models()
    site = await video.get_site(load_html=False)
    return channel, models, site
```

See [downloads](../guides/downloading.md) for quality selection, remuxing, reports, callbacks,
refresh, and the observed transport limitation.
