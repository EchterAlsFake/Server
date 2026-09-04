---
title: "Video — XVideos API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Video"
keywords:
  - "XVideos"
  - "Video"
  - "download"
  - "get_author"
  - "get_pornstars"
  - "url"
  - "title"
  - "description"
  - "thumbnail_url"
  - "preview_video_url"
  - "publish_date"
  - "content_url"
  - "tags"
  - "views"
  - "likes"
  - "dislikes"
  - "rating_votes"
  - "comment_count"
  - "author_link"
  - "length"
---

# Video — XVideos API

Documents Video behavior, signatures, fields, constraints, and examples for the XVideos API.

dataclass Inherits from `BaseMedia`. Represents a single video with all its metadata.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title

## description

Type: str | None; Description: Video description

## thumbnail_url

Type: str | None; Description: Thumbnail image URL

## preview_video_url

Type: str | None; Description: Short preview clip URL

## publish_date

Type: str | None; Description: Upload date

## content_url

Type: str | None; Description: Direct content URL

## tags

Type: list | None; Description: List of tag strings

## views

Type: str | None; Description: View count

## likes

Type: str | None; Description: Like count

## dislikes

Type: str | None; Description: Dislike count

## rating_votes

Type: str | None; Description: Total rating votes

## comment_count

Type: str | None; Description: Comment count

## author_link

Type: str | None; Description: Uploader profile URL

## length

Type: str | None; Description: Video duration

## pornstars_urls

Type: list | None; Description: URLs of pornstars featured

## embed_url

Type: str | None; Description: Embeddable iframe URL

## cdn_url

Type: str | None; Description: Optional CDN URL carried by listing data

## m3u8_base_url

Type: str | None; Description: HLS master playlist URL

## video_id

Type: str | None; Description: Internal video ID

## Methods

## download

Downloads the video using the HLS threaded downloader. The video title is automatically appended to the output path unless `no_title=True`.

```python
await video.download(
    configuration: DownloadConfigHLS
) -> bool | DownloadReport
```

### Parameters
- configuration DownloadConfigHLS — Download settings (quality, path, etc.). See [Downloading](../guides/downloading.md).

### Returns

→ bool | DownloadReport

## get_author

Lazily loads and returns the uploader's `Channel` object.

```python
await video.get_author -> Channel | None
```

### Returns

→ Channel | None

## get_pornstars

Yields `Pornstar` objects for each featured performer.

```python
async for star in video.get_pornstars -> Pornstar
```

### Returns

→ AsyncGenerator[Pornstar, None]

**Tip — Lazy Loading**
All objects inherit from `BaseMedia`. Accessing an unresolved attribute raises `DataNotLoadedError`. Use `await media.load_sources("html")` to load a complete source or `await media.load_fields(...)` for selected fields. By default, `client.get_video(..., load_html=True)` calls `load_sources("html")` and populates the HTML-backed attributes.

## Related MCP documents

- [XVideos API getting started](../getting-started.md)
- [Errors and troubleshooting — XVideos API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
