---
title: "Video — HQPorner API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the HQPorner API."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner Video"
keywords:
  - "HQPorner"
  - "Video"
  - "video_qualities"
  - "download"
  - "url"
  - "title"
  - "cdn_url"
  - "pornstars"
  - "length"
  - "publish_date"
  - "tags"
  - "direct_download_urls"
  - "thumbnail"
---

# Video — HQPorner API

Documents Video behavior, signatures, fields, constraints, and examples for the HQPorner API.

dataclass Inherits from `BaseMedia`. Represents a single video with extracted streaming qualities and download links.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title

## cdn_url

Type: str | None; Description: The Altplayer CDN iframe/block URL path

## pornstars

Type: list[str] | None; Description: List of actress names featured in the video

## length

Type: str | None; Description: Video length/duration (e.g., 15:45 )

## publish_date

Type: str | None; Description: Upload date string

## tags

Type: list[str] | None; Description: List of category/tag strings

## direct_download_urls

Type: list[str] | None; Description: Resolved direct MP4 links from Altplayer

## thumbnail

Type: str | None; Description: Video preview/thumbnail URL

## Methods & Properties

## video_qualities

Returns a sorted list of available qualities (resolutions like `["360", "480", "720", "1080"]`).

```python
video.video_qualities -> list[str]
```

### Returns

→ list[str]

## download

Downloads the video direct MP4 files using range/multipart support. Appends the video title to path unless `no_title=True`.

```python
await video.download(
    configuration: DownloadConfigRAW
) -> bool
```
- configuration DownloadConfigRAW — RAW download settings. See [Downloading](../guides/downloading.md).

### Returns

→ bool

## Related MCP documents

- [HQPorner API getting started](../getting-started.md)
- [Errors and troubleshooting — HQPorner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
