---
title: "Video — XFreeHD API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the XFreeHD API."
public_url: "https://docs.echteralsfake.me/xfreehd/"
aliases:
  - "XFreeHD Video"
keywords:
  - "XFreeHD"
  - "Video"
  - "video_qualities"
  - "download"
  - "url"
  - "title"
  - "likes"
  - "dislikes"
  - "publish_date"
  - "views"
  - "author"
  - "thumbnail"
  - "length"
  - "categories"
  - "tags"
  - "cdn_urls"
  - "rating"
---

# Video — XFreeHD API

Documents Video behavior, signatures, fields, constraints, and examples for the XFreeHD API.

dataclass Inherits from `BaseMedia`. Represents a single video with details extracted from player page HTML elements.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title

## likes

Type: str | None; Description: Number of likes

## dislikes

Type: str | None; Description: Number of dislikes

## publish_date

Type: str | None; Description: Publication / upload date string

## views

Type: str | None; Description: Number of views

## author

Type: str | None; Description: Username of the video uploader

## thumbnail

Type: str | None; Description: Cover image thumbnail URL

## length

Type: str | None; Description: Duration string (e.g. 12:34 )

## categories

Type: list[str] | None; Description: List of category labels

## tags

Type: list[str] | None; Description: List of video tags

## cdn_urls

Type: list[str] | None; Description: Direct MP4 CDN paths (up to two qualities: SD, HD)

## rating

Type: str | None; Description: Optional ratings metadata

## Methods

## video_qualities

Returns the quality tiers inferred from the number of CDN URLs: one URL maps to 480p and two map to 480p/720p. Other counts currently return an empty list.

```python
video.video_qualities() -> list[int]
```

### Returns

→ list[int]

## download

Downloads the video directly from CDN server using `DownloadConfigRAW`. Supports `hd` and `sd` quality configuration.

```python
await video.download(
    configuration: DownloadConfigRAW
) -> bool
```

### Parameters
- configuration DownloadConfigRAW — RAW download options. Set `quality="hd"` or `quality="sd"`. See [Downloading Options](../guides/downloading.md).

### Returns

→ bool

## Related MCP documents

- [XFreeHD API getting started](../getting-started.md)
- [Errors and troubleshooting — XFreeHD API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xfreehd/](https://docs.echteralsfake.me/xfreehd/)
