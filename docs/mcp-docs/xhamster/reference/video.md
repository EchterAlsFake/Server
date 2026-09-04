---
title: "Video — xHamster API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster Video"
keywords:
  - "xHamster"
  - "Video"
  - "download"
  - "url"
  - "video_id"
  - "video_hash"
  - "title"
  - "description"
  - "duration"
  - "views"
  - "comments_count"
  - "created_timestamp"
  - "date_ago"
  - "rating_percentage"
  - "likes"
  - "dislikes"
  - "is_vr"
  - "is_hd"
  - "max_resolution"
  - "orientation"
---

# Video — xHamster API

Documents Video behavior, signatures, fields, constraints, and examples for the xHamster API.

dataclass Inherits from `BaseMedia`. Represents a standard video with metadata extracted from page source JSON elements.

## Attributes

## url

Type: str; Description: The video page URL

## video_id

Type: str | None; Description: Unique video key ID

## video_hash

Type: str | None; Description: Hashed slug associated with the video ID

## title

Type: str | None; Description: Video title

## description

Type: str | None; Description: Video description

## duration

Type: int | None; Description: Video duration in seconds

## views

Type: int | None; Description: Total view count

## comments_count

Type: int | None; Description: Total comment count

## created_timestamp

Type: str | None; Description: Creation timestamp supplied by the page data

## date_ago

Type: str | None; Description: Human-readable age of the upload

## rating_percentage

Type: int | None; Description: Like percentage value

## likes

Type: int | None; Description: Number of likes

## dislikes

Type: int | None; Description: Number of dislikes

## is_vr

Type: bool | None; Description: Whether the video is a VR video

## is_hd

Type: bool | None; Description: Whether the video is available in HD

## max_resolution

Type: str | None; Description: Highest resolution reported by the page data

## orientation

Type: str | None; Description: Content orientation label, such as "straight" or "gay"

## uploader_name

Type: str | None; Description: Uploader profile name

## uploader_subscribers

Type: str | None; Description: Uploader subscriber count

## tags

Type: list[str] | None; Description: List of tags

## categories

Type: list[str] | None; Description: List of category labels

## pornstars

Type: list[str] | None; Description: Pornstars starring in the video

## thumbnail

Type: str | None; Description: Thumbnail cover image URL

## preview_thumbnail

Type: str | None; Description: Preview sprite or animated thumbnail URL

## m3u8_base_url

Type: str | None; Description: HLS playlist URL

## preview_video

Type: str | None; Description: Preview media path

## Methods

## download

Downloads the video via HLS streaming. Appends the video title to the output path unless `no_title=True` on the config.

```python
await video.download(
    configuration: DownloadConfigHLS
) -> bool | DownloadReport
```

### Parameters
- configuration DownloadConfigHLS — HLS download configurations

### Returns

→ bool | DownloadReport

## Related MCP documents

- [xHamster API getting started](../getting-started.md)
- [Errors and troubleshooting — xHamster API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
