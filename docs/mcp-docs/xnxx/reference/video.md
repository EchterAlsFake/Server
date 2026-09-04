---
title: "Video — XNXX API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the XNXX API."
public_url: "https://docs.echteralsfake.me/xnxx/"
aliases:
  - "XNXX Video"
keywords:
  - "XNXX"
  - "Video"
  - "download"
  - "url"
  - "title"
  - "description"
  - "thumbnail"
  - "publish_date"
  - "length"
  - "m3u8_base_url"
  - "views"
  - "author"
  - "tags"
  - "video_id"
  - "video_eid"
  - "preview_video_url"
  - "rating"
  - "max_quality"
---

# Video — XNXX API

Documents Video behavior, signatures, fields, constraints, and examples for the XNXX API.

dataclass Inherits from `BaseMedia`. Represents a single video with parsed metadata and HLS download streams.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title

## description

Type: str | None; Description: Video description metadata

## thumbnail

Type: str | None; Description: Thumbnail cover image URL

## publish_date

Type: str | None; Description: Upload / publish date string

## length

Type: str | None; Description: Duration string (e.g. PT15M42S )

## m3u8_base_url

Type: str | None; Description: Master HLS stream playlist URL

## views

Type: str | None; Description: Total view count

## author

Type: str | None; Description: Uploader name shown on the video page

## tags

Type: list[str] | None; Description: Keyword tags linked from the video page

## video_id

Type: str | None; Description: Numeric video identifier

## video_eid

Type: str | None; Description: External unique string ID

## preview_video_url

Type: str | None; Description: Direct URL to the short trailer / preview video clip

## rating

Type: str | None; Description: Upvote percentage or ranking score

## max_quality

Type: str | None; Description: Maximum resolution tag badge

## Methods

## download

Downloads the video via HLS streaming. Appends the video title to the output path unless `no_title=True` on the config.

```python
await video.download(
    configuration: DownloadConfigHLS
) -> bool | DownloadReport
```

### Parameters
- configuration DownloadConfigHLS — HLS download options. See [Downloading Options](../guides/downloading.md).

### Returns

→ bool | DownloadReport

## Related MCP documents

- [XNXX API getting started](../getting-started.md)
- [Errors and troubleshooting — XNXX API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xnxx/](https://docs.echteralsfake.me/xnxx/)
