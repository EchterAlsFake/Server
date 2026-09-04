---
title: "Video — Thumbzilla API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the Thumbzilla API."
public_url: "https://docs.echteralsfake.me/thumbzilla/"
aliases:
  - "Thumbzilla Video"
keywords:
  - "Thumbzilla"
  - "Video"
  - "download"
  - "url"
  - "video_id"
  - "title"
  - "duration"
  - "thumbnail"
  - "embed_url"
  - "views"
  - "publish_date"
  - "publish_date_thumbnail"
  - "description"
  - "author_name"
  - "m3u8_url"
  - "m3u8_base_url"
  - "media_definitions"
  - "preview_video_url"
  - "performers"
  - "uploader_url"
---

# Video — Thumbzilla API

Documents Video behavior, signatures, fields, constraints, and examples for the Thumbzilla API.

dataclass Inherits from `BaseMedia`. Represents a single video with metadata extracted from LD+JSON structured data and JavaScript media definitions.

## Attributes

## url

Type: str; Description: The video page URL

## video_id

Type: str | None; Description: Unique video key ID

## title

Type: str | None; Description: Video title

## duration

Type: str | int | None; Description: Video duration in seconds

## thumbnail

Type: str | None; Description: Thumbnail cover image URL

## embed_url

Type: str | None; Description: Embeddable player URL

## views

Type: str | None; Description: View count

## publish_date

Type: str | None; Description: Upload date

## publish_date_thumbnail

Type: str | None; Description: Thumbnail publication date

## description

Type: str | None; Description: Video description

## author_name

Type: str | None; Description: Name of the uploader

## m3u8_url

Type: str | None; Description: External HLS variants JSON source URL

## m3u8_base_url

Type: str | None; Description: Auto-constructed HLS master playlist string

## media_definitions

Type: list[dict] | None; Description: Raw media definition configurations

## preview_video_url

Type: str | None; Description: Preview clip path

## performers

Type: list[str] | None; Description: Featured performer names

## uploader_url

Type: str | None; Description: Uploader profile URL

## Methods

## download

Downloads the video via HLS streaming. Appends the video title to the output path unless `no_title=True`.

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

- [Thumbzilla API getting started](../getting-started.md)
- [Errors and troubleshooting — Thumbzilla API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/thumbzilla/](https://docs.echteralsfake.me/thumbzilla/)
