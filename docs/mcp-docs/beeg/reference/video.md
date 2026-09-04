---
title: "Video — Beeg API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the Beeg API."
public_url: "https://docs.echteralsfake.me/beeg/"
aliases:
  - "Beeg Video"
keywords:
  - "Beeg"
  - "Video"
  - "download"
  - "url"
  - "title"
  - "video_id"
  - "duration"
  - "m3u8_base_url"
  - "key"
---

# Video — Beeg API

Documents Video behavior, signatures, fields, constraints, and examples for the Beeg API.

dataclass Inherits from `BaseMedia`. Represents a single video with details extracted from Beeg's store facts API.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title

## video_id

Type: str | None; Description: Unique video file ID

## duration

Type: int | None; Description: Video duration in seconds

## m3u8_base_url

Type: str | None; Description: Master HLS stream playlist URL

## key

Type: str | None; Description: Video key extracted from the URL path

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

- [Beeg API getting started](../getting-started.md)
- [Errors and troubleshooting — Beeg API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/beeg/](https://docs.echteralsfake.me/beeg/)
