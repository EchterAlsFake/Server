---
title: "Video — MissAV API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the MissAV API."
public_url: "https://docs.echteralsfake.me/missav/"
aliases:
  - "MissAV Video"
keywords:
  - "MissAV"
  - "Video"
  - "download"
  - "url"
  - "title"
  - "publish_date"
  - "keywords"
  - "length"
  - "m3u8_base_url"
  - "thumbnail"
---

# Video — MissAV API

Documents Video behavior, signatures, fields, constraints, and examples for the MissAV API.

dataclass Inherits from `BaseMedia`. Represents a single JAV video with metadata extracted from OpenGraph meta tags and obfuscated JavaScript.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title (from og:title )

## publish_date

Type: str | None; Description: Release date (from og:video:release_date )

## keywords

Type: str | None; Description: Comma-separated keyword tags

## length

Type: str | None; Description: Video duration (from og:video:duration )

## m3u8_base_url

Type: str | None; Description: Reconstructed HLS playlist URL from obfuscated JS

## thumbnail

Type: str | None; Description: Cover image thumbnail URL (from og:image )

## Methods

## download

Downloads the video via HLS streaming using the reconstructed M3U8 playlist URL. Appends the video title to the output path unless `no_title=True`.

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

- [MissAV API getting started](../getting-started.md)
- [Errors and troubleshooting — MissAV API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/missav/](https://docs.echteralsfake.me/missav/)
