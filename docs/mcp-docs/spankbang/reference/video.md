---
title: "Video — SpankBang API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the SpankBang API."
public_url: "https://docs.echteralsfake.me/spankbang/"
aliases:
  - "SpankBang Video"
keywords:
  - "SpankBang"
  - "Video"
  - "download"
  - "url"
  - "title"
  - "description"
  - "thumbnail"
  - "tags"
  - "author"
  - "image"
  - "rating"
  - "length"
  - "m3u8_base_url"
  - "direct_download_urls"
  - "video_qualities"
  - "tag"
  - "views"
  - "resolution"
  - "video_source_url"
---

# Video — SpankBang API

Documents Video behavior, signatures, fields, constraints, and examples for the SpankBang API.

dataclass Inherits from `BaseMedia`. Represents a single SpankBang video. Populated with metadata from parsed Javascript configurations (`stream_data`) on the page and standard HTML tags.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title

## description

Type: str | None; Description: Description metadata content

## thumbnail

Type: str | None; Description: Video preview cover image URL

## tags

Type: list | None; Description: List of tags/categories

## author

Type: str | None; Description: Author / channel publisher name

## image

Type: str | None; Description: Author profile thumbnail / image alt text

## rating

Type: str | None; Description: Upvote percentage (e.g. 92% )

## length

Type: str | None; Description: Length in seconds

## m3u8_base_url

Type: str | None; Description: HLS master playlist URL

## direct_download_urls

Type: list | None; Description: CDN-resolved direct MP4 URLs

## video_qualities

Type: list | None; Description: Sorted list of available resolution heights (e.g. ["240", "320", "480", "720", "1080"] )

## tag

Type: str | None; Description: Primary search tag associated with the item

## views

Type: str | None; Description: View count string from the listing card

## resolution

Type: str | None; Description: Maximum resolution badge from listing card

## video_source_url

Type: str | None; Description: Raw listing element fallbacks

## Methods

## download

Downloads the video. Supports downloading via HLS segments (default) or fetching direct CDN MP4 files depending on the `use_hls` parameter.

```python
await video.download(
    configuration_hls: DownloadConfigHLS | None = None,
    configuration_raw: DownloadConfigRAW | None = None,
    use_hls: bool = True
) -> bool | DownloadReport
```

### Parameters
- configuration_hls DownloadConfigHLS | None — Config options for HLS segment downloads. Used if `use_hls=True`.
- configuration_raw DownloadConfigRAW | None — Config options for direct file downloads. Used if `use_hls=False`.
- use_hls bool — Download via HLS (default: `True`). Set `False` to download via raw MP4 links.

### Returns

→ bool | DownloadReport

## Related MCP documents

- [SpankBang API getting started](../getting-started.md)
- [Errors and troubleshooting — SpankBang API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/spankbang/](https://docs.echteralsfake.me/spankbang/)
