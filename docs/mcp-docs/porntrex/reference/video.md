---
title: "Video — Porntrex API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex Video"
keywords:
  - "Porntrex"
  - "Video"
  - "download"
  - "url"
  - "title"
  - "video_id"
  - "categories"
  - "tags"
  - "license_code"
  - "lrc"
  - "rnd"
  - "author"
  - "publish_date"
  - "views"
  - "duration"
  - "description"
  - "subscribers_count"
  - "thumbnail"
  - "direct_download_urls"
  - "video_qualities"
---

# Video — Porntrex API

Documents Video behavior, signatures, fields, constraints, and examples for the Porntrex API.

dataclass Inherits from `BaseMedia`. Represents a single video with details extracted from Porntrex's script variables.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title

## video_id

Type: str | None; Description: Unique video key ID

## categories

Type: list[str] | None; Description: List of category labels

## tags

Type: list[str] | None; Description: List of tags

## license_code

Type: str | None; Description: License code metadata

## lrc

Type: str | None; Description: LRC string identifier

## rnd

Type: str | None; Description: Rnd hash value used in player config

## author

Type: str | None; Description: Username of the uploader

## publish_date

Type: str | None; Description: Uploader date description

## views

Type: str | None; Description: Number of views

## duration

Type: str | None; Description: Duration string (e.g. 12:34 )

## description

Type: str | None; Description: Description of the video

## subscribers_count

Type: str | None; Description: Author's subscriber count

## thumbnail

Type: str | None; Description: Cover image thumbnail URL

## direct_download_urls

Type: list[str] | None; Description: Raw CDN download URLs ordered by resolution

## video_qualities

Type: list[str] | None; Description: Sorted list of available resolutions (e.g. ["360", "480", "720", "1080"] )

## Methods

## download

Downloads the video directly from CDN server using `DownloadConfigRAW`.

```python
await video.download(
    configuration: DownloadConfigRAW
) -> bool
```

### Parameters
- configuration DownloadConfigRAW — RAW download options. See [Downloading Options](../guides/downloading.md).

### Returns

→ bool

## Related MCP documents

- [Porntrex API getting started](../getting-started.md)
- [Errors and troubleshooting — Porntrex API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
