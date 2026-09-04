---
title: "Video — YouPorn API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the YouPorn API."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn Video"
keywords:
  - "YouPorn"
  - "Video"
  - "pornstars"
  - "download"
  - "author"
  - "url"
  - "title"
  - "publish_date"
  - "length"
  - "rating"
  - "views"
  - "thumbnail"
  - "categories"
  - "m3u8_base_url"
  - "author_link"
  - "pornstars_urls"
  - "uploader_id"
  - "uploader_status"
  - "uploader_type"
  - "uploader_name"
---

# Video — YouPorn API

Documents Video behavior, signatures, fields, constraints, and examples for the YouPorn API.

dataclass Inherits from `BaseMedia`. Represents a single video with details extracted from JavaScript parameters embedded in the page.

## Attributes

## url

Type: str; Description: The video page URL

## title

Type: str | None; Description: Video title

## publish_date

Type: str | None; Description: Upload / publish date string

## length

Type: str | None; Description: Duration string (e.g. 12:34 )

## rating

Type: str | None; Description: Like percentage value

## views

Type: str | None; Description: Total views count

## thumbnail

Type: str | None; Description: Cover image thumbnail URL

## categories

Type: list[str] | None; Description: List of category labels

## m3u8_base_url

Type: str | None; Description: Constructed HLS master playlist URL or direct MP4 URL depending on availability

## author_link

Type: str | None; Description: Uploader profile URL

## pornstars_urls

Type: list[str] | None; Description: Starring pornstar relative profile paths

## uploader_id

Type: str | None; Description: Uploader identifier

## uploader_status

Type: str | None; Description: Uploader status

## uploader_type

Type: str | None; Description: Uploader type

## uploader_name

Type: str | None; Description: Uploader profile name

## video_id

Type: str | None; Description: Unique video key ID

## is_hls

Type: bool | None; Description: Boolean indicating stream delivery type (True: HLS, False: Raw MP4)

## Methods

## pornstars

An async-generator property yielding fully loaded pornstar profiles starring in this video. Unlike concurrent listing methods, it yields `Pornstar` objects directly rather than `ScrapeResult`.

```python
async for star in video.pornstars:
    ...
# AsyncGenerator[Pornstar, None]
```

### Returns

→ AsyncGenerator[Pornstar, None]

## download

Downloads the video. If the video uses HLS streaming, processes it via `configuration`. If it falls back to raw MP4, processes it via `backup_configuration`.

```python
await video.download(
    configuration: DownloadConfigHLS,
    backup_configuration: DownloadConfigRAW | None = None
) -> bool | DownloadReport
```

### Parameters
- configuration DownloadConfigHLS — Main HLS download config
- backup_configuration DownloadConfigRAW | None — Backup direct file download config (required if `is_hls=False`)

### Returns

→ bool | DownloadReport

## author

Fetches the uploader profile, automatically returning either a `Pornstar` or `Channel` object.

```python
await video.author(
    load_html: bool = True
) -> Pornstar | Channel
```

### Parameters
- load_html bool — Pre-load uploader properties (default: `True`)

### Returns

→ Pornstar | Channel

## Related MCP documents

- [YouPorn API getting started](../getting-started.md)
- [Errors and troubleshooting — YouPorn API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
