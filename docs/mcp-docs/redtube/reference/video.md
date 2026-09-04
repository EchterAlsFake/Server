---
title: "Video — Redtube API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube Video"
keywords:
  - "Redtube"
  - "Video"
  - "download"
  - "author"
  - "url"
  - "video_id"
  - "title"
  - "duration"
  - "thumbnail"
  - "embed_code"
  - "locale"
  - "media_definitions"
  - "is_auto_play_enabled"
  - "is_vr"
  - "author_url"
  - "m3u8_source_url"
  - "mp4_url"
  - "action_tags_raw"
  - "action_tags"
  - "m3u8_base_url"
---

# Video — Redtube API

Documents Video behavior, signatures, fields, constraints, and examples for the Redtube API.

dataclass Inherits from `BaseMedia`. Represents a single video with details extracted from JavaScript parameters embedded in the page.

## Attributes

## url

Type: str; Description: The video page URL

## video_id

Type: str | None; Description: Unique video key ID

## title

Type: str | None; Description: Video title

## duration

Type: int | str | None; Description: Video duration supplied by the page player data

## thumbnail

Type: str | None; Description: Thumbnail cover image URL

## embed_code

Type: str | None; Description: Embed code for web players

## locale

Type: str | None; Description: Locale code identifier

## media_definitions

Type: list[dict] | None; Description: Raw media definitions from the player configuration

## is_auto_play_enabled

Type: bool | None; Description: Autoplay status

## is_vr

Type: bool | None; Description: VR video flag

## author_url

Type: str | None; Description: The author's profile page URL

## m3u8_source_url

Type: str | None; Description: The raw HLS playlists URL source path

## mp4_url

Type: str | None; Description: Raw MP4 direct download link (if available)

## action_tags_raw

Type: object; Description: Raw action-tag payload (currently a string or mapping at runtime)

## action_tags

Type: dict | None; Description: Decoded action tags mapped by keyword and timestamp

## m3u8_base_url

Type: str | None; Description: Constructed HLS master playlist string

## author_name

Type: str | None; Description: Name of the video author

## publish_date

Type: str | None; Description: Date-added text shown on the video page

## uploader_id

Type: str | None; Description: Uploader identifier

## uploader_type

Type: str | None; Description: Uploader type

## preview_video_url

Type: str | None; Description: Preview clip path

## pornstars_names

Type: list[str] | None; Description: Names of starring pornstars

## pornstars_urls

Type: list[str] | None; Description: starring pornstar profile links

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

## author

Fetches the uploader profile, automatically returning either an `Amateur`, `Pornstar`, or `Channel` object.

```python
await video.author(
    load_html: bool = False
) -> Amateur | Pornstar | Channel
```

### Parameters
- load_html bool — If `True`, pre-fetches full author metadata immediately

### Returns

→ Amateur | Pornstar | Channel

## Related MCP documents

- [Redtube API getting started](../getting-started.md)
- [Errors and troubleshooting — Redtube API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
