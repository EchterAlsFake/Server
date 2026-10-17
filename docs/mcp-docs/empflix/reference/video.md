---
title: "Video — EMPFlix API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the EMPFlix API."
public_url: "https://docs.echteralsfake.me/empflix/"
aliases:
  - "EMPFlix Video"
keywords:
  - "EMPFlix"
  - "Video"
  - "download"
  - "url"
  - "video_id"
  - "title"
  - "description"
  - "thumbnail_url"
  - "mosaic_url_template"
  - "preview_video_url"
  - "publish_date"
  - "publish_date_relative"
  - "duration"
  - "length"
  - "author_name"
  - "author_link"
  - "author_verified"
  - "pornstars"
  - "pornstars_urls"
  - "categories"
---

# Video — EMPFlix API

Documents Video behavior, signatures, fields, constraints, and examples for the EMPFlix API.

dataclass Inherits from `BaseMedia`. Represents an EMPFlix video item with metadata extracted from HTML5 Plyr player configurations and JSON-LD structured data.

## Attributes

## url

Type: str; Description: The video page URL

## video_id

Type: str | None; Description: Unique video identifier key

## title

Type: str | None; Description: Video title

## description

Type: str | None; Description: Video description

## thumbnail_url

Type: str | None; Description: Primary video cover image thumbnail URL

## mosaic_url_template

Type: str | None; Description: Timeline storyboard mosaic image template URL

## preview_video_url

Type: str | None; Description: Short teaser preview video clip URL

## publish_date

Type: str | None; Description: Upload date (ISO string)

## publish_date_relative

Type: str | None; Description: Relative upload time string

## duration

Type: int | None; Description: Duration in integer seconds

## length

Type: str | None; Description: Formatted duration string (e.g. 12:34 )

## author_name

Type: str | None; Description: Username of the uploader

## author_link

Type: str | None; Description: Profile URL of the author

## author_verified

Type: bool | None; Description: Whether the author has a verified badge

## pornstars

Type: list[dict[str, str]] | None; Description: Featured pornstars with name and URL

## pornstars_urls

Type: list[str] | None; Description: Profile URLs of featured performers

## categories

Type: list[dict[str, str]] | None; Description: List of category labels and URLs

## tags

Type: list[str] | None; Description: List of video tags

## views

Type: str | None; Description: Formatted view count

## likes

Type: str | None; Description: Like count

## dislikes

Type: str | None; Description: Dislike count

## rating

Type: str | None; Description: Rating score value

## rating_percent

Type: str | None; Description: Rating percentage string

## rating_votes

Type: str | None; Description: Total rating votes count

## embed_url

Type: str | None; Description: Embeddable iframe player URL

## direct_download_urls

Type: dict[int, str] | None; Description: Mapping of resolution height (e.g. 720, 1080) to direct signed progressive MP4 CDN URLs

## video_qualities

Type: list[int] | None; Description: Available progressive video resolutions sorted ascending (e.g. [360, 480, 720, 1080] )

## Methods

## download

Downloads the video directly from CDN server using progressive multi-threaded range requests via `DownloadConfigRAW`.

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

- [EMPFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — EMPFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/empflix/](https://docs.echteralsfake.me/empflix/)
