---
title: "Video — Eporner API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner Video"
keywords:
  - "Eporner"
  - "Video"
  - "video_qualities"
  - "get_url_by_quality"
  - "download"
  - "get_authors"
  - "url"
  - "video_id"
  - "keywords"
  - "title"
  - "views"
  - "rate"
  - "publish_date"
  - "length_seconds"
  - "length_minutes"
  - "embed_url"
  - "thumbnail"
  - "rating_value"
  - "rating_count"
  - "parsed_urls"
---

# Video — Eporner API

Documents Video behavior, signatures, fields, constraints, and examples for the Eporner API.

dataclass Inherits from `BaseMedia`. Represents a single video with details extracted from API endpoints and HTML elements.

## Attributes

## url

Type: str; Description: The video page URL

## video_id

Type: str | None; Description: Unique video key ID

## keywords

Type: list | None; Description: List of tags

## title

Type: str | None; Description: Video title

## views

Type: int | None; Description: Number of views

## rate

Type: str | None; Description: Rating representation

## publish_date

Type: str | None; Description: Publication / upload date string

## length_seconds

Type: str | None; Description: Duration in seconds

## length_minutes

Type: str | None; Description: Duration in minutes (e.g. 12:34 )

## embed_url

Type: str | None; Description: Embed player path

## thumbnail

Type: str | None; Description: Default cover image thumbnail URL

## rating_value

Type: str | None; Description: Rating score value

## rating_count

Type: str | None; Description: Total rating votes

## parsed_urls

Type: dict | None; Description: Resolvable CDN paths mapped by resolution (e.g. {"720p": {"h264": "...", "av1": "..."}} )

## description

Type: str | None; Description: Video summary description

## encoding_format

Type: str | None; Description: Encoding format metadata

## is_family_friendly

Type: str | None; Description: Family friendly flag

## thumbnails

Type: list[str] | None; Description: List of alternative thumbs

## content_url

Type: str | None; Description: Meta content URL

## best_rating

Type: str | None; Description: Upper rating limits

## worst_rating

Type: str | None; Description: Lower rating limits

## authors_urls

Type: list[str] | None; Description: List of actor URLs starring in this video

## tags

Type: list[str] | None; Description: Tag labels parsed from the HTML page

## categories

Type: list[str] | None; Description: Category labels parsed from the HTML page

## uploader

Type: str | None; Description: Uploader name parsed from the HTML page

## Methods

## video_qualities

Returns a list of resolutions available for download.

```python
video.video_qualities() -> list[str]
```

### Returns

→ list[str]

## get_url_by_quality

Finds the specific CDN file URL matching the quality height and encoding format.

```python
video.get_url_by_quality(
    quality: str | int,
    mode: Encoding | str
) -> str
```

### Parameters
- quality str | int — Target resolution (e.g. `1080` or `"1080p"`)
- mode Encoding | str — Video codec format (e.g. `Encoding.mp4_h264` or `"h264"`)

### Returns

→ str

## download

Downloads the video directly from CDN server using `DownloadConfigRAW`.

```python
await video.download(
    configuration: DownloadConfigRAW,
    mode: Encoding | str,
    use_workaround: bool = True
) -> bool
```

### Parameters
- configuration DownloadConfigRAW — RAW download options (quality, path, etc.). See [Downloading Options](../guides/downloading.md).
- mode Encoding | str — Video codec format (e.g. `Encoding.mp4_h264` or `Encoding.av1`)
- use_workaround bool — Enable download pipeline workarounds (default: `True`)

### Returns

→ bool

## get_authors

Yields pornstar profiles starring in this video.

```python
async for star in video.get_authors(
    load_html: bool = True
) -> AsyncGenerator[Pornstar, None]
```

### Parameters
- load_html bool — If `True`, pre-fetches full metadata properties for the yielded pornstar

### Returns

→ AsyncGenerator[Pornstar, None]

## Related MCP documents

- [Eporner API getting started](../getting-started.md)
- [Errors and troubleshooting — Eporner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
