---
title: "Video — PornHub API"
summary: "Documents Video behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Video"
keywords:
  - "PornHub"
  - "Video"
  - "download"
  - "author"
  - "url"
  - "video_id"
  - "title"
  - "duration"
  - "thumbnail"
  - "views"
  - "likes"
  - "publish_date"
  - "categories"
  - "tags"
  - "rating_percent"
  - "is_hd"
  - "is_vr"
  - "is_vertical"
  - "is_video_unavailable"
  - "is_video_unavailable_in_your_country"
---

# Video — PornHub API

Documents Video behavior, signatures, fields, constraints, and examples for the PornHub API.

dataclass Inherits from `BaseMedia`. Represents a single video with metadata from both HTML scraping and the Webmaster API. Supports dual loading modes: API-only (fast) and HTML (full data including m3u8 URLs for downloading).

## Attributes

## url

Type: str; Source: —; Description: The video page URL

## video_id

Type: str | None; Source: —; Description: Extracted viewkey from URL

## title

Type: str | None; Source: API / HTML; Description: Video title

## duration

Type: int | None; Source: API / HTML; Description: Video duration in seconds

## thumbnail

Type: str | None; Source: API / HTML; Description: Preview thumbnail URL

## views

Type: str | None; Source: API / HTML; Description: View count

## likes

Type: str | None; Source: API / HTML; Description: Like / rating count

## publish_date

Type: str | None; Source: API / HTML; Description: Upload / publish date

## categories

Type: list[str] | None; Source: API / HTML; Description: Category names

## tags

Type: list[str] | None; Source: API / HTML; Description: Tag names

## rating_percent

Type: str | float | None; Source: API; Description: Webmaster API rating percentage

## is_hd

Type: bool | None; Source: HTML; Description: Whether the video is HD

## is_vr

Type: bool | None; Source: HTML; Description: Whether the video is VR

## is_vertical

Type: bool | None; Source: HTML; Description: Whether the video is vertical (portrait)

## is_video_unavailable

Type: bool | None; Source: HTML; Description: Whether the video is unavailable

## is_video_unavailable_in_your_country

Type: bool | None; Source: HTML; Description: Whether the video is geo-blocked

## available_qualities

Type: list[int] | None; Source: HTML; Description: Sorted list of available resolution heights

## m3u8_base_url

Type: str | None; Source: HTML; Description: Synthesized master m3u8 playlist for HLS download

## author_thumbnail

Type: str | None; Source: HTML; Description: Author's avatar image URL

## author_link

Type: str | None; Source: HTML; Description: Author's profile URL

## author_information

Type: dict | None; Source: HTML; Description: Author details: name, link, video count, subscriber count

**Important**
To download a video, you **must** load the HTML source (either via `client.get_video(url, load_html=True)` or by calling `await video.load_sources("html")` afterward). The m3u8 streaming URLs are only available from that source.

## Methods & Properties

## download

Downloads the video via HLS streaming. Auto-appends the video title to the output path unless `no_title=True` is set on the config.

```python
await video.download(
    configuration: DownloadConfigHLS
) -> bool | DownloadReport
```

### Parameters
- configuration DownloadConfigHLS — HLS download settings. See [Downloading](../guides/downloading.md).

### Returns

→ bool | DownloadReport

## author

Returns the video's author as a `Pornstar`, `Model`, or `Channel` based on the author-link pattern. The source-aware property loads the author link on demand.

```python
await video.author -> Pornstar | Model | Channel | None
```

### Returns

→ Pornstar | Model | Channel | None

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
