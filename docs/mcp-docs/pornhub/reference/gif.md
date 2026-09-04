---
title: "GIF — PornHub API"
summary: "Documents GIF behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub GIF"
keywords:
  - "PornHub"
  - "GIF"
  - "download"
  - "url"
  - "title"
  - "vote_count"
  - "vote_percentage"
  - "views"
  - "publish_date"
  - "thumbnail"
  - "content_url"
  - "source_video_url"
  - "tags"
---

# GIF — PornHub API

Documents GIF behavior, signatures, fields, constraints, and examples for the PornHub API.

dataclass Inherits from `BaseMedia`. Represents a single GIF with voting data, source video link, and a direct download URL.

## Attributes

## url

Type: str; Description: The GIF page URL

## title

Type: str | None; Description: GIF title

## vote_count

Type: str | None; Description: Total vote count

## vote_percentage

Type: str | None; Description: Positive vote percentage

## views

Type: str | None; Description: View count

## publish_date

Type: str | None; Description: Upload date

## thumbnail

Type: str | None; Description: Thumbnail image URL

## content_url

Type: str | None; Description: Direct MP4/WebM download URL

## source_video_url

Type: str | None; Description: URL of the source video this GIF was created from

## tags

Type: dict[str, str] | None; Description: Tag name → URL mapping

## Methods

## download

Downloads the GIF using the RAW downloader (direct file download). Auto-appends the title to the output path unless `no_title=True`.

```python
await gif.download(
    configuration: DownloadConfigRAW
) -> bool
```

### Parameters
- configuration DownloadConfigRAW — RAW download settings. See [Downloading](../guides/downloading.md).

### Returns

→ bool

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
