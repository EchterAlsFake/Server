---
title: "Short — xHamster API"
summary: "Documents Short behavior, signatures, fields, constraints, and examples for the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster Short"
keywords:
  - "xHamster"
  - "Short"
  - "download"
  - "url"
  - "title"
  - "tags"
  - "thumbnail"
  - "video_id"
  - "comment_count"
  - "duration"
  - "created_at"
  - "poster_url"
  - "author_link"
  - "author_logo"
  - "m3u8_base_url"
  - "likes"
  - "views"
  - "author_subscribers"
  - "author"
  - "preview_video"
---

# Short — xHamster API

Documents Short behavior, signatures, fields, constraints, and examples for the xHamster API.

dataclass Inherits from `BaseMedia`. Represents a mobile-style short-form video.

## Attributes

## url

Type: str; Description: The short URL

## title

Type: str | None; Description: Video title

## tags

Type: list[str] | None; Description: Associated tags

## thumbnail

Type: str | None; Description: Cover thumbnail URL

## video_id

Type: str | None; Description: Unique short video ID

## comment_count

Type: str | None; Description: Number of comments

## duration

Type: str | None; Description: Duration string

## created_at

Type: str | None; Description: Upload timestamp string

## poster_url

Type: str | None; Description: Poster photo URL

## author_link

Type: str | None; Description: Link to author profile

## author_logo

Type: str | None; Description: Author's avatar path

## m3u8_base_url

Type: str | None; Description: HLS playlist URL

## likes

Type: str | None; Description: Number of likes

## views

Type: str | None; Description: Number of views

## author_subscribers

Type: str | None; Description: Author's subscriber count

## author

Type: str | None; Description: Name of the author

## preview_video

Type: str | None; Description: Short preview clip path

## Methods

## download

Downloads the short via HLS stream.

```python
await short.download(
    configuration: DownloadConfigHLS
) -> bool | DownloadReport
```

### Parameters
- configuration DownloadConfigHLS — HLS download configurations

### Returns

→ bool | DownloadReport

## Related MCP documents

- [xHamster API getting started](../getting-started.md)
- [Errors and troubleshooting — xHamster API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
