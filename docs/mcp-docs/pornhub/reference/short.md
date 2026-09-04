---
title: "Short — PornHub API"
summary: "Documents Short behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Short"
keywords:
  - "PornHub"
  - "Short"
  - "download"
  - "get_author"
  - "url"
  - "title"
  - "video_id"
  - "video_key"
  - "likes"
  - "dislikes"
  - "favorites"
  - "comment_count"
  - "is_hd"
  - "thumbnail"
  - "embed_url"
  - "author_name"
  - "author_link"
  - "avatar"
  - "video_url"
  - "m3u8_base_url"
---

# Short — PornHub API

Documents Short behavior, signatures, fields, constraints, and examples for the PornHub API.

dataclass Inherits from `BaseMedia`. Represents a Pornhub short-form video with metadata extracted from inline JSON.

## Attributes

## url

Type: str; Description: The short page URL

## title

Type: str | None; Description: Short title

## video_id

Type: str | None; Description: Internal video ID

## video_key

Type: str | None; Description: Video key identifier

## likes

Type: str | None; Description: Like count

## dislikes

Type: str | None; Description: Dislike count

## favorites

Type: str | None; Description: Favorite count

## comment_count

Type: str | None; Description: Comment count

## is_hd

Type: bool | None; Description: Whether the short is HD

## thumbnail

Type: str | None; Description: Thumbnail image URL

## embed_url

Type: str | None; Description: Embed URL

## author_name

Type: str | None; Description: Author display name

## author_link

Type: str | None; Description: Author profile URL

## avatar

Type: str | None; Description: Author avatar image URL

## video_url

Type: str | None; Description: Link to the full video version

## m3u8_base_url

Type: str | None; Description: Synthesized master m3u8 playlist

## media_definitions

Type: dict | None; Description: Raw media quality definitions

## Methods

## download

Downloads the short via HLS streaming. Auto-appends the title to the output path unless `no_title=True`.

```python
await short.download(
    configuration: DownloadConfigHLS
) -> bool | DownloadReport
```

### Parameters
- configuration DownloadConfigHLS — HLS download settings. See [Downloading](../guides/downloading.md).

### Returns

→ bool | DownloadReport

## get_author

Returns the `Pornstar` object who created this short.

```python
await short.get_author(
    load_html: bool = True
) -> Pornstar
```

### Returns

→ Pornstar

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
