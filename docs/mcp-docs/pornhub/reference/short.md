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
  - "get_video"
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

## duration

Type: int | None; Description: Video duration in seconds

## categories

Type: list[str] | None; Description: Category labels

## tags

Type: list[str] | None; Description: Tag labels

## is_verified

Type: bool | None; Description: Whether the creator is verified

## like_count

Type: int | None; Description: Numeric parsed like count

## dislike_count

Type: int | None; Description: Numeric parsed dislike count

## like_info

Type: str | None; Description: Formatted like string

## favorite_info

Type: str | None; Description: Formatted favorite string

## token

Type: str | None; Description: Short action token

## author_id

Type: str | None; Description: Uploader numeric account ID

## author_type

Type: str | None; Description: Author membership type (e.g. "Mpp")

## external_link

Type: str | None; Description: Creator external link URL

## external_link_text

Type: str | None; Description: Call-to-action text for the external link

## large_preview_url

Type: str | None; Description: High-resolution preview image URL

## shortie_url

Type: str | None; Description: Canonical short URL identifier

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

## get_video

Returns the full `Video` object corresponding to this short.

```python
await short.get_video(
    load_html: bool = False,
    load_api: bool = True
) -> Video
```

### Parameters
- load_html bool — If `True`, fetches full HTML page for video details
- load_api bool — If `True` (default), fetches metadata via the Webmaster API

### Returns

→ Video

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
