---
title: "Playlist — PornHub API"
summary: "Documents Playlist behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Playlist"
keywords:
  - "PornHub"
  - "Playlist"
  - "get_videos"
  - "get_author"
  - "url"
  - "title"
  - "description"
  - "views"
  - "rating_percent"
  - "likes"
  - "dislikes"
  - "video_count"
  - "unavailable_videos"
  - "tags"
  - "author_link"
  - "token"
  - "playlist_id"
---

# Playlist — PornHub API

Documents Playlist behavior, signatures, fields, constraints, and examples for the PornHub API.

dataclass Inherits from `BaseMedia`. Represents a video playlist with title, description, tags, and video count. Uses the chunked API endpoint internally for video iteration.

## Attributes

## url

Type: str; Description: The playlist page URL

## title

Type: str | None; Description: Playlist title

## description

Type: str | None; Description: Playlist description text

## views

Type: str | None; Description: View count

## rating_percent

Type: str | None; Description: Rating percentage

## likes

Type: str | None; Description: Like count

## dislikes

Type: str | None; Description: Dislike count

## video_count

Type: str | None; Description: Total number of videos in the playlist

## unavailable_videos

Type: int | None; Description: Number of hidden / unavailable videos

## tags

Type: dict[str, str] | None; Description: Tag name → URL mapping

## author_link

Type: str | None; Description: Playlist author's profile URL

## token

Type: str | None; Description: Internal token for chunked API requests

## playlist_id

Type: str | None; Description: Extracted playlist numeric ID

## Methods

## get_videos

Iterates over videos in the playlist. Uses the internal chunked API for paginated fetching.

```python
async for result in playlist.get_videos(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of chunked playlist pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default constructs results without eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_author

Returns the `User` who created the playlist.

```python
await playlist.get_author(
    load_html: bool = True
) -> User
```

### Returns

→ User

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
