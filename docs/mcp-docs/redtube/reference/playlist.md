---
title: "Playlist — Redtube API"
summary: "Documents Playlist behavior, signatures, fields, constraints, and examples for the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube Playlist"
keywords:
  - "Redtube"
  - "Playlist"
  - "get_author"
  - "get_videos"
  - "url"
  - "title"
  - "author_url"
  - "author_name"
  - "rating_percent"
  - "rating_count"
  - "views"
  - "video_count"
  - "updated_at"
  - "status"
---

# Playlist — Redtube API

Documents Playlist behavior, signatures, fields, constraints, and examples for the Redtube API.

dataclass Inherits from `BaseMedia`. Represents a user-curated playlist.

## Attributes

## url

Type: str; Description: The playlist URL

## title

Type: str | None; Description: Playlist title

## author_url

Type: str | None; Description: Author's relative profile path

## author_name

Type: str | None; Description: Name of the author

## rating_percent

Type: str | None; Description: User rating percentage

## rating_count

Type: str | None; Description: Total rating count

## views

Type: str | None; Description: Number of playlist views

## video_count

Type: str | None; Description: Total videos count

## updated_at

Type: str | None; Description: Last updated timestamp string

## status

Type: str | None; Description: Status description

## Methods

## get_author

Returns a populated `User` object representing the owner of this playlist.

```python
await playlist.get_author(
    load_html: bool = False
) -> User
```

### Parameters
- load_html bool — If `True`, pre-fetches full user metadata immediately

### Returns

→ User

## get_videos

Yields video scrape results nested inside this playlist.

```python
async for result in playlist.get_videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to load
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default eagerly loads each video's `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Redtube API getting started](../getting-started.md)
- [Errors and troubleshooting — Redtube API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
