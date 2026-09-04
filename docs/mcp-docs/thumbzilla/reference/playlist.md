---
title: "Playlist — Thumbzilla API"
summary: "Documents Playlist behavior, signatures, fields, constraints, and examples for the Thumbzilla API."
public_url: "https://docs.echteralsfake.me/thumbzilla/"
aliases:
  - "Thumbzilla Playlist"
keywords:
  - "Thumbzilla"
  - "Playlist"
  - "get_videos"
  - "url"
  - "title"
  - "author_name"
  - "rating_percent"
  - "rating_count"
  - "views"
  - "videos_count"
---

# Playlist — Thumbzilla API

Documents Playlist behavior, signatures, fields, constraints, and examples for the Thumbzilla API.

dataclass Inherits from `BaseMedia`. Represents a user-curated playlist.

## Attributes

## url

Type: str; Description: The playlist URL

## title

Type: str | None; Description: Playlist title

## author_name

Type: str | None; Description: Name of the author

## rating_percent

Type: str | None; Description: User rating percentage

## rating_count

Type: str | None; Description: Total rating count

## views

Type: str | None; Description: Number of playlist views

## videos_count

Type: str | None; Description: Total videos count

## Methods

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
- iterator_config IteratorConfig | None — Complete iterator policy. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Thumbzilla API getting started](../getting-started.md)
- [Errors and troubleshooting — Thumbzilla API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/thumbzilla/](https://docs.echteralsfake.me/thumbzilla/)
