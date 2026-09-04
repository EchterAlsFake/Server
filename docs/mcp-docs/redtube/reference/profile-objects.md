---
title: "Profile objects — Redtube API"
summary: "Documents Profile objects behavior, signatures, fields, constraints, and examples for the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube Profile objects"
keywords:
  - "Redtube"
  - "Profile objects"
  - "get_videos"
  - "get_playlists"
  - "User"
  - "Pornstar"
  - "Amateur"
  - "url"
  - "name"
  - "pornstar_information"
---

# Profile objects — Redtube API

Documents Profile objects behavior, signatures, fields, constraints, and examples for the Redtube API.

## User

`User` uses the shared behavior documented in this reference.

## Pornstar

`Pornstar` uses the shared behavior documented in this reference.

## Amateur

`Amateur` uses the shared behavior documented in this reference.

Scraper objects representing creators, actors, and registered users share metadata hierarchies (`UserHelper`).

## Attributes

## url

Type: str; Description: Profile page URL

## name

Type: str | None; Description: Username / profile display name

## pornstar_information

Type: dict | None; Description: Sidebar stat parameters (only populated for Pornstar objects)

## Methods

## get_videos

Yields videos uploaded by or featuring this profile.

```python
async for result in profile.get_videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to load
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default eagerly loads each video's `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_playlists

Yields playlists created by the user. **Available for User objects only.**

```python
async for result in user.get_playlists(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Playlist], None]
```

### Parameters
- pages int — Pages to load
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default eagerly loads each playlist's `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Playlist], None]

## Related MCP documents

- [Redtube API getting started](../getting-started.md)
- [Errors and troubleshooting — Redtube API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
