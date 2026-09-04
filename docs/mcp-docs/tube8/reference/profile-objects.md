---
title: "Profile objects — Tube8 API"
summary: "Documents Profile objects behavior, signatures, fields, constraints, and examples for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 Profile objects"
keywords:
  - "Tube8"
  - "Profile objects"
  - "get_videos"
  - "User"
  - "Pornstar"
  - "Amateur"
  - "url"
  - "name"
  - "pornstar_information"
---

# Profile objects — Tube8 API

Documents Profile objects behavior, signatures, fields, constraints, and examples for the Tube8 API.

## User

`User` uses the shared behavior documented in this reference.

## Pornstar

`Pornstar` uses the shared behavior documented in this reference.

## Amateur

`Amateur` uses the shared behavior documented in this reference.

Scraper objects representing creators, actors, and registered users share a common base class (`UserHelper`).

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
- iterator_config IteratorConfig | None — Complete iterator policy. The package default loads `html` and permits three attempts for pages and items.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Tube8 API getting started](../getting-started.md)
- [Errors and troubleshooting — Tube8 API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
