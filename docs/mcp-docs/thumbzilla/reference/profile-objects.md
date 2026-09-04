---
title: "Profile objects — Thumbzilla API"
summary: "Documents Profile objects behavior, signatures, fields, constraints, and examples for the Thumbzilla API."
public_url: "https://docs.echteralsfake.me/thumbzilla/"
aliases:
  - "Thumbzilla Profile objects"
keywords:
  - "Thumbzilla"
  - "Profile objects"
  - "get_videos"
  - "User"
  - "Pornstar"
  - "Amateur"
  - "url"
  - "name"
  - "pornstar_information"
---

# Profile objects — Thumbzilla API

Documents Profile objects behavior, signatures, fields, constraints, and examples for the Thumbzilla API.

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
    iterator_configuration: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to load
- iterator_configuration IteratorConfig | None — Complete iterator policy. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Thumbzilla API getting started](../getting-started.md)
- [Errors and troubleshooting — Thumbzilla API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/thumbzilla/](https://docs.echteralsfake.me/thumbzilla/)
