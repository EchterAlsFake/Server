---
title: "Profile objects — YouPorn API"
summary: "Documents Profile objects behavior, signatures, fields, constraints, and examples for the YouPorn API."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn Profile objects"
keywords:
  - "YouPorn"
  - "Profile objects"
  - "videos"
  - "Channel"
  - "Collection"
  - "Pornstar"
---

# Profile objects — YouPorn API

Documents Profile objects behavior, signatures, fields, constraints, and examples for the YouPorn API.

## Channel

`Channel` uses the shared behavior documented in this reference.

## Collection

`Collection` uses the shared behavior documented in this reference.

## Pornstar

`Pornstar` uses the shared behavior documented in this reference.

Scrapers representing publisher channels, custom collections, and pornstar profile pages provide listing iterators.

## Methods

## videos

Yields videos uploaded by or featuring this object.

```python
async for result in obj.videos(
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

- [YouPorn API getting started](../getting-started.md)
- [Errors and troubleshooting — YouPorn API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
