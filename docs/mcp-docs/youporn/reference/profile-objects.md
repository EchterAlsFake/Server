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
  - "url"
  - "name"
  - "avatar"
  - "banner"
  - "description"
---

# Profile objects — YouPorn API

Documents Profile objects behavior, signatures, fields, constraints, and examples for the YouPorn API.

`BaseProfile` inherits from `BaseMedia` and provides the common header properties (`name`, `avatar`, `banner`, and `description`) shared by both `Channel` and `Pornstar` profiles. Scrapers representing publisher channels, custom collections, and pornstar profile pages provide listing iterators via `videos()`.

## BaseProfile Attributes

## url

Type: str; Description: Profile page URL

## name

Type: str | None; Description: Profile display name

## avatar

Type: str | None; Description: Avatar image URL

## banner

Type: str | None; Description: Profile header banner image URL

## description

Type: str | None; Description: Profile bio description

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
