---
title: "Album — XFreeHD API"
summary: "Documents Album behavior, signatures, fields, constraints, and examples for the XFreeHD API."
public_url: "https://docs.echteralsfake.me/xfreehd/"
aliases:
  - "XFreeHD Album"
keywords:
  - "XFreeHD"
  - "Album"
  - "get_images_by_page"
  - "get_all_images"
  - "url"
  - "title"
  - "total_pages_count"
---

# Album — XFreeHD API

Documents Album behavior, signatures, fields, constraints, and examples for the XFreeHD API.

dataclass Inherits from `BaseMedia`. Represents a picture gallery album with support for paginated photo fetching.

## Attributes

## url

Type: str; Description: Album page URL

## title

Type: str | None; Description: Album title

## total_pages_count

Type: int | None; Description: Calculated total pages in the album

## Methods

## get_images_by_page

Fetches direct photo image URLs for a specific album index page.

```python
await album.get_images_by_page(
    page: int = 1
) -> list[str]
```

### Parameters
- page int — Page index (1-based, default: `1`)

### Returns

→ list[str]

## get_all_images

Iterates and collects direct image URLs for all pages in this album concurrently.

```python
await album.get_all_images() -> list[str]
```

### Returns

→ list[str]

## Related MCP documents

- [XFreeHD API getting started](../getting-started.md)
- [Errors and troubleshooting — XFreeHD API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xfreehd/](https://docs.echteralsfake.me/xfreehd/)
