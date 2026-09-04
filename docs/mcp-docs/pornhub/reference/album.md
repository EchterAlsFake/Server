---
title: "Album — PornHub API"
summary: "Documents Album behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Album"
keywords:
  - "PornHub"
  - "Album"
  - "get_photos"
  - "download_photo"
  - "author"
  - "url"
  - "rating_percentage"
  - "views"
  - "publish_date"
  - "tags"
  - "votes"
  - "author_link"
---

# Album — PornHub API

Documents Album behavior, signatures, fields, constraints, and examples for the PornHub API.

dataclass Inherits from `BaseMedia`. Represents a photo album with rating, views, tags, and individual photo download support.

## Attributes

## url

Type: str; Description: The album page URL

## rating_percentage

Type: str | None; Description: Album rating percentage

## views

Type: str | None; Description: View count

## publish_date

Type: str | None; Description: Publish date string

## tags

Type: dict[str, str] | None; Description: Tag name → URL mapping

## votes

Type: str | None; Description: Vote count string

## author_link

Type: str | None; Description: Album author's profile URL

## Methods

## get_photos

Iterates over all photos in the album. Each result is a dictionary containing `url`, `download_url`, `rating`, and `views`. Uses `ProcessPoolExecutor` for parallel HTML parsing across pages.

```python
async for photo in album.get_photos(
    pages: int
) -> dict
```

### Parameters
- pages int — **Required.** Number of album pages to fetch

### Returns

→ AsyncGenerator[dict, None]

Each dict contains: `url`, `download_url`, `rating`, `views`

## download_photo

Downloads a single photo using the RAW downloader. Use the `download_url` from `get_photos()` results.

```python
await album.download_photo(
    url: str,
    path: str
) -> bool
```

### Parameters
- url str — Direct download URL of the photo
- path str — Output file path

### Returns

→ bool

## author

Returns the `Pornstar` object who authored this album.

```python
await album.author -> Pornstar
```

### Returns

→ Pornstar

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
