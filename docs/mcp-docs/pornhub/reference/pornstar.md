---
title: "Pornstar — PornHub API"
summary: "Documents Pornstar behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Pornstar"
keywords:
  - "PornHub"
  - "Pornstar"
  - "get_videos"
  - "get_uploads"
  - "get_gifs"
  - "url"
  - "name"
  - "bio"
  - "about"
  - "info"
---

# Pornstar — PornHub API

Documents Pornstar behavior, signatures, fields, constraints, and examples for the PornHub API.

dataclass Inherits from `UserHelper` → `BaseMedia`. Represents a pornstar profile. Shared base with Model and User for profile info and video iteration.

## Attributes

## url

Type: str; Description: The pornstar profile URL

## name

Type: str | None; Description: Profile display name

## bio

Type: str | None; Description: Short bio / tagline text

## about

Type: str | None; Description: Extended about section text

## info

Type: dict | None; Description: Structured info fields (e.g., gender, age, location)

## Methods

## get_videos

Iterates over videos featured on the pornstar's profile.

```python
async for result in pornstar.get_videos(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of profile pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default does not eagerly load `html` or `api`.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_uploads

Iterates over videos directly uploaded by the pornstar (as opposed to featured videos).

```python
async for result in pornstar.get_uploads(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of upload pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default constructs results without eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_gifs

Iterates over GIFs associated with the pornstar's profile.

```python
async for result in pornstar.get_gifs(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[GIF], None]
```

### Parameters
- pages int — Number of GIF pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default constructs results without eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[GIF], None]

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
