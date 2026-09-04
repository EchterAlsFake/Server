---
title: "Profile objects — SpankBang API"
summary: "Documents Profile objects behavior, signatures, fields, constraints, and examples for the SpankBang API."
public_url: "https://docs.echteralsfake.me/spankbang/"
aliases:
  - "SpankBang Profile objects"
keywords:
  - "SpankBang"
  - "Profile objects"
  - "videos"
  - "Pornstar"
  - "Channel"
  - "Creator"
  - "url"
  - "name"
  - "video_count"
  - "views_count"
  - "subscribers_count"
  - "image"
---

# Profile objects — SpankBang API

Documents Profile objects behavior, signatures, fields, constraints, and examples for the SpankBang API.

## Pornstar

`Pornstar` uses the shared behavior documented in this reference.

## Channel

`Channel` uses the shared behavior documented in this reference.

## Creator

`Creator` uses the shared behavior documented in this reference.

dataclass Inherits from `PornstarHelper` → `BaseMedia`. Under the hood, SpankBang profiles for `Pornstar`, `Channel`, and `Creator` share the same attributes and methods via a common base class.

## Attributes

## url

Type: str; Description: The profile base URL

## name

Type: str | None; Description: Name of the pornstar, channel, or creator

## video_count

Type: str | None; Description: Total uploaded/featured videos

## views_count

Type: str | None; Description: Total profile views

## subscribers_count

Type: str | None; Description: Total subscriber count

## image

Type: str | None; Description: Profile avatar cover image URL

## Methods

## videos

Asynchronously yields video items listed on this profile, navigating page-by-page.

```python
async for result in profile.videos(
    pages: int = 0,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of extra pages to fetch (0 means only the main page URL)
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default eagerly loads each video's `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [SpankBang API getting started](../getting-started.md)
- [Errors and troubleshooting — SpankBang API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/spankbang/](https://docs.echteralsfake.me/spankbang/)
