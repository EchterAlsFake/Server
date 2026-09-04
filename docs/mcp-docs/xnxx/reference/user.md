---
title: "User — XNXX API"
summary: "Documents User behavior, signatures, fields, constraints, and examples for the XNXX API."
public_url: "https://docs.echteralsfake.me/xnxx/"
aliases:
  - "XNXX User"
keywords:
  - "XNXX"
  - "User"
  - "videos"
  - "url"
  - "total_videos_count"
  - "total_pages_count"
  - "total_videos_views"
---

# User — XNXX API

Documents User behavior, signatures, fields, constraints, and examples for the XNXX API.

dataclass Inherits from `BaseMedia`. Represents an XNXX user profile containing upload statistics and video iterations.

## Attributes

## url

Type: str; Description: The user profile URL

## total_videos_count

Type: int | None; Description: Total uploaded videos

## total_pages_count

Type: int | None; Description: Total number of paginated video list pages

## total_videos_views

Type: str | None; Description: Total views across all uploads

## Methods

## videos

Asynchronously iterates over videos uploaded by the user, navigating page-by-page.

```python
async for result in user.videos(
    pages: int = 0,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Max pages to fetch (will automatically cap to `total_pages_count`)
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default eagerly loads each video's `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [XNXX API getting started](../getting-started.md)
- [Errors and troubleshooting — XNXX API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xnxx/](https://docs.echteralsfake.me/xnxx/)
