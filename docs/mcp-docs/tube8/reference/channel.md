---
title: "Channel — Tube8 API"
summary: "Documents Channel behavior, signatures, fields, constraints, and examples for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 Channel"
keywords:
  - "Tube8"
  - "Channel"
  - "get_videos"
  - "url"
  - "name"
  - "rank"
  - "views"
  - "videos_count"
---

# Channel — Tube8 API

Documents Channel behavior, signatures, fields, constraints, and examples for the Tube8 API.

dataclass Inherits from `UserHelper`. Represents a publisher studio channel page.

## Attributes

## url

Type: str; Description: Channel page URL

## name

Type: str | None; Description: Studio/channel display name

## rank

Type: str | None; Description: Channel ranking score

## views

Type: str | None; Description: Total channel views count

## videos_count

Type: str | None; Description: Total uploaded videos count

## Methods

## get_videos

Yields video scrape results uploaded by this studio channel. Inherits from `UserHelper.get_videos()`.

```python
async for result in channel.get_videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Tube8 API getting started](../getting-started.md)
- [Errors and troubleshooting — Tube8 API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
