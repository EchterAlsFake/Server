---
title: "Channel — Redtube API"
summary: "Documents Channel behavior, signatures, fields, constraints, and examples for the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube Channel"
keywords:
  - "Redtube"
  - "Channel"
  - "get_videos"
  - "url"
  - "name"
  - "rank"
  - "views"
  - "videos_count"
  - "subscribers_count"
---

# Channel — Redtube API

Documents Channel behavior, signatures, fields, constraints, and examples for the Redtube API.

dataclass Inherits from `BaseMedia`. Represents a publisher studio channel page.

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

## subscribers_count

Type: str | None; Description: Total channel subscribers count

## Methods

## get_videos

Yields video scrape results uploaded by this studio channel.

```python
async for result in channel.get_videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to load
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default eagerly loads each video's `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Redtube API getting started](../getting-started.md)
- [Errors and troubleshooting — Redtube API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
