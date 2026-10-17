---
title: "Channel — TNAFlix API"
summary: "Documents Channel behavior, signatures, fields, constraints, and examples for the TNAFlix API."
public_url: "https://docs.echteralsfake.me/tnaflix/"
aliases:
  - "TNAFlix Channel"
keywords:
  - "TNAFlix"
  - "Channel"
  - "videos"
  - "url"
  - "slug"
  - "title"
  - "description"
  - "avatar_url"
  - "cover_url"
  - "verified"
  - "subscribers_count"
  - "total_videos_count"
  - "video_views"
---

# Channel — TNAFlix API

Documents Channel behavior, signatures, fields, constraints, and examples for the TNAFlix API.

dataclass Inherits from `BaseMedia`. Represents an official publisher studio or content creator channel on TNAFlix (e.g. `/channel/team-skeet`).

## Attributes

## url

Type: str; Description: Channel page URL

## slug

Type: str | None; Description: Channel URL slug identifier

## title

Type: str | None; Description: Studio or channel name

## description

Type: str | None; Description: Official channel description text

## avatar_url

Type: str | None; Description: Channel logo avatar picture URL

## cover_url

Type: str | None; Description: Channel header banner cover image URL

## verified

Type: bool; Description: Whether the channel is an officially verified partner

## subscribers_count

Type: str | None; Description: Total channel subscribers count

## total_videos_count

Type: str | None; Description: Total videos uploaded to this channel

## video_views

Type: str | None; Description: Cumulative video views across all channel videos

## Methods

## videos

Asynchronously yields video scrape results uploaded by this studio channel across listing pages.

```python
async for result in channel.videos(
    pages: int | str = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int | str — Number of pages to iterate (default: `2`) or `"all"`
- iterator_config IteratorConfig | None — Per-iterator concurrency, source loading, ordering, retry, error-mode, and custom-handler settings.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [TNAFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — TNAFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tnaflix/](https://docs.echteralsfake.me/tnaflix/)
