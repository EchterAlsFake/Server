---
title: "Channel — Eporner API"
summary: "Documents Channel behavior, signatures, fields, constraints, and examples for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner Channel"
keywords:
  - "Eporner"
  - "Channel"
  - "videos"
  - "url"
  - "name"
  - "subscribers"
  - "video_amount"
  - "video_views"
  - "picture"
  - "channel_id"
  - "channel_rank"
  - "logo"
  - "banner"
---

# Channel — Eporner API

Documents Channel behavior, signatures, fields, constraints, and examples for the Eporner API.

dataclass Inherits from `BaseProfile` -> `BaseMedia`. Represents an Eporner channel profile with rank, stats, logo, banner, and video stream pagination.

## Attributes

## url

Type: str; Description: Channel page URL

## name

Type: str | None; Description: Channel name (from `BaseProfile`)

## subscribers

Type: str | None; Description: Subscriber count (from `BaseProfile`)

## video_amount

Type: str | None; Description: Total uploaded videos count (from `BaseProfile`)

## video_views

Type: str | None; Description: Accumulated video views count (from `BaseProfile`)

## picture

Type: str | None; Description: Profile/logo picture URL (from `BaseProfile`)

## channel_id

Type: str | None; Description: Unique numeric channel ID

## channel_rank

Type: str | None; Description: Channel platform rank

## logo

Type: str | None; Description: Channel logo image URL

## banner

Type: str | None; Description: Channel header banner image URL

## Methods

## videos

Yields video scrape results for this channel. Inherited from `BaseProfile`.

```python
async for result in channel.videos(
    pages: int = 0,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to load (if `0`, automatically calculates pages based on total `video_amount`)
- iterator_config IteratorConfig | None — Concurrency, source loading, ordering, retry, and error policy

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Client — Eporner API](client.md)
- [Pornstar — Eporner API](pornstar.md)
- [Video — Eporner API](video.md)
- [Eporner API getting started](../getting-started.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
