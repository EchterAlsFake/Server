---
title: "Channel — Porntrex API"
summary: "Documents Channel behavior, signatures, fields, constraints, and examples for the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex Channel"
keywords:
  - "Porntrex"
  - "Channel"
  - "videos"
  - "url"
  - "name"
  - "information"
  - "thumbnail"
---

# Channel — Porntrex API

Documents Channel behavior, signatures, fields, constraints, and examples for the Porntrex API.

dataclass Inherits from `BaseMedia` via `ChannelModelHelper`. Represents a publisher channel.

## Attributes

## url

Type: str; Description: Channel page URL

## name

Type: str | None; Description: Name of the channel

## information

Type: dict | None; Description: Sidebar metadata key-value properties

## thumbnail

Type: str | None; Description: Channel cover profile picture URL

## Methods

## videos

Iterates over the videos uploaded to this channel.

```python
async for result in channel.videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to parse (default: `2`)
- iterator_config IteratorConfig | None — Per-iterator concurrency, source loading, ordering, retry, error-mode, and custom-handler settings. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Porntrex API getting started](../getting-started.md)
- [Errors and troubleshooting — Porntrex API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
