---
title: "Client — MissAV API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the MissAV API."
public_url: "https://docs.echteralsfake.me/missav/"
aliases:
  - "MissAV Client"
keywords:
  - "MissAV"
  - "Client"
  - "get_video"
  - "search"
---

# Client — MissAV API

Documents Client behavior, signatures, fields, constraints, and examples for the MissAV API.

Main entry point class. Provides methods to fetch individual videos and perform search queries via Recombee recommendations API.

```python
from missav_api import Client
client = Client()
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore()`)

## Methods

## get_video

Fetches a video page and returns a populated `Video` object. Extracts the M3U8 playlist URL from obfuscated JavaScript embedded in the page HTML.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The MissAV video page URL (e.g. `https://missav.ws/en/abc-123`)
- load_html bool — Pre-load parsed properties immediately

### Returns

→ Video

## search

Queries MissAV's Recombee recommendation engine to discover videos matching the search query. Generates an anonymous user ID and signs the API request with HMAC-SHA1.

```python
async for result in client.search(
    query: str,
    video_count: int = 50,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query (e.g. JAV code, actress name, keyword)
- video_count int — Maximum number of results to return (default: `50`)
- iterator_config IteratorConfig | None — Per-iterator concurrency, source loading, ordering, retry, error-mode, and custom-handler settings. MissAV defaults to one page task and the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [MissAV API getting started](../getting-started.md)
- [Errors and troubleshooting — MissAV API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/missav/](https://docs.echteralsfake.me/missav/)
