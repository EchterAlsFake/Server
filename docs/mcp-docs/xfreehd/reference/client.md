---
title: "Client — XFreeHD API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the XFreeHD API."
public_url: "https://docs.echteralsfake.me/xfreehd/"
aliases:
  - "XFreeHD Client"
keywords:
  - "XFreeHD"
  - "Client"
  - "get_video"
  - "get_album"
  - "search"
---

# Client — XFreeHD API

Documents Client behavior, signatures, fields, constraints, and examples for the XFreeHD API.

The main class to interact with the XFreeHD scraper ecosystem.

```python
from xfreehd_api import Client
from base_api import BaseCore

client = Client()
client_custom = Client(core=BaseCore())
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore()`)

## Methods

## get_video

Fetches metadata for a video URL and returns a populated `Video` object.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The XFreeHD video page URL
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Video

## get_album

Fetches photo album information and returns a populated `Album` object.

```python
await client.get_album(
    url: str,
    load_html: bool = True
) -> Album
```

### Parameters
- url str — The XFreeHD photo album page URL
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Album

## search

Queries XFreeHD search and streams video results via an asynchronous generator.

```python
async for result in client.search(
    query: str,
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search keywords
- pages int — Number of search pages to parse (default: `5`)
- iterator_config IteratorConfig | None — Per-iterator concurrency, source loading, ordering, retry, error-mode, and custom-handler settings. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [XFreeHD API getting started](../getting-started.md)
- [Errors and troubleshooting — XFreeHD API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xfreehd/](https://docs.echteralsfake.me/xfreehd/)
