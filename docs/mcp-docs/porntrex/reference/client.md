---
title: "Client — Porntrex API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex Client"
keywords:
  - "Porntrex"
  - "Client"
  - "get_video"
  - "get_model"
  - "get_channel"
  - "search"
---

# Client — Porntrex API

Documents Client behavior, signatures, fields, constraints, and examples for the Porntrex API.

The main class to interact with the Porntrex scraper ecosystem.

```python
from porntrex_api import Client
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
- url str — The Porntrex video page URL
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Video

## get_model

Fetches a model profile profile page and returns a populated `Model` object.

```python
await client.get_model(
    url: str,
    load_html: bool = True
) -> Model
```

### Parameters
- url str — The Porntrex model profile page URL
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Model

## get_channel

Fetches a publisher channel page and returns a populated `Channel` object.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Parameters
- url str — The Porntrex channel page URL
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Channel

## search

Queries Porntrex search and streams video results via an asynchronous generator.

```python
async for result in client.search(
    query: str,
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query string
- pages int — Number of search pages to parse (default: `2`)
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
