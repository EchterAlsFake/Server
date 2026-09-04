---
title: "Client — Tube8 API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 Client"
keywords:
  - "Tube8"
  - "Client"
  - "get_video"
  - "get_pornstar"
  - "get_channel"
  - "get_amateur"
  - "search"
---

# Client — Tube8 API

Documents Client behavior, signatures, fields, constraints, and examples for the Tube8 API.

Main entry point class to execute searches and load resource models.

```python
from tube8_api import Client
client = Client()
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore()`)

## Methods

## get_video

Fetches a video page and returns a populated `Video` object. Parses LD+JSON structured data and media definitions.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The Tube8 video URL
- load_html bool — Pre-load parsed properties immediately

### Returns

→ Video

## get_pornstar

Loads a pornstar profile page and returns a populated `Pornstar` object with sidebar biography stats.

```python
await client.get_pornstar(
    url: str,
    load_html: bool = True
) -> Pornstar
```

### Parameters
- url str — The pornstar profile URL
- load_html bool — Pre-load parsed properties

### Returns

→ Pornstar

## get_channel

Loads a production studio channel page.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Parameters
- url str — The channel page URL
- load_html bool — Pre-load parsed properties

### Returns

→ Channel

## get_amateur

Loads an amateur model profile page.

```python
await client.get_amateur(
    url: str,
    load_html: bool = True
) -> Amateur
```

### Parameters
- url str — The amateur profile page URL
- load_html bool — Pre-load parsed properties

### Returns

→ Amateur

## search

Queries Tube8 search index pages and yields video scrape results.

```python
async for result in client.search(
    query: str,
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query words
- pages int — Number of search pages to parse
- iterator_config IteratorConfig | None — Concurrency, ordering, source loading, retry, and terminal-error policy. The package default loads `html` and permits three attempts for both stages.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Tube8 API getting started](../getting-started.md)
- [Errors and troubleshooting — Tube8 API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
