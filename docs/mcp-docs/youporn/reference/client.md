---
title: "Client — YouPorn API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the YouPorn API."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn Client"
keywords:
  - "YouPorn"
  - "Client"
  - "get_video"
  - "get_pornstar"
  - "get_channel"
  - "get_collection"
  - "search_videos"
---

# Client — YouPorn API

Documents Client behavior, signatures, fields, constraints, and examples for the YouPorn API.

Main class serving as the core interface wrapper.

```python
from youporn_api import Client
from base_api import BaseCore

client = Client()
client_custom = Client(core=BaseCore())
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore()`)

## Methods

## get_video

Fetches a video profile page and returns a populated `Video` object. Parses the media definition variants.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The YouPorn video page URL
- load_html bool — Pre-load and extract properties immediately (default: `True`)

### Returns

→ Video

## get_pornstar

Fetches a model profile biography and returns a populated `Pornstar` object.

```python
await client.get_pornstar(
    url: str,
    load_html: bool = True
) -> Pornstar
```

### Parameters
- url str — The pornstar profile page URL
- load_html bool — Pre-load and extract properties immediately (default: `True`)

### Returns

→ Pornstar

## get_channel

Loads publisher channel metadata and returns a populated `Channel` object.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Parameters
- url str — The publisher channel URL
- load_html bool — Pre-load and extract properties immediately (default: `True`)

### Returns

→ Channel

## get_collection

Loads collection metadata and returns a populated `Collection` object.

```python
await client.get_collection(
    url: str,
    load_html: bool = True
) -> Collection
```

### Parameters
- url str — The collection playlist URL
- load_html bool — Pre-load and extract properties immediately (default: `True`)

### Returns

→ Collection

## search_videos

Queries search endpoints and streams video results via async generator.

```python
async for result in client.search_videos(
    query: str,
    pages: int = 0,
    filter_relevance: Literal["views", "rating", "date", "duration"] | None = None,
    filter_duration_minimum: Literal["10", "20", "30", "40", "50", "60"] | None = None,
    filter_duration_maximum: Literal["10", "20", "30", "40", "50", "60"] | None = None,
    filter_resolution: Literal["VR", "HD"] | None = None,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query words
- pages int — Pages to fetch
- filter_relevance str — Sort criteria (e.g. `"views"`, `"rating"`)
- filter_duration_minimum str — Min minutes duration
- filter_duration_maximum str — Max minutes duration
- filter_resolution str — Video resolution category (e.g. `"HD"`, `"VR"`)
- iterator_config IteratorConfig | None — Concurrency, ordering, source loading, retry, and terminal-error policy. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [YouPorn API getting started](../getting-started.md)
- [Errors and troubleshooting — YouPorn API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
