---
title: "Client — Eporner API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner Client"
keywords:
  - "Eporner"
  - "Client"
  - "get_video"
  - "search_videos"
  - "get_videos_by_category"
  - "get_pornstar"
  - "get_channel"
---

# Client — Eporner API

Documents Client behavior, signatures, fields, constraints, and examples for the Eporner API.

## URL handling in 2.4.3

This version requires `eaf-base-api>=4.2.2`. Video IDs are read from the URL path, excluding query parameters and fragments; embed links are normalized to full video pages. Pornstar and channel objects expose `total_pages` from HTML pagination links. Their `videos(pages=0)` iterates the discovered pages instead of using a fixed page count.

Scraper instance to orchestrate requests and retrieve media objects.

```python
from eporner_api import Client
from base_api import BaseCore

client = Client()
client_custom = Client(core=BaseCore())
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore(RuntimeConfig())`)

## Methods

## get_video

Fetches a video profile page and returns a populated `Video` object. By default, parses the JSON API endpoint first.

```python
await client.get_video(
    url: str,
    load_html: bool = False,
    load_api: bool = True
) -> Video
```

### Parameters
- url str — The Eporner video URL
- load_html bool — Parse full HTML elements for detailed fields (default: `False`)
- load_api bool — Fetch base properties from Eporner JSON endpoint (default: `True`)

### Returns

→ Video

## search_videos

Queries search endpoints and streams video results.

```python
async for result in client.search_videos(
    query: str,
    sorting_gay: str | Gay = Gay.include_gay_content,
    sorting_order: str | Order = Order.latest,
    sorting_low_quality: str | LowQuality = LowQuality.include_low_quality_content,
    per_page: int = 30,
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query words
- sorting_gay Gay | str — Exclude/include gay content filters (see [Sorting Enums](sorting-enums.md))
- sorting_order Order | str — Sort order (see [Sorting Enums](sorting-enums.md))
- sorting_low_quality LowQuality | str — Low quality exclusions (see [Sorting Enums](sorting-enums.md))
- per_page int — Number of video results per index page
- pages int — Number of search pages to parse
- iterator_config IteratorConfig | None — Concurrency, source loading, ordering, retry, and error policy; defaults to Eporner's API+HTML configuration

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_videos_by_category

Retrieves video lists categorized under specific tags.

```python
async for result in client.get_videos_by_category(
    category: str | Category,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- category Category | str — Eporner Category enum (e.g. `Category._4K`)
- iterator_config IteratorConfig | None — Concurrency, source loading, ordering, retry, and error policy; defaults to Eporner's API+HTML configuration

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_pornstar

Loads a pornstar profile page containing bio details.

```python
await client.get_pornstar(
    url: str,
    load_html: bool = True
) -> Pornstar
```

### Parameters
- url str — The Eporner pornstar profile URL
- load_html bool — Pre-load parsed properties (default: `True`)

### Returns

→ Pornstar

## get_channel

Loads a channel profile page containing channel stats, logo, and banner.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Parameters
- url str — The Eporner channel profile URL
- load_html bool — Pre-load parsed properties (default: `True`)

### Returns

→ Channel

## Behavior and edge cases

Search defaults are `Gay.include_gay_content`, `Order.latest`, `LowQuality.include_low_quality_content`, `per_page=30` and `pages=2`. Pages must be positive; `per_page` must be between 1 and 1000. Invalid enum values raise `ValueError`. Search pagination is one-based. Video identity handling also accepts localized `/porno-video/` paths.

## Related MCP documents

- [Eporner API getting started](../getting-started.md)
- [Errors and troubleshooting — Eporner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
