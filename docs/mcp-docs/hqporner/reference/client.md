---
title: "Client — HQPorner API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the HQPorner API."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner Client"
keywords:
  - "HQPorner"
  - "Client"
  - "get_video"
  - "get_videos_by_actress"
  - "get_videos_by_category"
  - "search_videos"
  - "get_top_porn"
  - "get_random_video"
  - "get_all_categories"
  - "get_brazzers_videos"
---

# Client — HQPorner API

Documents Client behavior, signatures, fields, constraints, and examples for the HQPorner API.

The `Client` class is your **entry point** for all interactions. It manages the session and headers, providing methods to search, retrieve category lists, and scrape video listings.

## Methods

## get_video

Fetches a video page and returns a populated `Video` object. Supports mobile URL fallbacks automatically.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The full HQPorner video URL
- load_html bool — If `True` (default), fetches and parses the HTML page for metadata

### Returns

→ Video

## get_videos_by_actress

Fetches videos matching the given actress page by page.

```python
async for result in client.get_videos_by_actress(
    name: str,
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- name str — The actress name (slug format or full URL)
- pages int — Number of pages to fetch (default: `5`)
- iterator_config IteratorConfig | None — Concurrency, HTML loading, ordering, retry, and error policy

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_videos_by_category

Fetches videos belonging to a specific category page by page.

```python
async for result in client.get_videos_by_category(
    category: Category | str,
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- category Category | str — The category name or Enum member
- pages int — Number of pages to fetch (default: `5`)
- iterator_config IteratorConfig | None — Concurrency, HTML loading, ordering, retry, and error policy

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## search_videos

Searches for videos matching the query text. See [Search & Filtering](../guides/searching-and-filtering.md) for details.

```python
async for result in client.search_videos(
    query: str,
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search keywords
- pages int — Number of result pages to iterate
- iterator_config IteratorConfig | None — Concurrency, HTML loading, ordering, retry, and error policy

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_top_porn

Fetches top rated/viewed videos sorted by a specific interval.

```python
async for result in client.get_top_porn(
    sort_by: Sort | str,
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- sort_by Sort | str — Sort interval: `Sort.ALL_TIME`, `Sort.WEEK`, `Sort.MONTH`
- pages int — Number of pages to retrieve
- iterator_config IteratorConfig | None — Concurrency, HTML loading, ordering, retry, and error policy

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_random_video

Queries the random endpoint, extracts three random suggestions, and returns one randomly selected `Video` object.

```python
await client.get_random_video(
    load_html: bool = True
) -> Video
```

### Returns

→ Video

## get_all_categories

Scrapes and returns a complete list of all category slug strings available on HQPorner.

```python
await client.get_all_categories() -> list[str]
```

### Returns

→ list[str]

## get_brazzers_videos

Fetches free Brazzers videos hosted on HQPorner.

```python
async for result in client.get_brazzers_videos(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of pages to fetch
- iterator_config IteratorConfig | None — Concurrency, HTML loading, ordering, retry, and error policy

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [HQPorner API getting started](../getting-started.md)
- [Errors and troubleshooting — HQPorner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
