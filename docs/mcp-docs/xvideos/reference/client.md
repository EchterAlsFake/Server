---
title: "Client — XVideos API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Client"
keywords:
  - "XVideos"
  - "Client"
  - "get_video"
  - "search"
  - "get_playlist"
  - "get_pornstar"
  - "get_channel"
  - "get_account"
---

# Client — XVideos API

Documents Client behavior, signatures, fields, constraints, and examples for the XVideos API.

The `Client` class is your **entry point** for all interactions. It manages the session and provides methods to fetch videos, search, and access channels/pornstars.

## Methods

## get_video

Fetches a video page and returns a populated `Video` object.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The full XVideos video URL
- load_html bool — If `True` (default), fetches and parses the HTML page for full metadata

### Returns

→ Video

## search

Searches for videos and yields results as an async generator. See [Search & Filtering](../guides/searching-and-filtering.md) for details.

```python
async for result in client.search(
    query: str,
    sorting_sort: str | Sort = Sort.Sort_relevance,
    sorting_date: str | SortDate = SortDate.Sort_all,
    sorting_time: str | SortVideoTime = SortVideoTime.Sort_all,
    sort_quality: str | SortQuality = SortQuality.Sort_all,
    pages: int | str = "all",
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search terms
- pages int | "all" — Number of result pages or `"all"` for automatic iteration
- iterator_config IteratorConfig | None — Optional v4 concurrency, ordering, eager-source, retry, and error-handling policy. The package default eagerly loads `html`.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_playlist

Fetches videos from a playlist page by page.

```python
async for result in client.get_playlist(
    url: str,
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- url str — The playlist URL
- pages int — Number of pages to scrape
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default eagerly loads each video's `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_pornstar

Fetches a pornstar profile.

```python
await client.get_pornstar(
    url: str,
    load_html: bool = True
) -> Pornstar
```

### Returns

→ Pornstar

## get_channel

Fetches a channel profile.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Returns

→ Channel

## get_account

Creates an `Account` instance for authenticated actions using cookies. See [Account](account.md).

```python
client.get_account(
    cookies: dict | None = None
) -> Account
```

### Returns

→ Account

## Related MCP documents

- [XVideos API getting started](../getting-started.md)
- [Errors and troubleshooting — XVideos API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
