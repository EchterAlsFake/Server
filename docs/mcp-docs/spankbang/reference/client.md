---
title: "Client — SpankBang API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the SpankBang API."
public_url: "https://docs.echteralsfake.me/spankbang/"
aliases:
  - "SpankBang Client"
keywords:
  - "SpankBang"
  - "Client"
  - "get_video"
  - "get_channel"
  - "get_pornstar"
  - "get_creator"
  - "search"
---

# Client — SpankBang API

Documents Client behavior, signatures, fields, constraints, and examples for the SpankBang API.

The `Client` class manages the network session, cookies, and HTTP headers to interact with SpankBang. It serves as the primary entry point to retrieve video details, explore profile channels/pornstars/creators, and run search queries.

```python
from spankbang_api import Client
from base_api import BaseCore

client = Client()

# Or construct with custom core configuration
client_custom = Client(core=BaseCore())
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore(RuntimeConfig())`)

## Methods

## get_video

Fetches a video page and returns a populated `Video` object. Parses Javascript variables containing HLS master playlists and direct MP4 resolutions.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The full SpankBang video URL
- load_html bool — If `True` (default), fetches and parses the HTML page for metadata

### Returns

→ Video

## get_channel

Fetches a channel profile page and returns a populated `Channel` object.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Parameters
- url str — The full SpankBang channel URL
- load_html bool — If `True` (default), parses the profile HTML for metadata

### Returns

→ Channel

## get_pornstar

Fetches a pornstar profile page and returns a populated `Pornstar` object.

```python
await client.get_pornstar(
    url: str,
    load_html: bool = True
) -> Pornstar
```

### Parameters
- url str — The full SpankBang pornstar URL
- load_html bool — If `True` (default), parses the profile HTML for metadata

### Returns

→ Pornstar

## get_creator

Fetches a creator profile page and returns a populated `Creator` object.

```python
await client.get_creator(
    url: str,
    load_html: bool = True
) -> Creator
```

### Parameters
- url str — The full SpankBang creator URL
- load_html bool — If `True` (default), parses the profile HTML

### Returns

→ Creator

## search

Performs a search query for videos with options to filter by rating, quality, duration, and upload date. Yields results paginated. See [Search & Filtering](../guides/searching-and-filtering.md).

```python
async for result in client.search(
    query,
    filter: Literal["trending", "new", "featured", "popular"] | None = None,
    quality: Literal["hd", "fhd", "uhd"] | None = None,
    duration: Literal["10", "20", "40"] | None = None,
    date: Literal["d", "w", "m", "y"] | None = None,
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query keywords
- filter str | None — Filter order: `"trending"`, `"new"`, `"featured"`, `"popular"`
- quality str | None — Quality filter: `"hd"` (720p), `"fhd"` (1080p), `"uhd"` (4k)
- duration str | None — Duration limits: `"10"` (10+ min), `"20"` (20+ min), `"40"` (40+ min)
- date str | None — Upload date range: `"d"` (day), `"w"` (week), `"m"` (month), `"y"` (year)
- pages int — Number of pages to iterate (default: `2`)
- iterator_config IteratorConfig | None — Optional v4 concurrency, ordering, eager-source, retry, and error-handling policy. The package default eagerly loads `html`.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [SpankBang API getting started](../getting-started.md)
- [Errors and troubleshooting — SpankBang API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/spankbang/](https://docs.echteralsfake.me/spankbang/)
