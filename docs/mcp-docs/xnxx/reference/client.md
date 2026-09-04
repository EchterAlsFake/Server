---
title: "Client — XNXX API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the XNXX API."
public_url: "https://docs.echteralsfake.me/xnxx/"
aliases:
  - "XNXX Client"
keywords:
  - "XNXX"
  - "Client"
  - "get_video"
  - "get_user"
  - "search_videos"
---

# Client — XNXX API

Documents Client behavior, signatures, fields, constraints, and examples for the XNXX API.

The `Client` class is the entry point for all API requests. It initializes and manages sessions to retrieve videos, fetch user data, and execute paginated search queries.

```python
from xnxx_api import Client
from base_api import BaseCore

client = Client()

# Or initialize with custom core config
client_custom = Client(core=BaseCore())
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore()`)

## Methods

## get_video

Fetches a video page and returns a populated `Video` object. Extracts inline JSON metadata and master HLS playlist files.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The full XNXX video URL
- load_html bool — If `True` (default), fetches and parses the HTML page for metadata

### Returns

→ Video

## get_user

Fetches a user profile page and returns a populated `User` object. Simultaneously requests the profile page and the initial video JSON listing page to fetch totals.

```python
await client.get_user(
    url: str,
    load_html: bool = True
) -> User
```

### Parameters
- url str — The full XNXX user profile URL
- load_html bool — If `True` (default), parses HTML pages

### Returns

→ User

## search_videos

Searches for videos matching the query text. Supports filtering by search mode, duration range, upload date, and resolution quality. Yields results paginated. See [Search & Filtering](../guides/searching-and-filtering.md).

```python
async for result in client.search_videos(
    query: str,
    pages: int = 0,
    mode: Mode | str = "",
    upload_time: UploadTime | str = "",
    length: Length | str = "",
    searching_quality: SearchingQuality | str = "",
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search keywords
- pages int — Number of pages to iterate
- mode Mode | str — Sort mode (e.g. `Mode.hits`, `Mode.random`)
- upload_time UploadTime | str — Upload age filter (e.g. `UploadTime.month`)
- length Length | str — Video duration category (e.g. `Length.X_10min_plus`)
- searching_quality SearchingQuality | str — Video quality category (e.g. `SearchingQuality.X_1080p_plus`)
- iterator_config IteratorConfig | None — Optional v4 concurrency, ordering, eager-source, retry, and error-handling policy. The package default eagerly loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [XNXX API getting started](../getting-started.md)
- [Errors and troubleshooting — XNXX API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xnxx/](https://docs.echteralsfake.me/xnxx/)
