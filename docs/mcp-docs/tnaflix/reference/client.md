---
title: "Client — TNAFlix API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the TNAFlix API."
public_url: "https://docs.echteralsfake.me/tnaflix/"
aliases:
  - "TNAFlix Client"
keywords:
  - "TNAFlix"
  - "Client"
  - "get_video"
  - "get_channel"
  - "get_profile"
  - "get_pornstar"
  - "search"
---

# Client — TNAFlix API

Documents Client behavior, signatures, fields, constraints, and examples for the TNAFlix API.

The `Client` class is the primary entry point to interact with the TNAFlix scraper ecosystem.

```python
from tnaflix_api import Client
from base_api import BaseCore

client = Client()
client_custom = Client(core=BaseCore())
```

## Constructor Parameters
- core BaseCore — Shared networking core instance (default: `BaseCore()`)

## Methods

## get_video

Fetches video metadata for a TNAFlix video URL and returns a populated `Video` object.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The full TNAFlix video page URL
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Video

## get_channel

Fetches publisher studio or creator channel page metadata and returns a populated `Channel` object.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Parameters
- url str — The TNAFlix channel URL (e.g. `https://www.tnaflix.com/channel/team-skeet`)
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Channel

## get_profile

Fetches metadata for a TNAFlix user profile page and returns a populated `Profile` object.

```python
await client.get_profile(
    url: str,
    load_html: bool = True
) -> Profile
```

### Parameters
- url str — The TNAFlix profile page URL (e.g. `https://www.tnaflix.com/profile/username`)
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Profile

## get_pornstar

Fetches metadata for a recognized pornstar profile page and returns a populated `Pornstar` object.

```python
await client.get_pornstar(
    url: str,
    load_html: bool = True
) -> Pornstar
```

### Parameters
- url str — The TNAFlix pornstar profile URL (e.g. `https://www.tnaflix.com/profile/lyla-lei`)
- load_html bool — If `True` (default), fetches and extracts metadata immediately

### Returns

→ Pornstar

## search

Queries TNAFlix video search and yields results as an asynchronous generator.

```python
async for result in client.search(
    query: str,
    sorting_sort: str | Sort = Sort.RECENT,
    sorting_date: str | SortDate = SortDate.ALL_TIME,
    pages: int | str = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query term
- sorting_sort str | Sort — Sort criteria enum (default: `Sort.RECENT`)
- sorting_date str | SortDate — Date filtering enum (default: `SortDate.ALL_TIME`)
- pages int | str — Number of search pages to parse (default: `2`) or `"all"`
- iterator_config IteratorConfig | None — Optional v4 iterator policy. Defaults to eagerly loading `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [TNAFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — TNAFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tnaflix/](https://docs.echteralsfake.me/tnaflix/)
