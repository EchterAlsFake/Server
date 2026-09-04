---
title: "Client — Redtube API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube Client"
keywords:
  - "Redtube"
  - "Client"
  - "get_video"
  - "get_pornstar"
  - "get_playlist"
  - "get_channel"
  - "get_amateur"
  - "get_user"
  - "search"
---

# Client — Redtube API

Documents Client behavior, signatures, fields, constraints, and examples for the Redtube API.

Main entry point class to execute searches and load resource models.

```python
from redtube_api import Client
from base_api import BaseCore

client = Client()
client_custom = Client(core=BaseCore())
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore()`)

## Methods

## get_video

Fetches a video profile page and returns a populated `Video` object. Parses the configuration script embedded inside the HTML.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — The Redtube video URL
- load_html bool — Pre-load parsed properties immediately

### Returns

→ Video

## get_pornstar

Loads a model profile page and returns a populated `Pornstar` object.

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

## get_playlist

Loads playlist information metadata and returns an `Playlist` object.

```python
await client.get_playlist(
    url: str,
    load_html: bool = True
) -> Playlist
```

### Parameters
- url str — The Redtube playlist URL
- load_html bool — Pre-load parsed properties

### Returns

→ Playlist

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

## get_user

Loads a registered user account profile page.

```python
await client.get_user(
    url: str,
    load_html: bool = True
) -> User
```

### Parameters
- url str — The user profile page URL
- load_html bool — Pre-load parsed properties

### Returns

→ User

## search

Queries Redtube search index pages and yields video scrape results.

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
- iterator_config IteratorConfig | None — Optional v4 concurrency, ordering, eager-source, retry, and error-handling policy. The package default eagerly loads `html`.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Redtube API getting started](../getting-started.md)
- [Errors and troubleshooting — Redtube API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
