---
title: "Client — Thumbzilla API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the Thumbzilla API."
public_url: "https://docs.echteralsfake.me/thumbzilla/"
aliases:
  - "Thumbzilla Client"
keywords:
  - "Thumbzilla"
  - "Client"
  - "get_video"
  - "get_pornstar"
  - "get_playlist"
  - "get_channel"
  - "get_amateur"
  - "search"
---

# Client — Thumbzilla API

Documents Client behavior, signatures, fields, constraints, and examples for the Thumbzilla API.

Main entry point class to execute searches and load resource models.

```python
from thumbzilla_api import Client
client = Client()
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore()`)

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
- url str — The Thumbzilla video URL
- load_html bool — Pre-load parsed properties immediately

### Returns

→ Video

## get_pornstar

Loads a pornstar profile page and returns a populated `Pornstar` object.

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

Loads playlist metadata and returns a populated `Playlist` object.

```python
await client.get_playlist(
    url: str,
    load_html: bool = True
) -> Playlist
```

### Parameters
- url str — The Thumbzilla playlist URL
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

## search

Queries Thumbzilla search index pages and yields structured video scrape results.

```python
async for result in client.search(
    query: str,
    pages: int = 2,
    iterator_configuration: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query words
- pages int — Number of search pages to parse
- iterator_configuration IteratorConfig | None — Concurrency, ordering, source loading, retry, and terminal-error policy. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Thumbzilla API getting started](../getting-started.md)
- [Errors and troubleshooting — Thumbzilla API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/thumbzilla/](https://docs.echteralsfake.me/thumbzilla/)
