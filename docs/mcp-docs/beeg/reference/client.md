---
title: "Client — Beeg API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the Beeg API."
public_url: "https://docs.echteralsfake.me/beeg/"
aliases:
  - "Beeg Client"
keywords:
  - "Beeg"
  - "Client"
  - "get_video"
---

# Client — Beeg API

Documents Client behavior, signatures, fields, constraints, and examples for the Beeg API.

The `Client` class is the entry point for all API requests. It initializes and manages the networking core to request video information pages.

```python
from beeg_api import Client
from base_api import BaseCore

client = Client()

# Or initialize with custom core config
client_custom = Client(core=BaseCore())
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore()`)

## Methods

## get_video

Fetches a video profile and returns a populated `Video` object. Queries Beeg's external store endpoints to obtain video parameters.

```python
await client.get_video(
    url: str,
    load_api: bool = True
) -> Video
```

### Parameters
- url str — The full Beeg video URL
- load_api bool — If `True` (default), fetches and parses the JSON metadata API response

### Returns

→ Video

**Source-aware fields**
Beeg has no paginated `Helper` iterator: `get_video()` is its only fetch operation, so `IteratorConfig`, iterator `RetryPolicy`, custom scrape handlers, and `ScrapeResult` do not apply here. With `load_api=True`, all remote fields are loaded from the `"api"` source. If you construct a lightweight object with `load_api=False`, call `await video.load_sources("api")`, `await video.load_fields("title", "duration")`, or `await video.get_field("title")` before reading unresolved fields. Direct unresolved access raises `DataNotLoadedError`; a real loaded `None` does not.

## Related MCP documents

- [Beeg API getting started](../getting-started.md)
- [Errors and troubleshooting — Beeg API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/beeg/](https://docs.echteralsfake.me/beeg/)
