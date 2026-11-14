---
title: "Source loading — Bellesa API"
summary: "Independent API-only and HTML-only Video/Performer metadata, precedence, deferred fields, media dependencies and serialization. Symbols: load_api load_html load_sources load_fields to_dict is_field_loaded loaded_sources unloaded_fields."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Source loading — Bellesa API", "Bellesa source loading"]
keywords: ["Bellesa", "bellesa_api", "load_api", "load_html", "load_sources", "load_fields", "media", "DataNotLoadedError", "to_dict"]
---

# Source loading — Bellesa API

Video and Performer each declare independent `api` and `html` sources. Their getters
load API by default and leave HTML deferred. API is an anonymous JSON request; HTML
reads the requested object from server-rendered `window.__INITIAL_DATA__`. Embedded
JSON is part of the HTML request, not a separate network API.

```python
from bellesa_api import Client

async def inspect_sources():
    url = "https://www.bellesa.co/videos/1094"
    async with Client() as client:
        api = await client.get_video(url, load_api=True, load_html=False)
        html = await client.get_video(url, load_api=False, load_html=True)
        both = await client.get_video(url, load_api=True, load_html=True)
        deferred = await client.get_video(url, load_api=False, load_html=False)
        print(deferred.to_dict())
        await deferred.load_fields("title")
        await deferred.load_sources("html")
        print(deferred.title, deferred.canonical_url)
        await deferred.load_sources("media")
        print(deferred.renditions)
```

A common field uses API precedence regardless of completion or loading order.
HTML-only `canonical_url` and `og_title` remain available after API loads. Description
is taken from the target video; a generic website description does not replace a known
absent one. The shared loader applies mappings atomically and records source failures.

Access is synchronous: reading an unresolved field raises `DataNotLoadedError` and
does not initiate network I/O. `None` means a loaded source knows a value is absent.
Use `loaded_sources`, `source_state(source)`, `source_errors`, `is_field_loaded(name)`,
`unloaded_fields()`, `load_fields(...)`, and `load_sources(...)` for inspection/loading.
`to_dict()` omits unresolved fields and `core` by default without fetching. The shared
`include_unloaded` and `include_core` options control serialization explicitly.

`Video` also has a lazy `media` source. It obtains prerequisite player metadata if
needed, then reads the HLS master to populate measured renditions and direct-source
mappings. To keep metadata HTML-only, load HTML before requesting media. It reuses
already-loaded fields instead of fetching API when that is sufficient.

Channel and Category have `api` metadata only; passing an unsupported source name raises
a shared loader configuration error. `refresh_media()` returns a new API/media-loaded
Video and does not automatically load HTML-only fields.

See [Video fields](../reference/video.md), [errors](../troubleshooting/errors.md), and
[shared BaseMedia](../../eaf-base-api/reference/base-media.md).
