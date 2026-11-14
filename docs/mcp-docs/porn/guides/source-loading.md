---
title: "Source loading — Porn.com API"
summary: "The single html metadata source, eager/deferred loading, listing-seeded fields, load_sources load_fields and to_dict serialization."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Source loading — Porn.com API", "Source loading Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "load_sources", "load_fields", "to_dict", "loaded_sources", "html", "DataNotLoadedError"]
---

# Source loading — Porn.com API

`Video` and the Collection subclasses declare one source: **`html`**. Individual
Client getters load it by default. No independently selectable public video API
was established: the REST root returned 401, while embedded WordPress schema
describes the generic `/scene` page. There are no `load_api` flags or `media`
loader. `get_qualities()` explicitly requests the real HLS master when needed.

```python
from porn_api import Client

async def inspect_sources():
    async with Client() as client:
        video = await client.get_video(
            "https://www.porn.com/scene/208974141", load_html=False,
        )
        print(video.loaded_sources, video.to_dict())
        await video.load_fields("title", "duration")
        print(video.title, video.duration)
        await video.load_sources("html")
        print(video.to_dict())
```

The shared `BaseMedia` loader applies field mappings atomically. Attribute access
is synchronous and never starts network I/O. An unloaded field raises
`DataNotLoadedError`; a loaded `None` or empty relationship list represents
known absence. Repeated/concurrent source loads share the shared media contract.

Use `loaded_sources`, `source_state("html")`, `source_errors`,
`is_field_loaded(name)`, `unloaded_fields()`, `load_fields(...)`, and
`load_sources(...)` to inspect or load state. `to_dict()` omits unresolved fields
and the core by default; `include_unloaded=True`/`include_core=True` are explicit
serialization options and do not fetch extra sources.

Listings return summary objects with observed title/poster/duration/rating or
directory name already seeded. Other scene/profile fields remain unresolved.
Because a summary already has `title`, `load_fields("title")` may perform no
detail request. Call `load_sources("html")` to request full scene metadata, or
set `IteratorConfig(load_specific_sources=("html",))` for eager item loading.
When referral HTML lacks a poster or exact duration, its observed listing image
and rounded length label are retained. Listing provenance remains separate.

Unsupported source names raise shared loader configuration errors. See
[errors](../troubleshooting/errors.md) and [iteration](iteration-and-results.md).
