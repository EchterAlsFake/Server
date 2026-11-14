---
title: "Source loading — Pornhat API"
summary: "HTML and media loaders, dependency loading, loaded-versus-missing fields, atomic errors and serialization without requests."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Source loading — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "source-loading"
---

# Source loading — Pornhat API

Pornhat exposes `html` metadata and `media` redirect resolution. Embedded JSON-LD and
`data-setup` JSON belong to the HTML request, not an independent public JSON API.
Collections only declare `html`. Videos declare both sources.

| Request | Behavior |
| --- | --- |
| `await client.get_video(url)` | Load HTML metadata only |
| `await client.get_video(url, load_html=False)` | Construct without requests |
| `await client.get_video(url, load_html=False, load_media=True)` | Media loader first ensures HTML, then resolves sources |
| `await video.load_sources("html", "media")` | Load both, respecting the media dependency |
| `await video.load_fields("title")` | Load HTML if needed |
| `await video.load_fields("m3u8_base_url")` | Load HTML plus media if needed |
| `video.to_dict()` | Serialize loaded fields without requests |

```python
async def inspect_lazily(client, url):
    video = await client.get_video(url, load_html=False)
    assert not video.loaded_sources
    snapshot = video.to_dict()
    await video.load_fields("title", "duration")
    assert video.loaded_sources == {"html"}
    await video.load_sources("media")
    assert video.loaded_sources == {"html", "media"}
    return snapshot, video.to_dict()
```

Field access is synchronous and cannot fetch: unresolved fields raise `DataNotLoadedError`.
Known missing fields are `None`, while relationships can be empty lists. Inspect
`is_field_loaded(name)`, `unloaded_fields()`, `loaded_sources`, `source_state(source)` and
`source_errors` before consuming partial objects. `to_dict(include_unloaded=True)` represents
unloaded fields as `None`; use the default to preserve loaded-versus-unloaded distinction.

Listings can construct `Video` objects with URL and stable `video_id` already present,
without claiming their HTML source is loaded. Default listing configuration then loads HTML;
`make_iterator_config(load_specific_sources=())` keeps those objects deferred.

HTML data is committed atomically by the shared model. It is never overwritten by lower
information media resolution; each loader owns separate fields. Failed loaders raise shared
`MediaLoadError` or `MediaLoadErrors` with original causes and leave source errors inspectable.

See [Video](../reference/video.md), [errors](../troubleshooting/errors.md), and
[shared media models](../../eaf-base-api/reference/base-media.md).
