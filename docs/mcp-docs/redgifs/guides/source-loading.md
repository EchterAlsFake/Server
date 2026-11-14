---
title: "Source loading — RedGIFs API"
summary: "Independent API/HTML flags, deferred fields, API precedence including None, serialization and image type checks. Symbols: load_sources load_fields to_dict include_unloaded include_core loaded_sources source_state source_errors is_field_loaded unloaded_fields."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Source loading — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "load_sources"
  - "load_fields"
  - "DataNotLoadedError"
  - "HTML"
  - "API"
  - "precedence"
---

# Source loading — RedGIFs API

`Video` and `Image` declare independent `api` and `html` loaders through the shared
`BaseMedia` interface. API loading defaults on, HTML off. Users, niches and collections
have only `api`; requesting `html` on them is a loader configuration error.

| Mode | Arguments / operation | Result |
| --- | --- | --- |
| API only | `load_api=True, load_html=False` | API fields; title remains unloaded |
| HTML only | `load_api=False, load_html=True` | HTML title/page fields; API-only fields remain unloaded |
| Both | `load_api=True, load_html=True` | Combined fields with declared API precedence |
| Deferred | Both flags false | Identity only, no metadata request |
| API then HTML | `load_sources("api")`, then `load_sources("html")` | Same precedence as combined loading |
| HTML then API | Reverse load order | Same final precedence |

```python
from redgifs_api import Client

async def inspect_sources():
    async with Client() as client:
        video = await client.get_video("hotpinkacrobatickitfox", load_api=False)
        print(video.to_dict())
        await video.load_fields("duration")
        assert video.loaded_sources == {"api"}
        await video.load_sources("html")
        print(video.title, video.page_description, video.duration)
```

`load_fields()` selects enough sources to cover unloaded requested fields; it may load
other fields from the same response. API-only fields include duration, publication date,
counts, dimensions, flags and rendition URLs. HTML-only fields include display title,
page description and raw HTML metadata. `description`, `thumbnail_url`, and `embed_url`
prefer API even when an API value is explicitly null. HTML-only information is retained
in its separate fields rather than overwritten.

Synchronous attribute reads never fetch. Unloaded fields raise `DataNotLoadedError`;
a loaded absent field is `None`. `to_dict()` omits unloaded fields by default and avoids
network requests; `include_unloaded=True` includes them as null, and `include_core=True`
includes the backend. Inspect `loaded_sources`, `source_state()`, `source_errors`,
`is_field_loaded()` and `unloaded_fields()` separately for loading state.

Successful sources stay committed. Failed loaders preserve their causes in shared
`MediaLoadError`/`MediaLoadErrors`; no partial mapping is applied. Loading one source
fails independently of a successful sibling. There is no provider `force=True` reload
argument. `get_download_url(refresh=True)` and downloads refresh the selected direct URL;
this does not overwrite an already committed metadata snapshot.

HTML parsing matches the requested stable ID and expected `VideoObject`/`ImageObject`.
Unrelated structured data or a challenge/directory page is not an empty successful media
object. Malformed HTML dates remain raw; normalized UTC dates come from API Unix seconds.
See [Video fields](../reference/video.md) and
[shared media loading](../../eaf-base-api/reference/base-media.md).
