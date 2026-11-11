---
title: "Searching and filtering — Bellesa API"
summary: "Typed video/performer/channel search, site matching, sequence filters, OR semantics, duration seconds and sort choices. Symbols: Client.search Client.get_videos min_duration max_duration."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Searching and filtering — Bellesa API", "Bellesa searching and filtering"]
keywords: ["Bellesa", "bellesa_api", "search", "get_videos", "categories", "channels", "performers", "tags", "min_duration", "max_duration"]
---

# Searching and filtering — Bellesa API

`Client.search(query, kind="video", sort=Sort.RELEVANCE, ...)` uses the site's search
endpoint. A trimmed query must have at least three characters; an empty query is not
a general catalog listing. Select `kind="performer"` or `kind="channel"` for typed profile
results. Search supports relevance, recent, longest and popular ordering. Matching and
ranking are site-defined; a query containing one meaningful term can return results
even when its other tokens appear unusual.

```python
from bellesa_api import Client, Sort

async def search_catalog():
    async with Client() as client:
        async with client.search("romance", sort=Sort.POPULAR) as stream:
            async for result in stream:
                print(result.unwrap().title)
        async with client.search("lacy lennon", kind="performer") as stream:
            async for result in stream:
                print(result.unwrap().name)
        async with client.search("zero", kind="channel") as stream:
            async for result in stream:
                print(result.unwrap().name)
```

Use `get_videos()` for a general or filtered listing:

```python
from bellesa_api import Client

async def filter_catalog():
    async with Client() as client:
        async with client.get_videos(
            categories=["sensual"], channels=["zero-to-hero", "belle-says"],
            performers=[], tags=[], min_duration=60, max_duration=1200,
            sort="recent", pages=2, start_page=1,
        ) as stream:
            async for result in stream:
                print(result.unwrap().video_id)
```

Each filter accepts a sequence of handles/tags, not a scalar string or object URL.
Channel/performer multiselects use the site's OR filter. Duration bounds are seconds,
nonnegative integers, and ordered when both are supplied; the website's UI may express
these in minutes, which does not change this API's units. Empty valid listings yield
nothing. Empty results are not substituted with promoted or recommended videos.

Filters are available on `get_videos()`, not as arbitrary keyword arguments to `search()`.
Profile `.videos()` methods accept sort/pagination/iterator controls. The performer
directory supports `gender="female"`, `"male"`, or `"all"` through `get_performers()`.
See [Client](../reference/client.md), [Sort](../reference/sorting-enums.md), and
[iteration](iteration-and-results.md).
