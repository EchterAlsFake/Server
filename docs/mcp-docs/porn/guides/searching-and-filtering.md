---
title: "Searching and filtering — Porn.com API"
summary: "Search query encoding, category redirects, Filters examples, empty added-period boundaries and orientation-specific routes."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Searching and filtering — Porn.com API", "Searching and filtering Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "search", "Filters", "sq", "orientation", "filter"]
---

# Searching and filtering — Porn.com API

`Client.search(query, *, pages=1, start_page=1, filters=None,
iterator_config=None)` streams `ScrapeResult[Video]`. A query must contain
1–100 characters and not be whitespace-only. The client encodes it under `sq`.
Search can legitimately redirect to a category: `yoga` resolves to `/yoga-porn`.
An unmatched search uses a verified empty-results layout, not a fake empty Video.

```python
from contextlib import aclosing
from porn_api import Client, Filters

async def search_videos():
    async with Client() as client:
        filters = Filters(source="xVideos", min_minutes=20, hd=True)
        async with aclosing(client.search("yoga", pages=2, filters=filters)) as stream:
            async for result in stream:
                summary = result.unwrap()
                print(summary.video_id, summary.title)
```

The same [Filters](../reference/filters.md) object works with
`Pornstar.videos`, `Channel.videos`, `Category.videos`, and `Source.videos`.
For an existing resource URL, omitting `filters` preserves its query filters;
passing a Filters object replaces the supported filter keys.

Select a verified language host with `Client(base_url="https://de.porn.com")`.
Use `Client(orientation="gay")` or `"trans"` for `/gay/search` or `/trans/search`
and the corresponding directories. Individual getters retain the URL supplied
by the caller rather than automatically adding an orientation prefix.

The backend reproduces the live response grid. Some injected cards can fall
outside a duration/source/quality filter, and displayed totals can remain
unfiltered. In the initial live run, yoga's `added_days=1` and `7` returned an
explicit page-0 empty listing; the other tested filters returned actual cards.
No additional sort parameter or sorting enums were verified.

See [pagination and result handling](iteration-and-results.md).
