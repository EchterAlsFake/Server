---
title: "Iteration and results — Pornhat API"
summary: "ScrapeStream lifecycle, ScrapeResult errors, one-based pagination, pages=all, deferred fields, ordering and complete profile evidence."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Iteration and results — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "iteration-and-results"
---

# Iteration and results — Pornhat API

Video catalogs, search, model/channel directories, and collection `.videos()` return
`ScrapeStream` objects. Construction is lazy; iteration fetches the first listing page to
inspect actual pagination, then requests the bounded selected range through the shared helper.

| Option | Meaning |
| --- | --- |
| `pages=1` | One page (default) |
| `pages=N` | Positive count of pages from start_page, clamped to the last page |
| `pages="all"` | All remaining pages |
| `start_page=1` | Positive one-based first requested page |
| `iterator_config=None` | HTML-loaded items, original ordering, yielded terminal item/page errors |

Beyond-last ranges return an empty stream. Invalid counts, booleans or nonpositive indices
raise `ValueError`. Initial navigation-discovery errors propagate directly; later page/item
failures follow `IteratorConfig`. Call `result.unwrap()` so failures are not silently ignored.

```python
from base_api import make_iterator_config

async def list_all(client):
    model = await client.get_model("https://www.pornhat.com/models/armani-black/")
    config = make_iterator_config(
        load_specific_sources=(),
        order="original",
        page_error_mode="raise",
        item_error_mode="raise",
        max_page_concurrency=2,
        max_item_concurrency=2,
    )
    async with model.videos(pages="all", iterator_config=config) as results:
        async for result in results:
            video = result.unwrap()
            print(video.video_id, video.url)
```

Without a caller configuration, the provider requests `html` for each item. To request only
certain fields, use `make_iterator_config(load_specific_sources=(), load_specific_fields=("title",))`.
Because all video metadata shares one HTML loader, requesting title also loads that page's
other HTML fields. Requesting media fields additionally resolves player redirects.
An explicit `IteratorConfig` is honored without replacing its source/error/order settings.
`order="completion"` permits completion order; the default is original page/card order.

Use `async with` or `await stream.aclose()` when stopping early so pending work is closed.
Do not close the injected core until all streams and returned object operations finish.

## Observed page boundaries

Full profile pages contain 59 real videos; ad cards are excluded. The following complete
listings were reconciled independently against live HTML on 2026-11-09:

| Type / route | Expected / actual IDs | Cards per page |
| --- | --- | --- |
| Model `/models/armani-black/` | 200 / 200 | 59, 59, 59, 23 |
| Model `/models/venus-valencia/` | 53 / 53 | 53 |
| Channel `/sites/60-plus-milfs/` | 471 / 471 | 59, 59, 59, 59, 59, 59, 59, 58 |
| Channel `/sites/deep-throat-sirens/` | 1 / 1 | 1 |
| Channel `/sites/cannon-productions/` | 0 / 0 | Explicit empty-state block |

These profiles had no duplicates or missing/unexpected IDs. Search pages may repeat cards;
no global deduplication is imposed. A changing catalog is not a transactional snapshot.
Exact page-capacity multiples were not observed. Empty search results and zero-video channels
are recognized through explicit empty-state markers; missing containers otherwise raise errors.

See [shared iterator configuration](../../eaf-base-api/configuration/iterator-config.md).
