---
title: "Pagination, iteration, and ScrapeResult — Bellesa API"
summary: "One-based pages and pages=all, exact/partial boundaries, source loading defaults, result unwrapping, error policies and stream closure. Symbols: pages start_page load_specific_sources load_specific_fields page_error_mode item_error_mode."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Pagination, iteration, and ScrapeResult — Bellesa API", "Bellesa iteration and results"]
keywords: ["Bellesa", "bellesa_api", "ScrapeStream", "ScrapeResult", "IteratorConfig", "pages", "start_page", "unwrap", "ResultOrder", "ErrorMode"]
---

# Pagination, iteration, and ScrapeResult — Bellesa API

Listings return `ScrapeStream` objects yielding `ScrapeResult[T]`. Stream methods are
synchronous factories: use `async with client.search(...) as stream`, not
`await client.search(...)`. Object getters such as `get_video()` are awaited.

```python
from bellesa_api import Client

async def iterate():
    async with Client() as client:
        async with client.get_videos(pages=2, start_page=1) as stream:
            async for result in stream:
                video = result.unwrap()
                print(video.video_id, video.title)
```

## Pages and boundaries

`start_page` is one-based and positive. `pages` is a positive page count from that start,
or `"all"`. Actual endpoint `x-pagination-*` headers bound the requested range. Beyond-last
and known empty listings yield nothing. The initial request validates the returned page
number; it raises if Bellesa returns a different page. There is no guessed page total.

| Listing | Items per page |
|---|---:|
| General videos, channels, categories, search | 24 |
| Performer profile videos | 9 |
| Performer directory | 12 |
| Related videos | 6 |

The range includes partial final pages and exact full-page boundaries. Performer
`video_count` is not used to invent a free listing total. Channel pagination uses the
actual provider filter because the website's `/channels/...` redirect loses page queries.
Recommendations, campaigns and autoplay rails are separate from these listings.

## Defaults and IteratorConfig

Provider defaults load API metadata, use `ResultOrder.ORIGINAL`, and raise terminal page
and item errors. A supplied `IteratorConfig` is honored instead. A bare shared config
has no requested metadata sources/fields and uses completion ordering and yielded errors.
Set ordering explicitly when comparing complete ID sequences.

```python
from base_api import ErrorMode, IteratorConfig, ResultOrder
from bellesa_api import Client

async def deferred_items():
    options = IteratorConfig(
        order=ResultOrder.ORIGINAL,
        load_specific_sources=(),
        load_specific_fields=(),
        max_page_concurrency=1,
        max_item_concurrency=2,
        page_error_mode=ErrorMode.YIELD,
        item_error_mode=ErrorMode.YIELD,
    )
    async with Client() as client:
        async with client.get_videos(iterator_config=options) as stream:
            async for result in stream:
                if result.succeeded:
                    print(result.unwrap().video_id)  # Metadata remains deferred.
                else:
                    print(result.stage, result.url, result.error)
```

Use `load_specific_sources=("html",)` for HTML-loaded video results, or
`load_specific_fields=("title",)` to load just the required source. Requesting a field
loads its source mapping, not an invented field-only network endpoint. Profiles without
an HTML source must use API/field loading. Concurrency, bounded retries and error handlers
are shared backend contracts; the initial pagination request precedes Helper scheduling
and propagates its own transport errors directly.

## ScrapeResult and cleanup

Results expose `stage`, `url`, `page_index`, `item_index`, `attempts`, `item`, `error`,
and `succeeded`. `unwrap()` returns the item or raises its typed terminal scrape error.
Stage indexes describe the scheduler's source range; they are not website page numbers.

Always use `async with` when breaking early. Exhaustion cleans up naturally; explicit
stream contexts cancel pending work on partial consumption. Keep the owning core open
while consuming the stream.

See [shared IteratorConfig](../../eaf-base-api/configuration/iterator-config.md) and
[shared ScrapeStream/Result](../../eaf-base-api/reference/scrape-stream-and-result.md).
