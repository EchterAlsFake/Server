---
title: "Iteration and results — Porn.com API"
summary: "ScrapeResult unwrap, IteratorConfig, one-based pages and start_page, duplicate preservation and numeric pagination beyond disabled Next links."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Iteration and results — Porn.com API", "Iteration and results Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "ScrapeResult", "IteratorConfig", "pages", "start_page", "unwrap", "pagination"]
---

# Iteration and results — Porn.com API

Search, profile/category/source videos, related videos, and directories return
async `ScrapeResult` streams. Defaults construct observed summaries and raise
terminal errors. Every result must be unwrapped; a configured yielded failure
must not silently disappear from the caller's loop.

```python
from contextlib import aclosing
from base_api import ErrorMode, IteratorConfig, ResultOrder
from porn_api import Client

async def iterate_profile():
    config = IteratorConfig(
        order=ResultOrder.ORIGINAL,
        max_item_concurrency=2,
        page_error_mode=ErrorMode.RAISE,
        item_error_mode=ErrorMode.RAISE,
        load_specific_sources=(),
    )
    async with Client() as client:
        channel = await client.get_channel("https://www.porn.com/bratty-sis")
        async with aclosing(channel.videos(pages="all", iterator_config=config)) as stream:
            async for result in stream:
                video = result.unwrap()
                print(result.page_index, result.item_index, video.video_id)
```

`IteratorConfig` also controls item/source/field loading, error handling, retries,
and completion ordering. Set `load_specific_sources=("html",)` for full item
loading, or `load_specific_fields=("duration",)` to request a required lazy field.
An already seeded field need not trigger a detail fetch. The exact caller
configuration is passed through to the shared Helper for each page.

## Pagination

- `start_page` is a positive one-based page number; `pages` is a positive count
  from that start or the string `"all"`.
- Real Next links determine the next URL. Paging is sequential; item work on a
  page remains bounded/configurable. This wrapper does not concurrently prefetch
  a guessed range of pages.
- Disabled/missing Next links are not sufficient proof of completion. If more
  pages were requested, the established `pg` route is probed until a genuine
  empty page or terminal boundary 404. Repeated URLs/entire pages raise errors.
- A boundary probe's 404 ends iteration. An explicitly requested initial page
  returning 404 raises a typed page error. Other failures remain governed by
  the caller's error policy. A skipped/failed page cannot establish completeness.

The verified Mia Khalifa grid disables Next at page 13, but pages 14–23 still
contain videos. Page 24 returns 404. `pages="all"` includes these extra live pages.
No hard-coded page size or advertised count truncates the feed.

Only actual cards in the intended video grid become items; native ad slots have
no video identity and are excluded. Duplicate/pinned IDs and recommendations
blended into that grid are preserved in site order. `video_count` is an advertised
slot total, not a unique-ID count. [Reconciliation](live-validation.md) records
the observed differences exactly. Use `aclosing` when stopping a stream early.
