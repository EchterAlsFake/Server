---
title: "Pagination, iteration, and ScrapeResult — PornHub API"
summary: "Documents Pagination, iteration, and ScrapeResult behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Pagination, iteration, and ScrapeResult"
keywords:
  - "PornHub"
  - "Pagination, iteration, and ScrapeResult"
  - "ScrapeResult"
  - "stage"
  - "url"
  - "page_index"
  - "item_index"
  - "attempts"
  - "item"
  - "error"
  - "succeeded"
---

# Pagination, iteration, and ScrapeResult — PornHub API

Documents Pagination, iteration, and ScrapeResult behavior, signatures, fields, constraints, and examples for the PornHub API.

Methods like `search_videos()`, `pornstar.get_videos()`, `channel.get_videos()`, and the account iterators yield typed `ScrapeResult[T]` values. Use `succeeded` to branch safely or `unwrap()` to return the item and raise its terminal error on failure:

```python
async for result in client.search_videos("college", pages=2):
    if result.succeeded:
        video = result.unwrap()
        await video.load_sources("html")
        print(video.title)
    else:
        print(result.stage, result.url, result.error)
```

## ScrapeResult

## stage

Type: ScrapeStage; Description: Whether the result came from the page or item stage

## url

Type: str; Description: The video URL

## page_index

Type: int; Description: Zero-based source page index

## item_index

Type: int | None; Description: Zero-based item index, or None for a page failure

## attempts

Type: int; Description: Number of attempts used by the yielding stage

## item

Type: T | None; Description: The constructed Video , GIF , or User on success

## error

Type: ScrapeOperationError | None; Description: The typed terminal page or item error on failure

## succeeded

Type: bool; Description: True when error is None

## IteratorConfig, bounded retries, and custom handlers

All iterator-only controls now live in one `IteratorConfig`. Pornhub's package default uses `ErrorMode.SKIP` for terminal page failures; a supplied config replaces that behavior, and a bare `IteratorConfig` instead defaults to `ErrorMode.YIELD`. A retry policy's `max_attempts` includes the initial attempt, so this example makes at most three stage attempts per failed page or item. Each stage attempt may itself perform the request retries configured on `BaseCore`.

Leave `page_retry` or `item_retry` as `None` to derive that stage's bounded policy from the active `RuntimeConfig` request-attempt and backoff settings; an explicit `RetryPolicy` overrides it per stage.

**Pornhub source loading is opt-in**

Pornhub's default iterator configuration loads no media source eagerly: it constructs objects from listing data. Call `await item.load_sources("html")` or opt in with `load_specific_sources=("html",)`, as shown in this document. Use `"api"` only when the selected media type supports that loader.

```python
from base_api import ErrorAction, ResultOrder, RetryPolicy, ScrapeErrorContext
from base_api.modules.config import IteratorConfig

async def handle_scrape_error(context: ScrapeErrorContext) -> ErrorAction:
    if context.attempt < context.max_attempts:
        return ErrorAction.RETRY
    return ErrorAction.YIELD

retry = RetryPolicy(
    max_attempts=3, base_delay=0.5, multiplier=2.0,
    max_delay=4.0, jitter=0.2
)
iterator_config = IteratorConfig(
    max_page_concurrency=2,
    max_item_concurrency=8,
    max_pending_items=16,
    order=ResultOrder.ORIGINAL,
    load_specific_sources=("html",),
    page_retry=retry,
    item_retry=retry,
    page_error_handler=handle_scrape_error,
    item_error_handler=handle_scrape_error,
)

async for result in client.search_videos(
    "college", pages=2, iterator_config=iterator_config
):
    if result.succeeded:
        print(result.unwrap().title)
    else:
        print(result.stage, result.error)
```

`ScrapeErrorContext` supplies `stage`, `url`, `error`, `attempt`, `max_attempts`, `page_index`, and `item_index`. A handler returns `ErrorAction.RETRY`, `RAISE`, `YIELD`, or `SKIP`.

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [IteratorConfig — eaf_base_api](../../eaf-base-api/configuration/iterator-config.md)
- [ScrapeStream and ScrapeResult — eaf_base_api](../../eaf-base-api/reference/scrape-stream-and-result.md)
- [RetryPolicy and custom error handling — eaf_base_api](../../eaf-base-api/guides/retry-and-error-handling.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
