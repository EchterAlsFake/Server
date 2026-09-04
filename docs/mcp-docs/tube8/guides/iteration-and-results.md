---
title: "Iteration and ScrapeResult — Tube8 API"
summary: "Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 Iteration and ScrapeResult"
keywords:
  - "Tube8"
  - "Iteration and ScrapeResult"
  - "stage"
  - "url"
  - "page_index"
  - "item_index"
  - "attempts"
  - "item"
  - "error"
  - "succeeded"
  - "unwrap"
---

# Iteration and ScrapeResult — Tube8 API

Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the Tube8 API.

All concurrently iterated methods accept one `IteratorConfig` policy and yield immutable `ScrapeResult[Video]` values. Tube8's package default loads the `html` source, skips terminal page failures, and uses `RetryPolicy(max_attempts=3)` for both page and item stages. A supplied configuration replaces that default, so preserve the HTML source, page error mode, and desired retry policies explicitly; the example in this document deliberately opts into yielding page failures.

```python
from base_api import ErrorAction, ErrorMode, ResultOrder, RetryPolicy, ScrapeErrorContext
from base_api.modules.config import IteratorConfig

async def handle_error(context: ScrapeErrorContext) -> ErrorAction:
    if context.attempt < context.max_attempts:
        return ErrorAction.RETRY
    return ErrorAction.YIELD

iterator_config = IteratorConfig(
    max_page_concurrency=2,
    max_item_concurrency=8,
    order=ResultOrder.ORIGINAL,
    load_specific_sources=("html",),
    page_retry=RetryPolicy(max_attempts=3, base_delay=0.5),
    item_retry=RetryPolicy(max_attempts=3, base_delay=0.5),
    page_error_mode=ErrorMode.YIELD,
    item_error_mode=ErrorMode.YIELD,
    page_error_handler=handle_error,
    item_error_handler=handle_error,
)

async for result in client.search(
    "beach", pages=2, iterator_config=iterator_config
):
    if result.succeeded:
        video = result.unwrap()
        print(video.title)
    else:
        print(result.stage, result.url, result.attempts, result.error)
```

## ScrapeResult Attributes

## stage

Type: ScrapeStage; Description: PAGE or ITEM

## url

Type: str; Description: The page or item target URL

## page_index

Type: int; Description: Zero-based source-page index

## item_index

Type: int | None; Description: Zero-based item index; None for page failures

## attempts

Type: int; Description: Number of attempts consumed

## item

Type: Video | None; Description: The loaded item on success

## error

Type: ScrapeOperationError | None; Description: The typed terminal error on failure

## succeeded

Type: bool; Description: True when the result contains an item

## unwrap

Type: Video; Description: Returns the item or raises its terminal error

## Related MCP documents

- [Tube8 API getting started](../getting-started.md)
- [IteratorConfig — eaf_base_api](../../eaf-base-api/configuration/iterator-config.md)
- [ScrapeStream and ScrapeResult — eaf_base_api](../../eaf-base-api/reference/scrape-stream-and-result.md)
- [RetryPolicy and custom error handling — eaf_base_api](../../eaf-base-api/guides/retry-and-error-handling.md)
- [Errors and troubleshooting — Tube8 API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
