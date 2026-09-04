---
title: "Pagination, iteration, and ScrapeResult — HQPorner API"
summary: "Documents Pagination, iteration, and ScrapeResult behavior, signatures, fields, constraints, and examples for the HQPorner API."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner Pagination, iteration, and ScrapeResult"
keywords:
  - "HQPorner"
  - "Pagination, iteration, and ScrapeResult"
  - "ScrapeResult"
  - "url"
  - "stage"
  - "page_index"
  - "item_index"
  - "attempts"
  - "item"
  - "error"
  - "succeeded"
  - "unwrap"
---

# Pagination, iteration, and ScrapeResult — HQPorner API

Documents Pagination, iteration, and ScrapeResult behavior, signatures, fields, constraints, and examples for the HQPorner API.

Methods like `search_videos()`, `get_videos_by_actress()`, and `get_videos_by_category()` return async generators yielding immutable `ScrapeResult[Video]` instances:

```python
async for result in client.search_videos("college", pages=2):
    if result.succeeded:
        video = result.unwrap()
        print(video.title)
    else:
        print(f"{result.stage} failed for {result.url}: {result.error}")
```

## ScrapeResult

## url

Type: str; Description: The video URL

## stage

Type: ScrapeStage; Description: ITEM for media results or PAGE for yielded page failures

## page_index

Type: int; Description: Zero-based page index

## item_index

Type: int | None; Description: Extractor position, or None for a page failure

## attempts

Type: int; Description: Number of stage attempts used

## item

Type: Video | None; Description: The populated Video when successful

## error

Type: ScrapeOperationError | None; Description: The typed page or item failure

## succeeded

Type: bool; Description: True when item is present

## unwrap

Type: Video; Description: Returns the item or raises the stored typed error

## IteratorConfig Parameters

All iterator methods accept a single `iterator_config`. The most commonly customized fields are:
- max_item_concurrency int | None — Concurrent Video work; `None` resolves from `RuntimeConfig.videos_concurrency`.
- max_page_concurrency int | None — Concurrent page work; `None` resolves from `RuntimeConfig.pages_concurrency`.
- load_specific_sources Iterable[str] — Keep `("html",)` to preserve HQPorner's populated Video results.
- order ResultOrder | str — Completion order by default; use `ResultOrder.ORIGINAL` for page/extractor order.
- page_retry / item_retry RetryPolicy | None — Bounded stage policies; `None` resolves from RuntimeConfig.
- page_error_handler / item_error_handler ErrorHandler | None — Structured handlers receiving `ScrapeErrorContext` and returning `ErrorAction`.

## Related MCP documents

- [HQPorner API getting started](../getting-started.md)
- [IteratorConfig — eaf_base_api](../../eaf-base-api/configuration/iterator-config.md)
- [ScrapeStream and ScrapeResult — eaf_base_api](../../eaf-base-api/reference/scrape-stream-and-result.md)
- [RetryPolicy and custom error handling — eaf_base_api](../../eaf-base-api/guides/retry-and-error-handling.md)
- [Errors and troubleshooting — HQPorner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
