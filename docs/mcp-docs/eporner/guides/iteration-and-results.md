---
title: "Iteration and ScrapeResult — Eporner API"
summary: "Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner Iteration and ScrapeResult"
keywords:
  - "Eporner"
  - "Iteration and ScrapeResult"
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

# Iteration and ScrapeResult — Eporner API

Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the Eporner API.

Concurrently iterated methods yield immutable `ScrapeResult[Video]` values. A result contains exactly one of `item` or `error`:

```python
async for result in client.search_videos("couple", sorting_gay="0", sorting_order="latest", sorting_low_quality="1", per_page=10):
    if result.succeeded:
        video = result.unwrap()     # Returns Video or raises the typed scrape error
        print(video.title)
    else:
        print(f"{result.stage} error for {result.url}: {result.error}")
```

## ScrapeResult Attributes

## url

Type: str; Description: The parsed video target URL

## stage

Type: ScrapeStage; Description: ITEM for media results or PAGE for yielded page failures

## page_index

Type: int; Description: Zero-based target-page index

## item_index

Type: int | None; Description: Extractor position, or None for a page failure

## attempts

Type: int; Description: Number of stage attempts used

## item

Type: Video | None; Description: The parsed Video when successful

## error

Type: ScrapeOperationError | None; Description: The typed page or item failure

## succeeded

Type: bool; Description: True when item is present

## unwrap

Type: Video; Description: Returns the item or raises the stored typed error

## Related MCP documents

- [Eporner API getting started](../getting-started.md)
- [IteratorConfig — eaf_base_api](../../eaf-base-api/configuration/iterator-config.md)
- [ScrapeStream and ScrapeResult — eaf_base_api](../../eaf-base-api/reference/scrape-stream-and-result.md)
- [RetryPolicy and custom error handling — eaf_base_api](../../eaf-base-api/guides/retry-and-error-handling.md)
- [Errors and troubleshooting — Eporner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
