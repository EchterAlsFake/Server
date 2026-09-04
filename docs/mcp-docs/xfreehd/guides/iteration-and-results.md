---
title: "Iteration and ScrapeResult — XFreeHD API"
summary: "Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the XFreeHD API."
public_url: "https://docs.echteralsfake.me/xfreehd/"
aliases:
  - "XFreeHD Iteration and ScrapeResult"
keywords:
  - "XFreeHD"
  - "Iteration and ScrapeResult"
  - "succeeded"
  - "unwrap"
  - "item"
  - "error"
  - "stage"
---

# Iteration and ScrapeResult — XFreeHD API

Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the XFreeHD API.

Iterating methods like `client.search()` return async generators yielding `ScrapeResult` instances:

```python
async for result in client.search("beach", pages=2):
    if result.succeeded:
        video = result.unwrap()     # The Video object
        print(video.title)
    else:
        print(f"{result.stage} failed: {result.error}")
```

## ScrapeResult Attributes

## succeeded

Type: bool; Description: Whether the scraping task succeeded.

## unwrap

Type: Video; Description: Returns the parsed video, or raises the stored error.

## item

Type: Video | None; Description: The parsed video when successful.

## error

Type: ScrapeOperationError | None; Description: The typed page or item failure.

## stage

Type: ScrapeStage; Description: The iterator stage: PAGE or ITEM .

## Related MCP documents

- [XFreeHD API getting started](../getting-started.md)
- [IteratorConfig — eaf_base_api](../../eaf-base-api/configuration/iterator-config.md)
- [ScrapeStream and ScrapeResult — eaf_base_api](../../eaf-base-api/reference/scrape-stream-and-result.md)
- [RetryPolicy and custom error handling — eaf_base_api](../../eaf-base-api/guides/retry-and-error-handling.md)
- [Errors and troubleshooting — XFreeHD API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xfreehd/](https://docs.echteralsfake.me/xfreehd/)
