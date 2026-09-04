---
title: "Iteration and ScrapeResult — Porntrex API"
summary: "Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex Iteration and ScrapeResult"
keywords:
  - "Porntrex"
  - "Iteration and ScrapeResult"
  - "succeeded"
  - "unwrap"
  - "item"
  - "error"
  - "stage"
---

# Iteration and ScrapeResult — Porntrex API

Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the Porntrex API.

Iterators like `client.search()` and `model.videos()` return async generators that yield `ScrapeResult` containers:

```python
async for result in client.search("college", pages=3):
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

- [Porntrex API getting started](../getting-started.md)
- [IteratorConfig — eaf_base_api](../../eaf-base-api/configuration/iterator-config.md)
- [ScrapeStream and ScrapeResult — eaf_base_api](../../eaf-base-api/reference/scrape-stream-and-result.md)
- [RetryPolicy and custom error handling — eaf_base_api](../../eaf-base-api/guides/retry-and-error-handling.md)
- [Errors and troubleshooting — Porntrex API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
