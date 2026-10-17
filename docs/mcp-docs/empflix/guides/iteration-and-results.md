---
title: "Iteration and ScrapeResult — EMPFlix API"
summary: "Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the EMPFlix API."
public_url: "https://docs.echteralsfake.me/empflix/"
aliases:
  - "EMPFlix Iteration and ScrapeResult"
keywords:
  - "EMPFlix"
  - "Iteration and ScrapeResult"
  - "succeeded"
  - "unwrap"
  - "item"
  - "error"
  - "stage"
---

# Iteration and ScrapeResult — EMPFlix API

Documents Iteration and ScrapeResult behavior, signatures, fields, constraints, and examples for the EMPFlix API.

Iterators yield `ScrapeResult` containers encapsulating item success or typed error details:

```python
async for result in client.search("college", pages=2):
    if result.succeeded:
        video = result.unwrap()
        print(f"Found: {video.title}")
    else:
        print(f"Stage {result.stage} error: {result.error}")
```

## ScrapeResult Attributes

## succeeded

Type: bool; Description: Whether the scraping task succeeded

## unwrap

Type: Video; Description: Returns the parsed item or raises the underlying exception

## item

Type: Video | None; Description: Parsed video object on success

## error

Type: ScrapeOperationError | None; Description: Typed failure when unsuccessful

## stage

Type: ScrapeStage; Description: Stage where execution occurred: PAGE or ITEM

## Related MCP documents

- [EMPFlix API getting started](../getting-started.md)
- [IteratorConfig — eaf_base_api](../../eaf-base-api/configuration/iterator-config.md)
- [ScrapeStream and ScrapeResult — eaf_base_api](../../eaf-base-api/reference/scrape-stream-and-result.md)
- [RetryPolicy and custom error handling — eaf_base_api](../../eaf-base-api/guides/retry-and-error-handling.md)
- [Errors and troubleshooting — EMPFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/empflix/](https://docs.echteralsfake.me/empflix/)
