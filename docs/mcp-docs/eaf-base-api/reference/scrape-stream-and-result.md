---
title: "ScrapeStream and ScrapeResult — eaf_base_api"
summary: "Documents ScrapeStream, scrape_stream, and ScrapeResult behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API ScrapeStream and ScrapeResult"
  - "eaf base ScrapeStream and ScrapeResult"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "ScrapeStream and ScrapeResult"
  - "scrape_stream"
  - "ScrapeResult"
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

# ScrapeStream and ScrapeResult — eaf_base_api

Documents `ScrapeStream`, `scrape_stream()`, and `ScrapeResult` behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

## Stream Consumption Approaches

`eaf_base_api` provides two ways to consume scrape streams:

### 1. Direct iteration via `scrape_stream()` (Async Generator)

The `scrape_stream()` helper function returns an `AsyncGenerator[ScrapeResult[T], None]`. Consume it directly with `async for`:

```python
from base_api import scrape_stream

async for result in scrape_stream(
    target_page_urls=page_urls,
    item_extractor=extractor,
    iterator_config=iterator_config,
    core=core,
):
    if not result.succeeded:
        print(f"Failed {result.stage} for {result.url}: {result.error}")
        continue
    media = result.unwrap()  # Returns loaded item or raises result.error
    print(media.title)
```

**Note:** `scrape_stream()` is an async generator, **not** an async context manager. Do not use `async with scrape_stream(...)`.

### 2. Context manager via `Helper.iterator()` (`ScrapeStream`)

`Helper.iterator()` returns a `ScrapeStream` instance that implements an async context manager. Use it when manual control over stream entry and exit is preferred:

```python
stream = helper.iterator(
    target_page_urls=page_urls,
    item_extractor=extractor,
    iterator_config=iterator_config,
)

async with stream:
    async for result in stream:
        if not result.succeeded:
            print(result.stage, result.url, result.error)
            continue
        media = result.unwrap()
```

## ScrapeResult Attributes

Every yielded item in a scrape stream is an immutable `ScrapeResult[T]` instance with the following fields:

### stage

Type: `ScrapeStage`; Description: `ScrapeStage.PAGE` or `ScrapeStage.ITEM` indicating which stage produced this result.

### url

Type: `str`; Description: Page URL or item URL associated with this outcome.

### page_index

Type: `int`; Description: Zero-based target-page index.

### item_index

Type: `int | None`; Description: Zero-based item extractor position within the page, or `None` for page-level failures.

### attempts

Type: `int`; Description: Number of stage retry attempts consumed.

### item

Type: `T | None`; Description: Loaded media model on success, otherwise `None`.

### error

Type: `PageFetchError | ItemFetchError | None`; Description: Typed scrape operation exception on yielded failure, otherwise `None`.

### succeeded

Type: `bool`; Description: `True` exactly when the result contains a successfully loaded `item`.

### unwrap()

Description: Returns the loaded `item` if `succeeded` is `True`, or raises the stored `error`.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [IteratorConfig — eaf_base_api](../configuration/iterator-config.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
