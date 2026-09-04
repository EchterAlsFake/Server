---
title: "ScrapeStream and ScrapeResult — eaf_base_api"
summary: "Documents ScrapeStream and ScrapeResult behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API ScrapeStream and ScrapeResult"
  - "eaf base ScrapeStream and ScrapeResult"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "ScrapeStream and ScrapeResult"
  - "ScrapeResult"
  - "stage"
  - "url"
  - "attempts"
  - "item"
  - "error"
  - "succeeded"
  - "unwrap"
---

# ScrapeStream and ScrapeResult — eaf_base_api

Documents ScrapeStream and ScrapeResult behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

## ScrapeResult

`ScrapeResult` uses the shared behavior documented in this reference.

`Helper.iterator()` returns a lazily started `ScrapeStream`. Exhausting it cleans up normally; use it as an async context manager whenever the consumer may stop early.

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
        media = result.unwrap()  # Same object as result.item after the check
```

## stage

Description: ScrapeStage.PAGE or ScrapeStage.ITEM

## url

Description: Page or item URL associated with this outcome

## attempts

Description: Number of attempts consumed

## item

Description: Loaded media on success, otherwise None

## error

Description: Typed PageFetchError / ItemFetchError on yielded failure

## succeeded

Description: True exactly when the result contains an item

## unwrap

Description: Return the item or raise the stored typed scrape error

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
