---
title: "IteratorConfig — eaf_base_api"
summary: "Documents IteratorConfig behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API IteratorConfig"
  - "eaf base IteratorConfig"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "IteratorConfig"
  - "max_page_concurrency"
  - "max_item_concurrency"
  - "max_pending_items"
  - "extract_in_thread"
  - "order"
  - "page_error_mode"
  - "item_error_mode"
  - "page_retry"
  - "item_retry"
  - "page_error_handler"
  - "item_error_handler"
  - "load_specific_fields"
  - "load_specific_sources"
---

# IteratorConfig — eaf_base_api

Documents IteratorConfig behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

Site-specific iterator methods now accept one `IteratorConfig` instead of many concurrency, ordering, loading, and callback parameters. Values left as `None` are resolved from the active core's `RuntimeConfig`.

## max_page_concurrency

Default: RuntimeConfig.pages_concurrency; Description: Concurrent page operations

## max_item_concurrency

Default: RuntimeConfig.videos_concurrency; Description: Concurrent media-item operations

## max_pending_items

Default: 4 × item concurrency; Description: Backpressure limit for extracted items awaiting work

## extract_in_thread

Default: True; Description: Run the synchronous extractor and its iteration in a worker thread

## order

Default: ResultOrder.COMPLETION; Description: Yield fastest results first or restore original page/item order

## page_error_mode

Default: ErrorMode.YIELD; Description: Terminal page failure behavior

## item_error_mode

Default: ErrorMode.YIELD; Description: Terminal item failure behavior

## page_retry

Default: derived from RuntimeConfig; Description: Bounded retry policy for a complete page operation

## item_retry

Default: derived from RuntimeConfig; Description: Bounded retry policy for construction/loading of one item

## page_error_handler

Default: None; Description: Optional sync/async handler receiving ScrapeErrorContext

## item_error_handler

Default: None; Description: Optional sync/async handler receiving ScrapeErrorContext

## load_specific_fields

Default: (); Description: Fields each constructed media item must load

## load_specific_sources

Default: (); Description: Sources each constructed media item must load before fields

**Preserve package loading defaults**
Passing a custom `IteratorConfig` replaces that API method's default config. Include the method's required `load_specific_sources` or `load_specific_fields`; most site packages use `("html",)`, while some dual-source APIs use both `"api"` and `"html"`.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
