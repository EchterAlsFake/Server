---
title: "Migration from 3.x — eaf_base_api"
summary: "Documents Migration from 3.x behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Migration from 3.x"
  - "eaf base Migration from 3.x"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Migration from 3.x"
---

# Migration from 3.x — eaf_base_api

Documents Migration from 3.x behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

3.x| 4.0 replacement
---|---
`fetch(url)`| `fetch_text(url)`
`fetch(..., get_bytes=True)`| `fetch_bytes(...)`
`fetch(..., get_response=True)`| `request(...)`
`fetch(..., save_cache=False)`| `fetch_text(..., cache_policy=CachePolicy.BYPASS)`
`max_cache_items`| `response_cache_size_bytes` \+ `segment_cache_size_bytes`
`max_retries`| `request_attempts`
`proxies`| `proxy`
`load(api=True, html=False)`| `load_sources("api")` or `load_fields(...)`
`on_error_hint` returning `bool`| `ErrorHandler` returning `ErrorAction`
`keep_original_order=True`| `IteratorConfig(order=ResultOrder.ORIGINAL)`
`max_video_concurrency`| `IteratorConfig(max_item_concurrency=...)`
`result.is_success`| `result.succeeded`
`result.video`| `result.unwrap()` or checked `result.item`

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
