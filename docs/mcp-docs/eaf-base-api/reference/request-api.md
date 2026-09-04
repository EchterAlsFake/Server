---
title: "Request API — eaf_base_api"
summary: "Documents Request API behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Request API"
  - "eaf base Request API"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Request API"
  - "request"
  - "fetch_text"
  - "fetch_bytes"
---

# Request API — eaf_base_api

Documents Request API behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

Version 4 replaces the flag-driven `fetch()` method with one method per representation:

## request

Returns: curl_cffi.Response; Cache behavior: Never uses the text cache

## fetch_text

Returns: str; Cache behavior: Successful GET text can use the configured cache

## fetch_bytes

Returns: bytes; Cache behavior: Never uses the text cache

```python
from base_api import BaseCore, CachePolicy

async with BaseCore() as core:
    response = await core.request(url)
    text = await core.fetch_text(url)
    data = await core.fetch_bytes(download_url)

    refreshed = await core.fetch_text(
        url,
        cache_policy=CachePolicy.REFRESH,
    )
    uncached = await core.fetch_text(
        url,
        cache_policy=CachePolicy.BYPASS,
    )
```

`CachePolicy.USE` reads and writes, `REFRESH` skips the read and replaces the cached value, and `BYPASS` neither reads nor writes. All three request methods accept timeout, cookies, redirects, data, HTTP method, headers, JSON, parameters, and `retry_non_idempotent`.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
