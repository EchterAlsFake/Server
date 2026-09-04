---
title: "Caching — eaf_base_api"
summary: "Documents Caching behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Caching"
  - "eaf base Caching"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Caching"
---

# Caching — eaf_base_api

Documents Caching behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

The built-in `Cache` uses separate, thread-safe TTL caches for text responses and HLS segment lists. Limits are measured in UTF-8 bytes, not item counts. Request keys include method, URL, redirects, parameters, body, headers, and cookies; sensitive values are fingerprinted rather than stored in plaintext keys.
- Only successful GET text responses are stored.
- Concurrent cache misses for the same request share one in-flight network operation.
- `core.cache.clear()` clears both built-in caches.
- Pass a custom `CacheBackend` to `BaseCore(cache=...)` to replace storage.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
