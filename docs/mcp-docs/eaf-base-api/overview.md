---
title: "Overview — eaf_base_api"
summary: "Documents Overview behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Overview"
  - "eaf base Overview"
keywords:
  - "eaf_base_api"
  - "base_api"
---

# Overview — eaf_base_api

Documents Overview behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

**Version 4 is intentionally breaking**
The legacy multi-mode `BaseCore.fetch()`, `BaseMedia.load(api=..., html=...)`, mutable `ScrapeResult.video`/`is_success` contract, and boolean retry callbacks were removed. Use the explicit request, media, iterator, and download interface references in this corpus.

`eaf_base_api` is the shared engine used by all site-specific API packages. Version 4 separates each responsibility into an explicit, typed interface:
- **BaseCore** — HTTP sessions, request retries, response decoding, caching, proxy/interface binding, HLS inspection, and downloads
- **BaseMedia + media_field** — source-aware, atomic lazy loading with deterministic source precedence
- **Helper + IteratorConfig** — bounded page/item scheduling, ordering, retries, error handlers, and load selection
- **ScrapeStream + ScrapeResult** — deterministic stream cleanup and immutable success/failure results
- **CacheBackend** — replaceable storage contract; the built-in cache uses byte limits and TTL expiry

## Related MCP documents

- [Error reference — eaf_base_api](troubleshooting/errors.md)
- [EAF Python API documentation overview](../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
