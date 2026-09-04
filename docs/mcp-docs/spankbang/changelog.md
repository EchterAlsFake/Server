---
title: "Changelog — SpankBang API"
summary: "Records the versions and documented changes for the SpankBang API."
public_url: "https://docs.echteralsfake.me/spankbang/"
aliases:
  - "SpankBang Changelog"
keywords:
  - "SpankBang"
  - "Changelog"
---

# Changelog — SpankBang API

Records the versions and documented changes for the SpankBang API.

## 2.4.1 — 2026-08-14
- `18a8f15` / `5871e80` — Updated request headers and forced HTTP/3 for newly initialized client sessions to restore access after upstream 403 responses.

## 2.3 — 2026-08-11
- `809909a` / `71e71f6` — Added the PEP 561 `py.typed` marker, left iterator retry policies unset so they resolve from `RuntimeConfig`, and removed a temporary local package-source setting from the published configuration.

## 2.3 — 2026-08-08
- `e63c384` — Consolidated profile and search iterator concurrency, ordering, source loading, retry, and error controls into `IteratorConfig`.

## 2.3 migration — 2026-08-07
- `2f1c01d` — Migrated to the eaf_base_api v4 request and scraping model: `fetch_text()`/`request()`, structured exceptions, source-aware media loading, typed scrape streams/results, bounded retries, and field-aware loading before downloads.

## Related MCP documents

- [SpankBang API getting started](getting-started.md)
- [Errors and troubleshooting — SpankBang API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/spankbang/](https://docs.echteralsfake.me/spankbang/)
