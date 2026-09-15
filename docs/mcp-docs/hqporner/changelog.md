---
title: "Changelog — HQPorner API"
summary: "Records the versions and documented changes for the HQPorner API."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner Changelog"
keywords:
  - "HQPorner"
  - "Changelog"
---

# Changelog — HQPorner API

Records the versions and documented changes for the HQPorner API.

## 2.5 (current)
- 2026-09-15 · `fccc573` / `4e702e9` — Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete diagnostic context (`url`, `class_name`, `api`). Added layout anchor validations to detect page structure changes. Implemented robust fallback selectors for video metadata and CDN URLs. Enhanced download quality resolution using `PATTERN_RESOLUTION` and validation. Added snippet-based unit tests for HTML extraction and layout checks.
- 2026-08-11 · `a097c19` — Released 2.5, added generic `ScrapeResult[Video]` annotations and the `py.typed` marker, and switched missing iterator policies to live RuntimeConfig-derived defaults.
- 2026-08-08 · `e3055d4` — Centralized every listing method on `IteratorConfig`, preserving required `("html",)` loading and page-failure skipping while removing legacy concurrency/loading/order/callback parameters.
- 2026-08-07 · `eaceacf` — Migrated to `eaf-base-api>=4.0.0`: explicit request methods, source-aware fields/loaders, bounded scheduling, deterministic stream cleanup, structured results/errors, and extractor validation.

## Related MCP documents

- [HQPorner API getting started](getting-started.md)
- [Errors and troubleshooting — HQPorner API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
