---
title: "Changelog — Porntrex API"
summary: "Records the versions and documented changes for the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex Changelog"
keywords:
  - "Porntrex"
  - "Changelog"
  - "d86ccad"
  - "aa51d6b"
  - "d731458"
---

# Changelog — Porntrex API

Records the versions and documented changes for the Porntrex API.

## 1.8 — 2026-09-15
- `541cd29` / `221d32b` — Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete context (`url`, `class_name`, `api`). Added layout anchor validations to detect page structure changes. Implemented robust fallback selectors for video and channel/model metadata. Normalized protocol schemes for download URLs and validated quality availability. Added snippet-based unit tests for channel and video data extraction.

## d86ccad
- Added generic `ScrapeResult[Video]` return annotations and the `py.typed` marker.
- Changed unset iterator retry policies to resolve from the live `RuntimeConfig`.
- Updated the package version from 1.7 to 1.8.

## aa51d6b
- Replaced the legacy per-call iterator arguments with `IteratorConfig`.
- Preserved the required `html` source loading for search, model, and channel results.

## d731458
- Migrated to eaf-base-api 4.x with explicit request methods and source-aware media loading.
- Added bounded retries, structured errors, extractor validation, improved concurrency, and deterministic stream cleanup.
- Removed obsolete compatibility code and adopted the current `ScrapeResult` model.

## Related MCP documents

- [Porntrex API getting started](getting-started.md)
- [Errors and troubleshooting — Porntrex API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
