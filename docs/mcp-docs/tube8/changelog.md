---
title: "Changelog — Tube8 API"
summary: "Records the versions and documented changes for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 Changelog"
keywords:
  - "Tube8"
  - "Changelog"
---

# Changelog — Tube8 API

Records the versions and documented changes for the Tube8 API.

Date| Commit| Changes
---|---|---
2026-09-15| `b4e8cd3` / `8d881f9`| Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete diagnostic context (`url`, `class_name`, `api`). Added layout anchors and resilient fallback selectors with offline extraction unit tests. Exported `Amateur`, `User`, and `UserHelper` in `__all__`. Adopted centralized `extract_video_grid` from `base_api.modules.static_functions`.
2026-08-11| `d999d7a`| Completed public type hints and added the `py.typed` marker.
2026-08-11| `7e67e0e`| Released 1.3 and corrected search-result URLs that incorrectly targeted `thumbzilla.com` instead of `tube8.com`.
2026-08-08| `aaa2784`| Centralized concurrent scraping on `IteratorConfig` and the package's three-attempt page/item defaults.
2026-08-07| `30618cb`| Migrated source-aware models, explicit loading, bounded retries, and structured results to eaf v4.

## Related MCP documents

- [Tube8 API getting started](getting-started.md)
- [Errors and troubleshooting — Tube8 API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
