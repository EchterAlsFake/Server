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

## 2.5.2 — 2026-10-27 (current)
- Fetch distinct listing pages and handle the all-time sorting option correctly.
- Return an empty search when the site shows recommendations below its no-results message.
- Accept canonical, www and mobile actress links, and correct the mobile 404 fallback.
- Limit category results to actual category cards and resolve listing and image links correctly.
- Extract CDN download links from both ordinary anchors and JavaScript HTML strings.
- Reject zero page or concurrency limits and report CLI batch failures accurately.

[GitHub release and distribution files](https://github.com/EchterAlsFake/unofficial-api-for-hqporner/releases/tag/2.5.2) · [PyPI 2.5.2](https://pypi.org/project/unofficial-api-for-hqporner/2.5.2/)

Uses the published `eaf-base-api>=4.2.5` dependency.

## 2.5
- 2026-09-15 · `fccc573` / `4e702e9` — Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete diagnostic context. Added layout anchor validations to detect page structure changes. Implemented robust fallback selectors for video metadata and CDN URLs. Enhanced download quality resolution using `PATTERN_RESOLUTION` and validation. Added snippet-based unit tests for HTML extraction and layout checks.
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
