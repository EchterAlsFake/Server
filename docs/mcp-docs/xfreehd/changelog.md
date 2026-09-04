---
title: "Changelog — XFreeHD API"
summary: "Records the versions and documented changes for the XFreeHD API."
public_url: "https://docs.echteralsfake.me/xfreehd/"
aliases:
  - "XFreeHD Changelog"
keywords:
  - "XFreeHD"
  - "Changelog"
  - "d41c536"
  - "bf40a03"
---

# Changelog — XFreeHD API

Records the versions and documented changes for the XFreeHD API.

## 1.7.1 — 2026-08-14 `264b618`
- Added `Video.video_qualities()` for consumers that need numeric quality tiers for the current one- or two-CDN layouts.

## d41c536
- Added the `py.typed` marker and changed unset iterator retry policies to resolve from the live `RuntimeConfig`.
- Updated the package version from 1.6 to 1.7.

## IteratorConfig synchronization — 2026-08-08 `5f55f07`
- Replaced the legacy per-call iterator arguments with `IteratorConfig`.
- Preserved the required `html` source loading for search results.

## bf40a03
- Migrated to eaf-base-api 4.x with explicit request methods and source-aware media loading.
- Added bounded retries, structured errors, extractor validation, improved concurrency, and deterministic stream cleanup.
- Removed obsolete compatibility code and adopted the current `ScrapeResult` model.

## Related MCP documents

- [XFreeHD API getting started](getting-started.md)
- [Errors and troubleshooting — XFreeHD API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xfreehd/](https://docs.echteralsfake.me/xfreehd/)
