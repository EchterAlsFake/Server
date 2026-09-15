---
title: "Changelog — MissAV API"
summary: "Records the versions and documented changes for the MissAV API."
public_url: "https://docs.echteralsfake.me/missav/"
aliases:
  - "MissAV Changelog"
keywords:
  - "MissAV"
  - "Changelog"
  - "b291d71"
  - "dc52215"
---

# Changelog — MissAV API

Records the versions and documented changes for the MissAV API.

## 2.6 — 2026-09-15
- `8c16241` / `6389916` — Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete context (`url`, `class_name`, `api`). Added layout anchor validations to detect page structure changes. Implemented robust fallback selectors for title, thumbnail, publish date, and duration. Enhanced m3u8 playlist URL extraction fallbacks (JS regex, direct regex, surrit regex) and validated base URL presence in download method. Added unit tests for snippet parsing and error scenarios.

## 2.6 — 2026-08-14
- `5cce2e3` / `562b69c` — Updated cross-site request headers and switched the client to the required `safari17_2_ios` impersonation profile to restore access after upstream 403 responses.

## b291d71
- Added the `py.typed` marker for typed consumers and changed unset iterator retry policies to resolve from the live `RuntimeConfig`.
- Updated the package version from 2.4 to 2.5.

## dc52215
- Moved search iteration settings into `IteratorConfig`.
- Preserved MissAV's single-page concurrency and required `html` source loading.

## Core v4 migration — 2026-08-07 `9136b07`
- Migrated to the eaf-base-api 4.x runtime and result model.
- Adopted policy-driven retries, structured scrape errors, and current iterator error handling.

## Related MCP documents

- [MissAV API getting started](getting-started.md)
- [Errors and troubleshooting — MissAV API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/missav/](https://docs.echteralsfake.me/missav/)
