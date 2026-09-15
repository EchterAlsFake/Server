---
title: "Changelog — Redtube API"
summary: "Records the versions and documented changes for the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube Changelog"
keywords:
  - "Redtube"
  - "Changelog"
---

# Changelog — Redtube API

Records the versions and documented changes for the Redtube API.

## 1.4.1 — 2026-09-15
- `105ca53` / `7751b3b` — Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete context (`url`, `class_name`, `api`). Added layout anchor checks across Video, Channel, Playlist, and Pornstar parsers. Implemented resilient fallback selectors for titles, stats, avatars, banners, and media definitions. Improved download stream resolution and added unit tests for video, channel, playlist, and pornstar HTML snippet extractions.

## 1.4.1 — 2026-08-14
- `647f2db` — Added the HTML-backed `Video.publish_date` field.

## 1.4 — 2026-08-11
- `8fcf5ec` — Added generic `ScrapeResult` typing and the PEP 561 `py.typed` marker, left iterator retry policies unset so they resolve from `RuntimeConfig`, and released 1.4.

## 1.3 — 2026-08-08
- `eb45470` — Consolidated playlist, user, channel, and search iterator concurrency, ordering, source loading, retry, and error controls into `IteratorConfig`.

## 1.3 migration — 2026-08-07
- `46fc0fd` — Migrated to the eaf_base_api v4 request and scraping model: `fetch_text()`/`request()`, structured exceptions, source-aware media loading, typed scrape streams/results, and bounded retries.

## Related MCP documents

- [Redtube API getting started](getting-started.md)
- [Errors and troubleshooting — Redtube API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
