---
title: "Changelog — XNXX API"
summary: "Records the versions and documented changes for the XNXX API."
public_url: "https://docs.echteralsfake.me/xnxx/"
aliases:
  - "XNXX Changelog"
keywords:
  - "XNXX"
  - "Changelog"
---

# Changelog — XNXX API

Records the versions and documented changes for the XNXX API.

## 2.4.1 — 2026-08-14
- `af53c16` — Added HTML-backed `Video.author` and `Video.tags` fields.

## 2.4 — 2026-08-11
- `1d57554` — Prefixed search-result links with `https://xnxx.com`, added generic `ScrapeResult[Video]` typing and the PEP 561 `py.typed` marker, left iterator retry policies unset so they resolve from `RuntimeConfig`, and released 2.4.

## 2.3 — 2026-08-08
- `45c4e90` — Consolidated `User.videos()` and `Client.search_videos()` pagination, concurrency, source loading, retry, ordering, and error controls into `IteratorConfig`.

## 2.3 migration — 2026-08-07
- `0bf61e5` — Migrated to the eaf_base_api v4 request and scraping model: `fetch_text()`/`request()`, structured exceptions, source-aware media loading, typed scrape streams/results, and bounded retries.

## Related MCP documents

- [XNXX API getting started](getting-started.md)
- [Errors and troubleshooting — XNXX API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xnxx/](https://docs.echteralsfake.me/xnxx/)
