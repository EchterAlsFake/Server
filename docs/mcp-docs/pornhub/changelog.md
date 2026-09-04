---
title: "Changelog — PornHub API"
summary: "Records the versions and documented changes for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Changelog"
keywords:
  - "PornHub"
  - "Changelog"
---

# Changelog — PornHub API

Records the versions and documented changes for the PornHub API.

## 5.4.2 follow-up — 2026-09-01
- `5553a68` / `56578f3` — Removed the wrapper's hard-coded User-Agent and replaced constructor-triggered background login with the awaited `Client.create(..., login=True)` factory.

## 5.4.2 — 2026-08-16
- `50f41e3` / `8cfac95` — Corrected fallback width calculation for HLS variants that provide height without width.

## 5.4.1 — 2026-08-13
- `fe1d38f` — Added the HTML-backed `UserHelper.name` field with selectors for both supported profile layouts.

## 5.4 — 2026-08-11
- `68f6a65` / `b16c2ea` — Sanitized Short, GIF, and Video download titles to prevent path traversal and illegal filenames, then released 5.4.
- `6a5c064` — Added generic `ScrapeStream`/`ScrapeResult` typing and the PEP 561 `py.typed` marker; iterator retry fields remain unset so they resolve from `RuntimeConfig`.

## 5.3.1 fixes — 2026-08-10
- `1acf957` — Made iterator source loading opt-in by default, fixed profile `/videos` URL construction, separated upload/model/playlist extractors for richer structured results and deduplication, tolerated missing playlist descriptions, and corrected count parsing (issues #96, #97, and #98).

## 5.3.1 iterator synchronization — 2026-08-08
- `69bffd6` — Consolidated iterator concurrency, ordering, source loading, retry, and error controls into `IteratorConfig`.

## 5.3.1 v4 migration — 2026-08-07
- `7142475` — Migrated to the eaf_base_api v4 request and scraping model: `fetch_text()`/`request()`, structured exceptions, source-aware media loading, typed scrape streams/results, and bounded retries.

## 5.3.1 — 2026-08-06
- `f93c3eb` — Fixed `Video.author(load_html)`, corrected the CLI entry point, and released the 5.3.1 patch.

## Related MCP documents

- [PornHub API getting started](getting-started.md)
- [Errors and troubleshooting — PornHub API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
