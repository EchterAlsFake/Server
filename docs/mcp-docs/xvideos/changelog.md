---
title: "Changelog — XVideos API"
summary: "Records the versions and documented changes for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Changelog"
keywords:
  - "XVideos"
  - "Changelog"
---

# Changelog — XVideos API

Records the versions and documented changes for the XVideos API.

## 2.5.3 — 2026-10-27 (current)
- Fix default search pagination and avoid double-encoding spaces in search terms.
- Return real thumbnails and clean titles from listings, and skip profile cards that are not videos.
- Decode HTML entities in profile JSON results.
- Support both property-style and method-style author and performer helpers.
- Bound collaborator loading so a missing profile does not abort the whole result.
- Handle empty channels and model URL aliases, and export Channel and Account.

[GitHub release and distribution files](https://github.com/EchterAlsFake/unofficial-api-for-xvideos/releases/tag/2.5.3) · [PyPI 2.5.3](https://pypi.org/project/unofficial-api-for-xvideos/2.5.3/)

Uses the published `eaf-base-api>=4.2.5` dependency.

## 2.5 — 2026-09-15
- `23dec61` / `bb96133` / `d03b382` — Adopted shared request and download error handling from `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete diagnostic context. Modernized HTML scraping for `Video`, `Channel`, and `Pornstar` classes with layout anchors and resilient fallback selectors (JSON-LD, setVideoTitle, setThumbUrl, setVideoHLS, data-id, model links). Added comprehensive unit test suites for channel, pornstar, and video extraction.

## 2.5 — 2026-08-11
- `c1e34b3` / `f8ebcb3` — Added generic `ScrapeResult[Video]` typing and the PEP 561 `py.typed` marker, left iterator retry policies unset so they resolve from `RuntimeConfig`, and released 2.5.

## 2.4 — 2026-08-08
- `9a88d09` — Consolidated account, profile, search, and playlist iterator concurrency, ordering, source loading, retry, and error controls into `IteratorConfig`; authenticated account listings use their required `POST` transport internally.

## 2.4 migration — 2026-08-07
- `e39c5ec` — Migrated to the eaf_base_api v4 request and scraping model: `fetch_text()`/`request()`, structured exceptions, source-aware media loading, typed scrape streams/results, and bounded retries.

## Related MCP documents

- [XVideos API getting started](getting-started.md)
- [Errors and troubleshooting — XVideos API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
