---
title: "Changelog — Eporner API"
summary: "Records the versions and documented changes for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner Changelog"
keywords:
  - "Eporner"
  - "Changelog"
---

# Changelog — Eporner API

Records the versions and documented changes for the Eporner API.

## 2.4.1 (current)
- 2026-09-15 · `3ee78ee` / `6b80518` / `f9fd944` / `01429e8` — Updated dependency to `eaf-base-api>=4.2.0` and adopted centralized request/download error handling. Failed downloads now raise `DownloadFailed` with complete context (`url`, `class_name`, `api`). Added `BaseProfile`, `Pornstar`, and `Channel` classes with profile video scraping via `videos()`. Added `Client.get_channel()`. Expanded `Video` metadata (dual API/HTML source loading for title, views, embed URL, and thumbnails; `length_seconds` integer type; clean `ResourceGone` exception when videos are deleted or removed).
- 2026-08-14 · `7f1bbac` — Added HTML-backed `tags`, `categories`, and `uploader` fields; renamed `get_available_qualities()` to `video_qualities()`; and made optional pornstar biography fields tolerant of missing page elements.
- 2026-08-11 · `c8f2974` — Added typed `ScrapeResult[Video]` annotations and `py.typed`; fixed the Eporner v2 API URL/list response handling and treated package `NotFound` as a terminal resource error. Default iterator error handling now uses the structured `ScrapeErrorContext`/`ErrorAction` handler.
- 2026-08-08 · `f862f1c` — Replaced all per-method concurrency, loading, ordering, retry, and callback arguments with `IteratorConfig` while preserving eager `("api", "html")` loading.
- 2026-08-07 · `e3c682a` — Migrated to `eaf-base-api>=4.0.0`: explicit request methods, source-aware media loaders, bounded scheduling, deterministic stream cleanup, structured scrape results, and validated extractors.

## Related MCP documents

- [Eporner API getting started](getting-started.md)
- [Errors and troubleshooting — Eporner API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
