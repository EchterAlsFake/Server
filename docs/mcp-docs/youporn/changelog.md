---
title: "Changelog — YouPorn API"
summary: "Records the versions and documented changes for the YouPorn API."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn Changelog"
keywords:
  - "YouPorn"
  - "Changelog"
---

# Changelog — YouPorn API

Records the versions and documented changes for the YouPorn API.

## 1.8.3 — 2026-10-27 (current)
- Fetch search results with default arguments and encode search queries correctly.
- Handle empty listing pages, partial collections and users without public collections safely.
- Resolve absolute collection links without adding a second site prefix.
- Let author, performer and collection helpers work without loading unrelated title or name fields for logging.
- Close CLI sessions reliably and report unsuccessful downloads as errors.

[GitHub release and distribution files](https://github.com/EchterAlsFake/unofficial-api-for-youporn/releases/tag/1.8.3) · [PyPI 1.8.3](https://pypi.org/project/unofficial-api-for-youporn/1.8.3/)

Uses the published `eaf-base-api>=4.2.5` dependency.

Date| Commit| Changes
---|---|---
2026-09-15| `8144589` / `874e7ab` / `f4272be`| Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete diagnostic context. Added `BaseProfile` class for common header attributes (name, avatar, banner, description) across `Channel` and `Pornstar`. Added complete public type-hint coverage across the API.
2026-08-11| `6c2af7f`| Completed additional public type-hint coverage.
2026-08-11| `b7c2cb3`| Released 1.8 with typing improvements and the `py.typed` marker.
2026-08-08| `36a06fe`| Centralized concurrent scraping on `IteratorConfig` and forwarded package source/retry defaults.
2026-08-07| `f163c07`| Migrated source-aware media, explicit loading, bounded retries, and structured scrape results to eaf v4.

## Related MCP documents

- [YouPorn API getting started](getting-started.md)
- [Errors and troubleshooting — YouPorn API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
