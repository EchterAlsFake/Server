---
title: "Changelog — Thumbzilla API"
summary: "Records the versions and documented changes for the Thumbzilla API."
public_url: "https://docs.echteralsfake.me/thumbzilla/"
aliases:
  - "Thumbzilla Changelog"
keywords:
  - "Thumbzilla"
  - "Changelog"
---

# Changelog — Thumbzilla API

Records the versions and documented changes for the Thumbzilla API.

Date| Commit| Changes
---|---|---
2026-09-15| `d39ab9e` / `6d20c49`| Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete diagnostic context (`url`, `class_name`, `api`). Adopted centralized `extract_video_grid` from `base_api.modules.static_functions`. Added layout anchors and resilient fallback selectors for video, channel, and pornstar pages with offline extraction unit tests.
2026-08-11| `0d65160`| Released 1.4 with complete type hints and the `py.typed` marker.
2026-08-08| `b495027`| Centralized iterator behavior on `IteratorConfig`, forwarded source/retry defaults, and aligned download-test behavior.
2026-08-08| `e91bdf3`| Synchronized the package with the local eaf v4 source and released 1.3.
2026-08-07| `b2c7678`| Migrated models, explicit source loading, structured retries, and iterator results to eaf v4.

## Related MCP documents

- [Thumbzilla API getting started](getting-started.md)
- [Errors and troubleshooting — Thumbzilla API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/thumbzilla/](https://docs.echteralsfake.me/thumbzilla/)
