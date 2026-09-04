---
title: "Changelog — xHamster API"
summary: "Records the versions and documented changes for the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster Changelog"
keywords:
  - "xHamster"
  - "Changelog"
---

# Changelog — xHamster API

Records the versions and documented changes for the xHamster API.

Date| Commit| Changes
---|---|---
2026-08-24| `c640d89` / `b7c302e`| Adapted listing extraction to the site's new per-video `data-video-id` layout, searched all candidate result containers, deduplicated overlapping results, and mapped listing duration into the current `duration` field.
2026-08-14| `79224f5`| Released 2.6 with expanded `Video` metadata: hash, description, duration/views/comments, timestamps, VR/HD flags, maximum resolution, orientation, and preview thumbnail.
2026-08-11| `d9714c3`| Released 2.5 with complete typing and `py.typed`; repaired selectors and fallbacks; implemented `get_shorts()` on `Pornstar` and `Creator` (not the shared base or Channel); and aligned retry defaults with `RuntimeConfig`.
2026-08-08| `5ce0a28`| Centralized concurrent scraping on `IteratorConfig` and forwarded package source/retry defaults.
2026-08-07| `706fd4f`| Migrated source-aware media, explicit loading, bounded retries, and structured scrape results to eaf v4.

## Related MCP documents

- [xHamster API getting started](getting-started.md)
- [Errors and troubleshooting — xHamster API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
