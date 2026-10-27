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

## 2.6.5 — 2026-10-27 (current)
- Restore shorts and moments extraction from current page data and DOM layouts.
- Keep profile shorts on the correct listing route and preserve regional URL hosts.
- Read listing metadata from hydrated page data so later cards retain thumbnails and durations.
- Avoid incompatible quality filters for VR search and recognize Full HD and UHD videos correctly.
- Handle missing short metadata safely and add compatible user, video and shorts aliases.
- Route shorts and moments through the CLI.

[GitHub release and distribution files](https://github.com/EchterAlsFake/unofficial-api-for-xhamster/releases/tag/2.6.5) · [PyPI 2.6.5](https://pypi.org/project/unofficial-api-for-xhamster/2.6.5/)

Uses the published `eaf-base-api>=4.2.5` dependency.

Date| Commit| Changes
---|---|---
2026-09-17| `e452f99` / `79f61a7`| Released 2.6.2. Added validation for invalid credential error payloads in xHamster login API JSON responses (`extras.error`), raising `LoginFailed` when authentication fails rather than returning an invalid `Account` instance on HTTP 200 responses.
2026-09-15| `a136ebe` / `8030a56`| Adopted shared request and download error handling with `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete context. Added layout anchor validations to detect page structure changes. Implemented resilient fallback selectors for video and pornstar metadata. Enhanced download stream URL resolution and error handling. Added snippet-based unit tests for video and pornstar extraction.
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
