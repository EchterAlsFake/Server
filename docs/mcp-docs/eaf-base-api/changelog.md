---
title: "Changelog — eaf_base_api"
summary: "Records the versions and documented changes for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Changelog"
  - "eaf base Changelog"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Changelog"
---

# Changelog — eaf_base_api

Records the versions and documented changes for the eaf_base_api API.

Date / Version| Changes since 3.3.3
---|---
**2026-08-19 — 4.1.1**|  Synchronized download/remux progress callbacks across worker threads, normalized discontinuous HLS packet timestamps during remuxing, and added regressions for stage-specific error handlers and per-core runtime settings. Commit `a062695`.
**2026-08-16 — 4.1.0**|  Made HLS cancellation stop pending segment work promptly and corrected JSON resume-state serialization, including configured `Path` values. Commit `acdb967`.
**2026-08-14 — 4.0.1**|  Reworked HLS quality discovery/selection for canonical landscape and portrait tiers, inline/callable playlists, and bandwidth fallbacks; fixed independent item error handlers, idempotent session initialization, configured session cookies and retry multipliers, and removed hard-coded transport headers. Commits `2fd3a55`–`1eb9105`.
**2026-08-11 — 4.0.0**|  Added the `py.typed` marker; finalized runtime-resolved `IteratorConfig` values; expanded typed exports; improved page/item exception logging and terminal error context. Commits `13b4105`–`184df57`.
**2026-08-08 — 4.0.0**|  Centralized page/item concurrency, ordering, loading, retry policies, and handlers in `IteratorConfig`; resolved omitted policies from `RuntimeConfig`; expanded inline API documentation. Commits `2705faa`–`baccdfd`.
**2026-08-07 — 4.0.0**|  Breaking v4 redesign: explicit request methods and cache policies; byte-bounded TTL caches and single-flight text fetches; source-aware atomic media loading; bounded dynamic Helper scheduling; immutable `ScrapeResult`; owned `ScrapeStream`; structured retry/error policies. Commits `37176cb`, `7294115`.
**2026-08-07 — 3.3.6**|  Improved legacy iterator ordering and ensured worker cancellation/cleanup when iteration finishes or the consumer exits early. Commits `34286d0`, `76b3023`.
**2026-08-04 — 3.3.5**|  Added local interface binding and corrected proxy initialization to use a single proxy URL. Commit `a3ca95e`.
**2026-07-27 — 3.3.4**|  Hardened output filename sanitization against path traversal and invalid filename components. Commit `eec47e3`.
**2026-07-26 — 3.3.3**|  Baseline requested for this documentation update; licensing changed to AGPL-3.0-or-later. Commit `3ee47f7`.

## Related MCP documents

- [Overview — eaf_base_api](overview.md)
- [Error reference — eaf_base_api](troubleshooting/errors.md)
- [EAF Python API documentation overview](../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
