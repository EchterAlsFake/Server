---
title: "Changelog — RedGIFs API"
summary: "Initial local 0.1.0 interface, API/HTML sources, direct transfers and incomplete live-validation evidence."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Changelog — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "version"
  - "0.1.0"
  - "changelog"
---

# Changelog — RedGIFs API

## 0.1.0 — initial local implementation

- Async `Client`, `Video`, `Image`, `User`, `Niche`, `Collection` and immutable `Tag` records.
- Independent API/HTML media loaders, deferred fields, typed relationships and raw metadata.
- Video/image/creator search, full/trending tags, niches and public collections.
- Shared numeric-page result streams with count/range control, source selection and
  caller-controlled ordering/concurrency/error policy.
- Public anonymous API authentication through BaseCore; no mutable global auth/CDN headers.
- Shared RAW MP4/JPG transfers, exact HD/SD/silent labels, best/half/worst selectors,
  source refresh, cancellation, callbacks, filename handling and download/file CLI modes.
- Verified page/CDN hosts and lowercase content identity while preserving source URL casing.
- 23 complete MP4 matrix downloads, two JPG renditions, concurrent/repeated transfers
  and CLI checks; complete collection 246/246 and niche 5/5 in the final run.
- Final live suite on 2026-11-10: **38 passed / 12 failed / 0 skipped** in 363.26 seconds.
  All final failures were HTTP 429. Earlier equal-timestamp profile page comparisons
  had omissions/duplicates, and those assertions remain intact.
- Matching HTML and searchable MCP documentation following the shared documentation layout.

This is an unpublished local version. HLS URLs are inspectable but HLS downloads,
gallery enumeration, private/account actions and personalized recommendation feeds are
not implemented. No claim is made that the full validation gate has passed.
See [getting started](getting-started.md) and [validation](guides/live-validation.md).
