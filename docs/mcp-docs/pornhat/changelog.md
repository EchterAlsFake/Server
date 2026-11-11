---
title: "Changelog — Pornhat API"
summary: "Initial local 0.1.0 implementation, typed catalog objects, lazy sources, HLS downloads and recorded live verification."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Changelog — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "changelog"
---

# Changelog — Pornhat API

## 0.1.0 — initial local implementation

- Async `Client`, `Video`, `Model`, `Channel`, `Category`, and paysite/brand `Site` objects.
- Explicit HTML metadata loading and dependent public media resolution through BaseCore.
- Video/relationship metadata, tag collections, search, new/popular/trending feeds and
  sortable model/channel directories with original-order ScrapeResult streams.
- Numbered pagination, complete pages="all" profile listings, known empty collections
  and one-based page ranges.
- Verified `.com`, `.one`, and de/fr/it/es/pt/hi host variants.
- Shared HLS downloads, source refresh, callbacks, reports, FFmpeg metadata/remuxing and CLI.
- Full live verification on 2026-11-09: 58 passed, 0 failed, 0 skipped in 94.99 seconds,
  including 20 complete media downloads and complete model/channel reconciliation.
- The final run used four download workers. An earlier 20-worker HTTP/2 repeat stalled;
  this remains documented rather than hidden by the successful bounded run.
- HTML documentation and searchable MCP reference pages following the existing API corpus.

This version is a local checkout; package publication and remote CI badge status are not
asserted. Exact-multiple profile totals, additional quality sets, other platforms, accounts,
playlists and player-only recommendation controls remain unverified or unimplemented.

See [getting started](getting-started.md) and [download evidence](guides/downloading.md).
