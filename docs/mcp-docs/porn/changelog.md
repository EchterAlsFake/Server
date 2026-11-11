---
title: "Changelog — Porn.com API"
summary: "Version 0.1.0 initial Porn.com implementation: lazy HTML objects, verified hosts, real pagination and HLS downloads with recorded live evidence."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Changelog — Porn.com API", "Changelog Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "changelog", "0.1.0", "release"]
---

# Changelog — Porn.com API

## 0.1.0

- Initial async Client and typed `Video`, `Rendition`, `Collection`, `Pornstar`,
  `Channel`, `Category`, `Source`, and `Filters` interfaces.
- Eager/deferred HTML metadata through the shared source-aware BaseMedia model;
  listing summaries preserve real provenance without loading every scene.
- Scene identity checks, native HLS metadata, referral availability, performer
  and category relationships, biographies, localized profile information.
- Filtered search, category/source listings, directories, and orientation routes.
- Verified twelve-host allowlist; input locale and content identity are retained.
- Numeric pagination continues beyond premature disabled Next links, preserves
  real duplicate occurrences, excludes ads, and detects repeated pages.
- Shared-backend HLS downloading, quality selection, signed-source refresh,
  caller-configuration isolation, optional remux/export metadata, and CLI.
- Recorded 48 passing live cases, 15 complete files, and full small/multipage
  performer/channel comparisons during implementation on 2026-11-10.
- Matching HTML and focused searchable MCP documentation added for the provider.

The package is still a local unpublished checkout. See
[getting started](getting-started.md) and [live validation](guides/live-validation.md).
