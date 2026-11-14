---
title: "Changelog \u2014 Porndoe API"
summary: "Porndoe API release history and initial public video catalog capabilities."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Changelog \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "changelog"
---

# Changelog — Porndoe API

## 1.0.1

- Parse video totals, page sizes and profile fields on the German, French,
  Spanish, Italian and Brazilian Portuguese subdomains.
- Include the active final page when discovering all remaining pages.
- Report zero page size for requests beyond the end of a feed.
- Accept whitespace around pasted resource URLs.
- Verify profile feeds against every live video card, including one-video
  profiles and complete multi-page feeds. No saved HTML or network mocks.

## 1.0.0

- Initial asynchronous client, BaseMedia Video/Pornstar/Channel/Category models.
- HTML and player metadata, playable signed MP4 sources and optional HLS sources.
- Search, browse/category/tag URLs, directories, profile videos, related videos
  and cross-profile listings using shared ScrapeResult streams.
- RAW/HLS delegation, quality selection and command line downloader.
- Live site/CDN integration tests run by default, including a complete MP4 download.
- HTML documentation and searchable MCP documentation.

See [getting started](getting-started.md).
