---
title: "Changelog — TNAFlix API"
summary: "Records the versions and documented changes for the TNAFlix API."
public_url: "https://docs.echteralsfake.me/tnaflix/"
aliases:
  - "TNAFlix Changelog"
keywords:
  - "TNAFlix"
  - "Changelog"
---

# Changelog — TNAFlix API

Records the versions and documented changes for the TNAFlix API.

## 1.0.1 — 2026-10-27 (current)
- Follow canonical watch links when short or embedded pages omit metadata and related videos.
- Normalize video, profile, channel and pornstar links and return the correct media types.
- Expose callable author and performer helpers and keep channel authors out of tags and categories.
- Parse abbreviated rating counts and source URLs when optional size attributes are absent.
- Export Sort and SortDate and send date sorting through the website query parameter.
- Include the HTML fixtures used by the parser regression tests.

[GitHub release and distribution files](https://github.com/EchterAlsFake/unofficial-api-for-tnaflix/releases/tag/1.0.1) · [PyPI 1.0.1](https://pypi.org/project/unofficial-api-for-tnaflix/1.0.1/)

Uses the published `eaf-base-api>=4.2.5` dependency.

## 1.0 — 2026-10-17
- Initial production release of the unofficial TNAFlix asynchronous Python API wrapper.
- Full extraction of Video metadata from HTML5 Plyr configurations, JSON-LD schemas, and video listing cards.
- Direct progressive MP4 stream extraction and multi-threaded range downloading via `DownloadConfigRAW`.
- Channel scraper implementation supporting official studio / publisher channel metadata and video streaming.
- Profile and Pornstar scraper implementations supporting member statistics and video listing streaming.
- Search engine integration with `Sort` and `SortDate` filters.
- Complete CLI tool supporting direct and batch URL downloads.
- Full compatibility with `eaf-base-api>=4.2.2` networking engine.

## Related MCP documents

- [TNAFlix API getting started](getting-started.md)
- [Errors and troubleshooting — TNAFlix API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tnaflix/](https://docs.echteralsfake.me/tnaflix/)
