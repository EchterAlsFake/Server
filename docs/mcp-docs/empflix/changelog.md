---
title: "Changelog — EMPFlix API"
summary: "Records the versions and documented changes for the EMPFlix API."
public_url: "https://docs.echteralsfake.me/empflix/"
aliases:
  - "EMPFlix Changelog"
keywords:
  - "EMPFlix"
  - "Changelog"
---

# Changelog — EMPFlix API

Records the versions and documented changes for the EMPFlix API.

## 1.0.1 — 2026-10-27 (current)
- Resolve short and embedded video links to the full watch page so metadata and related videos are available.
- Return the correct profile, channel and pornstar types when resolving author links.
- Keep channel authors out of categories and tags, and parse abbreviated rating counts safely.
- Expose Sort and SortDate and support normal get_author() and get_pornstars() calls.
- Include the HTML fixtures used by the parser regression tests.

[GitHub release and distribution files](https://github.com/EchterAlsFake/unofficial-api-for-empflix/releases/tag/1.0.1) · [PyPI 1.0.1](https://pypi.org/project/unofficial-api-for-empflix/1.0.1/)

Uses the published `eaf-base-api>=4.2.5` dependency.

## 1.0 — 2026-10-17
- Initial production release of the unofficial EMPFlix asynchronous Python API wrapper.
- Full extraction of Video metadata from HTML5 Plyr configurations, JSON-LD schemas, and video listing cards.
- Direct progressive MP4 stream extraction and multi-threaded range downloading via `DownloadConfigRAW`.
- Profile and Pornstar scraper implementations supporting member statistics and video listing streaming.
- Search engine integration with `Sort` and `SortDate` filters.
- Complete CLI tool supporting direct and batch URL downloads.
- Full compatibility with `eaf-base-api>=4.2.2` networking engine.

## Related MCP documents

- [EMPFlix API getting started](getting-started.md)
- [Errors and troubleshooting — EMPFlix API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/empflix/](https://docs.echteralsfake.me/empflix/)
