---
title: "Changelog — Tube8 API"
summary: "Records the versions and documented changes for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 Changelog"
keywords:
  - "Tube8"
  - "Changelog"
---

# Changelog — Tube8 API

Records the versions and documented changes for the Tube8 API.

## 1.3.3 — 2026-10-27 (current)
- Stop mistaking subscriber totals for video counts, including on French channel pages.
- Reject empty User pages instead of accepting generic session metadata as a profile identity.
- Encode search queries correctly and preserve their literal special characters.
- Close CLI sessions and report failed downloads accurately.
- A working public User feed remains unverified; ordinary video, channel, pornstar and amateur routes were tested live.

[GitHub release and distribution files](https://github.com/EchterAlsFake/unofficial-api-for-tube8/releases/tag/1.3.3) · [PyPI 1.3.3](https://pypi.org/project/unofficial-api-for-tube8/1.3.3/)

Uses the published `eaf-base-api>=4.2.5` dependency.

Date| Commit| Changes
---|---|---
2026-09-15| `b4e8cd3` / `8d881f9`| Adopted shared request and download error handling from `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete diagnostic context. Exported `Amateur`, `User`, and `UserHelper` in `__all__`. Adopted centralized `extract_video_grid` from `base_api.modules.static_functions`. Added layout anchors and resilient fallback selectors for video, channel, amateur, and pornstar pages with offline unit tests.
2026-08-11| `d999d7a`| Completed public type hints and added the `py.typed` marker.
2026-08-11| `7e67e0e`| Released 1.3 and corrected search-result URLs that incorrectly targeted `thumbzilla.com` instead of `tube8.com`.
2026-08-08| `aaa2784`| Centralized concurrent scraping on `IteratorConfig` and the package's three-attempt page/item defaults.
2026-08-07| `30618cb`| Migrated source-aware models, explicit loading, bounded retries, and structured results to eaf v4.

## Related MCP documents

- [Tube8 API getting started](getting-started.md)
- [Errors and troubleshooting — Tube8 API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
