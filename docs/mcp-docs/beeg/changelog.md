---
title: "Changelog — Beeg API"
summary: "Records the versions and documented changes for the Beeg API."
public_url: "https://docs.echteralsfake.me/beeg/"
aliases:
  - "Beeg Changelog"
keywords:
  - "Beeg"
  - "Changelog"
---

# Changelog — Beeg API

Records the versions and documented changes for the Beeg API.

## 1.7.4 — 2026-10-27 (current)
- Accept video IDs, links without a scheme, and video links copied from tag pages without losing the video key.
- Expose author, tags, thumbnails and publication dates from the API response.
- Report missing or malformed metadata as NotFound instead of failing with an indexing error.
- Handle missing batch files and output directories more gracefully in the CLI.

[GitHub release and distribution files](https://github.com/EchterAlsFake/unofficial-api-for-beeg/releases/tag/1.7.4) · [PyPI 1.7.4](https://pypi.org/project/unofficial-api-for-beeg/1.7.4/)

Uses the published `eaf-base-api>=4.2.5` dependency.

## 1.7 — September 15, 2026
- `6bd391b` / `c5a4549` / `05837ac` — Adopted shared request and download error handling from `base_api.modules.provider` (requiring `eaf-base-api>=4.2.0`). Failed downloads now raise `DownloadFailed` with complete context. Added CLI support with automatic console logging, exception chaining, and contextual logging.

## 1.7 — August 11, 2026
- `9eb18ac` — Added complete public type hints and the `py.typed` marker, updated package metadata for 1.7, and reverted the temporary exact-suffix ID parsing change. The current implementation again uses `strip("-0")`.

## Changes during August 7–10, 2026
- `3f3f68d` (August 7) — Migrated to `eaf_base_api 4`: explicit request methods, source-aware `media_field("api")` loaders, strict loader results, and removal of the v3 compatibility code.
- `2c0a098` (August 9) — Temporarily changed Beeg ID parsing to remove only the exact `"-0"` suffix.
- `41d4443` (August 10) — Merged that temporary ID parsing change; it was subsequently reverted by `9eb18ac`.

## Related MCP documents

- [Beeg API getting started](getting-started.md)
- [Errors and troubleshooting — Beeg API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/beeg/](https://docs.echteralsfake.me/beeg/)
