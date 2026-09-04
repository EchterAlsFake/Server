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
