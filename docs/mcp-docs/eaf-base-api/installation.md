---
title: "Installation — eaf_base_api"
summary: "Explains how to install the eaf_base_api shared base package and its optional download dependency."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Installation"
  - "eaf base Installation"
keywords:
  - "eaf_base_api"
  - "base_api"
---

# Installation — eaf_base_api

Explains how to install the eaf_base_api shared base package and its optional download dependency.

```shell
pip install eaf_base_api
```

Version 4 requires **Python 3.12 or newer**. The package ships a `py.typed` marker, so type checkers can consume its inline annotations. Remuxing downloaded HLS streams into MP4 and embedding single-pass MP4 metadata/cover art uses an `ffmpeg` binary (discovered on `PATH` or configured via `RuntimeConfig.ffmpeg_path`). If `ffmpeg` is not available when `remux=True`, the downloader logs a warning and preserves the raw MPEG-TS stream cleanly.

## Related MCP documents

- [Overview — eaf_base_api](overview.md)
- [Error reference — eaf_base_api](troubleshooting/errors.md)
- [EAF Python API documentation overview](../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
