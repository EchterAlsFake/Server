---
title: "Supported platforms — XVideos API"
summary: "Lists the operating systems and Python versions documented for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Supported platforms"
keywords:
  - "XVideos"
  - "Supported platforms"
---

# Supported platforms — XVideos API

Lists the operating systems and Python versions documented for the XVideos API.

Platform| Architecture| Status
---|---|---
Windows 11| x64| ✅ Tested
macOS Sequoia| x86_64| ✅ Tested
Linux (Arch)| x86_64| ✅ Tested
Android 16| aarch64| ✅ Tested

**Note**
HLS TS→MP4 remuxing requires `ffmpeg` (available on Termux via `pkg install ffmpeg`). If `ffmpeg` is not installed, use `remux=False` or allow automatic fallback to raw MPEG-TS output.

## Related MCP documents

- [XVideos API getting started](getting-started.md)
- [Errors and troubleshooting — XVideos API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
