---
title: "CLI — XVideos API"
summary: "Documents the command-line interface, arguments, and examples for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos CLI"
keywords:
  - "XVideos"
  - "CLI"
  - "xvideos_api"
---

# CLI — XVideos API

Documents the command-line interface, arguments, and examples for the XVideos API.

## xvideos_api

`xvideos_api` uses the shared behavior documented in this reference.

XVideos API includes a command-line interface:

```bash
# Download a single video
xvideos_api --download "https://www.xvideos.com/video..." --quality best --output ./video.mp4 --no-title True

# Download from a file of URLs
xvideos_api --file urls.txt --quality 720 --output ./downloads/ --no-title False
```

## CLI Options

Flag| Description
---|---
`--download URL`| Video URL to download
`--file PATH`| Text file with URLs (one per line)
`--quality`| Video quality: `best`, `half`, `worst`
`--output`| Output path (directory or file)
`--no-title`| `True`/`False` — Skip auto-appending title

## Related MCP documents

- [XVideos API getting started](../getting-started.md)
- [Errors and troubleshooting — XVideos API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
