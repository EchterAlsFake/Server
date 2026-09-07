---
title: "CLI — xHamster API"
summary: "Documents the command-line interface, arguments, and examples for the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster CLI"
keywords:
  - "xHamster"
  - "CLI"
  - "xhamster_api"
---

# CLI — xHamster API

Documents the command-line interface, arguments, and examples for the xHamster API.

## xhamster_api

`xhamster_api` can be executed as a console command or via `python -m xhamster_api`:

```bash
# Download a single video
xhamster_api --download "https://xhamster.com/videos/sample-title-12345" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m xhamster_api --download "https://xhamster.com/videos/sample-title-12345" --quality best --output ./downloads --no-title False

# Download from a line-separated text file of URLs
xhamster_api --file urls.txt --quality best --output ./downloads --no-title False
```

## CLI Options

Flag| Description
---|---
`--download URL`| Video URL to download
`--file FILE`| Text file with URLs (one per line)
`--quality QUALITY`| Video quality: `best`, `half`, `worst`
`--output DIR`| Destination file or directory path
`--no-title True/False`| Skip auto-appending video title to output filename (default: `False`)

## Related MCP documents

- [xHamster API getting started](../getting-started.md)
- [Errors and troubleshooting — xHamster API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
