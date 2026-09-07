---
title: "CLI — Thumbzilla API"
summary: "Documents the command-line interface, arguments, and examples for the Thumbzilla API."
public_url: "https://docs.echteralsfake.me/thumbzilla/"
aliases:
  - "Thumbzilla CLI"
keywords:
  - "Thumbzilla"
  - "CLI"
  - "thumbzilla_api"
---

# CLI — Thumbzilla API

Documents the command-line interface, arguments, and examples for the Thumbzilla API.

## thumbzilla_api

`thumbzilla_api` can be executed as a console command or via `python -m thumbzilla_api`:

```bash
# Download a single video
thumbzilla_api --download "https://www.thumbzilla.com/video/ph123456789/sample-title" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m thumbzilla_api --download "https://www.thumbzilla.com/video/ph123456789/sample-title" --quality best --output ./downloads --no-title False

# Download from a line-separated text file of URLs
thumbzilla_api --file urls.txt --quality best --output ./downloads --no-title False
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

- [Thumbzilla API getting started](../getting-started.md)
- [Errors and troubleshooting — Thumbzilla API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/thumbzilla/](https://docs.echteralsfake.me/thumbzilla/)
