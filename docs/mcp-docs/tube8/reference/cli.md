---
title: "CLI — Tube8 API"
summary: "Documents the command-line interface, arguments, and examples for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 CLI"
keywords:
  - "Tube8"
  - "CLI"
  - "tube8_api"
---

# CLI — Tube8 API

Documents the command-line interface, arguments, and examples for the Tube8 API.

## tube8_api

`tube8_api` uses the shared behavior documented in this reference.

The CLI entry point configures console logging at INFO level. Caught per-URL failures include the URL and full traceback; the default log format shows the logger, file, line, and function. Library applications should configure logging once at startup.

Tube8 API includes a command-line interface accessible via `tube8_api` or `python -m tube8_api`:

```bash
# Download a single video
tube8_api --download "https://www.tube8.com/video/12345/sample" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m tube8_api --download "https://www.tube8.com/video/12345/sample" --quality best --output ./downloads --no-title False

# Download from a line-separated file of URLs
tube8_api --file urls.txt --quality best --output ./downloads --no-title False
```

## CLI Options

Flag| Description
---|---
`--download URL`| Video URL to download
`--file FILE`| Text file with URLs (separated by newlines)
`--quality QUALITY`| Video quality: `best`, `half`, `worst`
`--output DIR`| Destination directory or output file path
`--no-title True/False`| Skip auto-appending video title to output filename (default: `False`)

## Related MCP documents

- [Tube8 API getting started](../getting-started.md)
- [Errors and troubleshooting — Tube8 API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
