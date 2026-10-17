---
title: "CLI — Porntrex API"
summary: "Documents the command-line interface, arguments, and examples for the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex CLI"
keywords:
  - "Porntrex"
  - "CLI"
  - "porntrex_api"
---

# CLI — Porntrex API

Documents the command-line interface, arguments, and examples for the Porntrex API.

## porntrex_api

`porntrex_api` uses the shared behavior documented in this reference.

The CLI entry point configures console logging at INFO level. Caught per-URL failures include the URL and full traceback; the default log format shows the logger, file, line, and function. Library applications should configure logging once at startup.

Porntrex API includes a command-line interface accessible via `porntrex_api` or `python -m porntrex_api`:

```bash
# Download a single video
porntrex_api --download "https://www.porntrex.com/video/12345/video-title" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m porntrex_api --download "https://www.porntrex.com/video/12345/video-title" --quality best --output ./downloads --no-title False

# Download from a line-separated file of URLs
porntrex_api --file urls.txt --quality best --output ./downloads --no-title False
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

- [Porntrex API getting started](../getting-started.md)
- [Errors and troubleshooting — Porntrex API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
