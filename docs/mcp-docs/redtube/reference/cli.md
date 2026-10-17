---
title: "CLI — Redtube API"
summary: "Documents the command-line interface, arguments, and examples for the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube CLI"
keywords:
  - "Redtube"
  - "CLI"
  - "redtube_api"
---

# CLI — Redtube API

Documents the command-line interface, arguments, and examples for the Redtube API.

## redtube_api

`redtube_api` uses the shared behavior documented in this reference.

The CLI entry point configures console logging at INFO level. Caught per-URL failures include the URL and full traceback; the default log format shows the logger, file, line, and function. Library applications should configure logging once at startup.

RedTube API includes a command-line interface accessible via `redtube_api` or `python -m redtube_api`:

```bash
# Download a single video
redtube_api --download "https://www.redtube.com/1234567" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m redtube_api --download "https://www.redtube.com/1234567" --quality best --output ./downloads --no-title False

# Download from a line-separated file of URLs
redtube_api --file urls.txt --quality best --output ./downloads --no-title False
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

- [Redtube API getting started](../getting-started.md)
- [Errors and troubleshooting — Redtube API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
