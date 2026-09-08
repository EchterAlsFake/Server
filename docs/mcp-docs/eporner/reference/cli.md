---
title: "CLI — Eporner API"
summary: "Documents the command-line interface, arguments, and examples for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner CLI"
keywords:
  - "Eporner"
  - "CLI"
  - "eporner_api"
---

# CLI — Eporner API

Documents the command-line interface, arguments, and examples for the Eporner API.

## eporner_api

`eporner_api` can be executed as a console command or via `python -m eporner_api`:

```bash
# Download a single video
eporner_api --download "https://www.eporner.com/video-12345/sample-video/" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m eporner_api --download "https://www.eporner.com/video-12345/sample-video/" --quality best --output ./downloads --no-title False

# Download from a line-separated text file of URLs
eporner_api --file urls.txt --quality best --output ./downloads --no-title False
```

## CLI Options

Flag| Description
---|---
`--download URL`| Video URL to download
`--file FILE`| Text file with URLs (one per line)
`--quality QUALITY`| Video quality: `best`, `half`, `worst`
`--output DIR`| Destination file or directory path
`--no-title True/False`| Skip auto-appending video title to output filename (default: `False`)

The CLI entry point configures console logging at INFO level. Caught per-URL failures include the URL and full traceback; the default log format shows the logger, file, line, and function. Library applications should configure logging once at startup.

See [Logging and cleanup](../../eaf-base-api/guides/logging-and-cleanup.md) for application logging setup.

## Related MCP documents

- [Eporner API getting started](../getting-started.md)
- [Errors and troubleshooting — Eporner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
