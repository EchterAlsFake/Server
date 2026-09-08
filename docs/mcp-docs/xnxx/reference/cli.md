---
title: "CLI — XNXX API"
summary: "Documents the command-line interface, arguments, and examples for the XNXX API."
public_url: "https://docs.echteralsfake.me/xnxx/"
aliases:
  - "XNXX CLI"
keywords:
  - "XNXX"
  - "CLI"
  - "xnxx_api"
---

# CLI — XNXX API

Documents the command-line interface, arguments, and examples for the XNXX API.

## xnxx_api

`xnxx_api` can be invoked directly or via `python -m xnxx_api`.

The XNXX API package includes a CLI tool executable directly from the terminal:

```bash
# Download a single video to target folder
xnxx_api --download "https://www.xnxx.com/video-..." --quality best --output ./downloads --no-title False

# Batch download URLs from a line-separated text file
xnxx_api --file file_list.txt --quality best --output ./downloads --no-title False
```

## CLI Parameters

Flag| Description
---|---
`--download URL`| Download video from the specified XNXX URL
`--file PATH`| Read URLs from a text file (separated by newlines) and download them
`--quality QUALITY`| **Required.** Set video download quality: `best`, `half`, `worst`
`--output DIR`| **Required.** Destination file or directory path
`--no-title True/False`| **Required.** Skip auto-appending video title to output filename (set to `True` if output path includes target filename)

The CLI entry point configures console logging at INFO level. Caught per-URL failures include the URL and full traceback; the default log format shows the logger, file, line, and function. Library applications should configure logging once at startup.

See [Logging and cleanup](../../eaf-base-api/guides/logging-and-cleanup.md) for application logging setup.

## Related MCP documents

- [XNXX API getting started](../getting-started.md)
- [Errors and troubleshooting — XNXX API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xnxx/](https://docs.echteralsfake.me/xnxx/)
