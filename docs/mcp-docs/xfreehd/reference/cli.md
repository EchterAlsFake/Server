---
title: "CLI — XFreeHD API"
summary: "Documents the command-line interface, arguments, and examples for the XFreeHD API."
public_url: "https://docs.echteralsfake.me/xfreehd/"
aliases:
  - "XFreeHD CLI"
keywords:
  - "XFreeHD"
  - "CLI"
  - "xfreehd_api"
---

# CLI — XFreeHD API

Documents the command-line interface, arguments, and examples for the XFreeHD API.

## xfreehd_api

`xfreehd_api` can be executed as a console command or via `python -m xfreehd_api`:

```bash
# Download a single video
xfreehd_api --download "https://www.xfreehd.com/video/12345/sample" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m xfreehd_api --download "https://www.xfreehd.com/video/12345/sample" --quality best --output ./downloads --no-title False

# Download from a line-separated text file of URLs
xfreehd_api --file urls.txt --quality best --output ./downloads --no-title False
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

- [XFreeHD API getting started](../getting-started.md)
- [Errors and troubleshooting — XFreeHD API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xfreehd/](https://docs.echteralsfake.me/xfreehd/)
