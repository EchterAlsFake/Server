---
title: "CLI — YouPorn API"
summary: "Documents the command-line interface, arguments, and examples for the YouPorn API."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn CLI"
keywords:
  - "YouPorn"
  - "CLI"
  - "youporn_api"
---

# CLI — YouPorn API

Documents the command-line interface, arguments, and examples for the YouPorn API.

## youporn_api

`youporn_api` can be executed as a console command or via `python -m youporn_api`:

```bash
# Download a single video
youporn_api --download "https://www.youporn.com/watch/1234567/sample-title/" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m youporn_api --download "https://www.youporn.com/watch/1234567/sample-title/" --quality best --output ./downloads --no-title False

# Download from a line-separated text file of URLs
youporn_api --file urls.txt --quality best --output ./downloads --no-title False
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

- [YouPorn API getting started](../getting-started.md)
- [Errors and troubleshooting — YouPorn API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
