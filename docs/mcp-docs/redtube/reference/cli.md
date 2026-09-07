---
title: "CLI — RedTube API"
summary: "Documents the command-line interface, arguments, and examples for the RedTube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "RedTube CLI"
keywords:
  - "RedTube"
  - "CLI"
  - "redtube_api"
---

# CLI — RedTube API

Documents the command-line interface, arguments, and examples for the RedTube API.

## redtube_api

`redtube_api` can be executed as a console command or via `python -m redtube_api`:

```bash
# Download a single video
redtube_api --download "https://www.redtube.com/1234567" --quality best --output ./downloads --no-title False

# Or invoke via python -m
python -m redtube_api --download "https://www.redtube.com/1234567" --quality best --output ./downloads --no-title False

# Download from a line-separated text file of URLs
redtube_api --file urls.txt --quality best --output ./downloads --no-title False
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

- [RedTube API getting started](../getting-started.md)
- [Errors and troubleshooting — RedTube API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
