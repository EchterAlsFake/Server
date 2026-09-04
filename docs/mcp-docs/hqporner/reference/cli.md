---
title: "CLI — HQPorner API"
summary: "Documents the command-line interface, arguments, and examples for the HQPorner API."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner CLI"
keywords:
  - "HQPorner"
  - "CLI"
  - "hqporner_api"
---

# CLI — HQPorner API

Documents the command-line interface, arguments, and examples for the HQPorner API.

## hqporner_api

`hqporner_api` uses the shared behavior documented in this reference.

The HQPorner API package includes a rich CLI:

```bash
# Download a single video
hqporner_api --download "https://hqporner.com/hd/..." --quality best --output ./downloads --no-title False

# Search and download resulting videos
hqporner_api --search "blonde" --pages 2 --quality 1080 --output ./blonde_videos/ --concurrency 3
```

## CLI Options

Flag| Description
---|---
`--download URL`| Download a single video from the specified URL
`--file FILE`| Read and download URLs from a line-separated text file
`--search QUERY`| Search videos by keyword and download matches
`--actress NAME`| Download videos featuring the actress name or URL
`--category CATEGORY`| Download videos from a specific category
`--random`| Download a single randomly chosen video
`--quality QUALITY`| **Required.** The video quality: `best`, `half`, `worst`, or specific height (e.g. `720`)
`--output DIR`| **Required.** The destination path/directory
`--no-title True/False`| Skip auto-appending video title to output filename (default: `False`)
`--pages N`| Number of pages to scrape (default: `1`)
`--concurrency N`| Max concurrent downloads to run in parallel (default: `3`)

## Related MCP documents

- [HQPorner API getting started](../getting-started.md)
- [Errors and troubleshooting — HQPorner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
