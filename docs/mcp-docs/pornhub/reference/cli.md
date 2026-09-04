---
title: "CLI — PornHub API"
summary: "Documents the command-line interface, arguments, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub CLI"
keywords:
  - "PornHub"
  - "CLI"
  - "phub"
---

# CLI — PornHub API

Documents the command-line interface, arguments, and examples for the PornHub API.

## phub

`phub` uses the shared behavior documented in this reference.

The PornHub API package includes a built-in CLI accessible via the `phub` command:

```bash
# Download a single video
phub --download "https://www.pornhub.com/view_video.php?viewkey=..." --quality best --output ./downloads --no-title False

# Download from a file of URLs
phub --file urls.txt --quality best --output ./downloads --no-title False

# Download liked videos (requires login)
phub --liked --email user@example.com --password pass --quality best --output ./favorites --no-title False

# Download with video ID as filename and a limit
phub --download "https://www.pornhub.com/view_video.php?viewkey=..." --quality best --output ./downloads --no-title False --id-as-title --limit 10
```

## CLI Options

Flag| Description
---|---
`--download URL`| Download from the specified URL (video, short, GIF, album, pornstar, model, user, channel, or playlist)
`--file FILE`| Read and download URLs from a line-separated text file
`--quality QUALITY`| **Required.** The video quality: `best`, `half`, `worst`
`--output DIR`| **Required.** The destination path/directory
`--no-title True/False`| **Required.** Skip auto-appending video title to output filename
`--pages N`| Number of pages to fetch for iterables (default: `1`)
`--email EMAIL`| Account email for login
`--password PASS`| Account password for login
`--id-as-title`| Use the video ID as the output filename instead of the title
`--limit N`| Maximum number of videos to download
`--liked`| Download liked/favorite videos (requires login)
`--recommended`| Download recommended videos (requires login)
`--watched`| Download watched/history videos (requires login)

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
