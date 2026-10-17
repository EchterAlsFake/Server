---
title: "CLI — TNAFlix API"
summary: "Documents the command-line interface, arguments, and examples for the TNAFlix API."
public_url: "https://docs.echteralsfake.me/tnaflix/"
aliases:
  - "TNAFlix CLI"
keywords:
  - "TNAFlix"
  - "CLI"
  - "tnaflix_api"
---

# CLI — TNAFlix API

Documents the command-line interface, arguments, and examples for the TNAFlix API.

## tnaflix_api

`tnaflix_api` uses the shared behavior documented in this reference.

TNAFlix API includes a command-line interface accessible via the `tnaflix_api` binary or `python -m tnaflix_api`:

```bash
tnaflix_api --download "https://www.tnaflix.com/hd-videos/example-video-12345" --quality best --output ./downloads

python -m tnaflix_api --download "https://www.tnaflix.com/hd-videos/example-video-12345" --quality 720 --output ./downloads

tnaflix_api --file urls.txt --quality best --output ./downloads --no-title False
```

## CLI Options

Flag| Description
---|---
`--download URL`| Video URL to download
`--file FILE`| Text file containing video URLs (newline-separated)
`--quality QUALITY`| Desired resolution quality (`best`, `half`, `worst`, or height integer)
`--output DIR`| Destination folder or file path
`--no-title True/False`| Skip auto-appending video title to output filename (default: `False`)

## Related MCP documents

- [TNAFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — TNAFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tnaflix/](https://docs.echteralsfake.me/tnaflix/)
