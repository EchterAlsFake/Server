---
title: "CLI — EMPFlix API"
summary: "Documents the command-line interface, arguments, and examples for the EMPFlix API."
public_url: "https://docs.echteralsfake.me/empflix/"
aliases:
  - "EMPFlix CLI"
keywords:
  - "EMPFlix"
  - "CLI"
  - "empflix_api"
---

# CLI — EMPFlix API

Documents the command-line interface, arguments, and examples for the EMPFlix API.

## empflix_api

`empflix_api` uses the shared behavior documented in this reference.

EMPFlix API includes a command-line interface accessible via the `empflix_api` binary or `python -m empflix_api`:

```bash
empflix_api --download "https://www.empflix.com/videos/example-video-12345" --quality best --output ./downloads

python -m empflix_api --download "https://www.empflix.com/videos/example-video-12345" --quality 720 --output ./downloads

empflix_api --file urls.txt --quality best --output ./downloads --no-title False
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

- [EMPFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — EMPFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/empflix/](https://docs.echteralsfake.me/empflix/)
