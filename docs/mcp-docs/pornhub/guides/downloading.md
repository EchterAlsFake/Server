---
title: "Downloading — PornHub API"
summary: "Explains the documented download configuration and download procedure for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Downloading"
keywords:
  - "PornHub"
  - "Downloading"
---

# Downloading — PornHub API

Explains the documented download configuration and download procedure for the PornHub API.

The PornHub API uses **two download modes** depending on the content type:
- **HLS** (`DownloadConfigHLS`) — For **Videos** and **Shorts**. Downloads HLS streams with quality selection, threaded segment downloading, resume support, and optional TS→MP4 remuxing.
- **RAW** (`DownloadConfigRAW`) — For **GIFs** and **Album photos**. Direct file downloads with multi-threaded range request support.

## HLS Download (Videos & Shorts)

```python
from base_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",           # "best", "half", "worst", or height int (e.g. 720)
    path="./downloads",       # Output directory or file path
    no_title=False,           # Auto-append video.title + ".mp4" if False
)

# Must have HTML loaded for m3u8 URLs
video = await client.get_video(url, load_html=True)
success = await video.download(configuration=config)
```

## RAW Download (GIFs & Photos)

```python
from base_api import DownloadConfigRAW

config = DownloadConfigRAW(
    quality="best",           # "best", "half", "worst", or height int
    path="./downloads",       # Output directory or file path
    no_title=False,           # Auto-append title + ".mp4" if False
    allow_multipart=True,     # Use multi-threaded range requests
    max_workers=5             # Number of parallel download threads
)

gif = await client.get_gif(url)
success = await gif.download(configuration=config)
```

For full details on all download configuration options, refer to the [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
