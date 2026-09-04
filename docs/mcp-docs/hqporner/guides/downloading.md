---
title: "Downloading — HQPorner API"
summary: "Explains the documented download configuration and download procedure for the HQPorner API."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner Downloading"
keywords:
  - "HQPorner"
  - "Downloading"
  - "quality"
  - "path"
  - "no_title"
  - "callback"
  - "stop_event"
  - "allow_multipart"
  - "max_workers"
  - "read_timeout"
  - "chunk_size"
  - "max_retries"
---

# Downloading — HQPorner API

Explains the documented download configuration and download procedure for the HQPorner API.

HQPorner videos host direct MP4 media files instead of HLS streams. All downloads are configured using the `DownloadConfigRAW` dataclass:

```python
from hqporner_api import DownloadConfigRAW

config = DownloadConfigRAW(
    quality="best",           # "best", "half", "worst", or height int (e.g. 720)
    path="./downloads",       # Output directory or file path
    no_title=False,           # Auto-append video.title + ".mp4" if False
    allow_multipart=True,     # Use multi-threaded range requests
    max_workers=5             # Number of parallel download threads
)

success = await video.download(configuration=config)
```

## DownloadConfigRAW — Full Options

## quality

Type: str | int; Default: —; Description: Required. "best", "half", "worst", or resolution height (360, 480, 720, 1080, etc.)

## path

Type: str; Default: "./"; Description: Output directory or exact file path

## no_title

Type: bool; Default: False; Description: If True , treat path as the exact destination filename

## callback

Type: (int, int) → None; Default: None; Description: Progress callback (downloaded, total)

## stop_event

Type: asyncio.Event; Default: None; Description: Set this event to cancel the download

## allow_multipart

Type: bool; Default: True; Description: Enable parallel segmented downloads using range requests

## max_workers

Type: int; Default: 5; Description: Maximum concurrent worker threads for downloading segments

## read_timeout

Type: float; Default: 120.0; Description: Connection read timeout in seconds for chunk fetching

## chunk_size

Type: int; Default: 1024; Description: Download buffer chunk size in bytes

## max_retries

Type: int; Default: 5; Description: Max retries per worker when downloading chunks

## Related MCP documents

- [HQPorner API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — HQPorner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
