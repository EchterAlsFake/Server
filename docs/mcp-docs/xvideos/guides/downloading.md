---
title: "Downloading — XVideos API"
summary: "Explains the documented download configuration and download procedure for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Downloading"
keywords:
  - "XVideos"
  - "Downloading"
  - "quality"
  - "path"
  - "no_title"
  - "callback"
  - "stop_event"
  - "remux"
  - "start_segment"
  - "segment_state_path"
  - "segment_dir"
  - "return_report"
  - "cleanup_on_stop"
  - "keep_segment_dir"
  - "ios_support"
---

# Downloading — XVideos API

Explains the documented download configuration and download procedure for the XVideos API.

All downloads are configured using the `DownloadConfigHLS` dataclass:

```python
from xvideos_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",           # "best", "half", "worst", or int like 720
    path="./downloads",       # Output directory (title auto-appended)
    no_title=False,           # If True, use path as exact filename
    remux=True,               # Convert TS segments to MP4 (needs av)
    return_report=True,       # Return DownloadReport instead of bool
)

report = await video.download(configuration=config)
print(report.status)       # "completed", "failed", or "cancelled"
print(report.downloaded)    # Segments downloaded
print(report.total)         # Total segments
```

## DownloadConfigHLS — Full Options

## quality

Type: str | int; Default: —; Description: Required. "best", "half", "worst", or pixel height (720, 1080, etc.)

## path

Type: str; Default: "./"; Description: Output directory or exact file path

## no_title

Type: bool; Default: False; Description: Skip auto-appending video title to filename

## callback

Type: (int, int) → None; Default: None; Description: Progress callback (downloaded, total) . Falls back to text progress bar.

## stop_event

Type: asyncio.Event; Default: None; Description: Set this event to cancel the download

## remux

Type: bool; Default: False; Description: Remux TS → MP4 using PyAV

## start_segment

Type: int; Default: 0; Description: Skip first N segments

## segment_state_path

Type: str | None; Default: None; Description: Path for resume state JSON file

## segment_dir

Type: str | None; Default: None; Description: Directory for individual segment files

## return_report

Type: bool; Default: False; Description: Return DownloadReport instead of bool

## cleanup_on_stop

Type: bool; Default: True; Description: Delete temp files when cancelled

## keep_segment_dir

Type: bool; Default: False; Description: Keep segment files after completion

## ios_support

Type: bool; Default: False; Description: Restrict audio codec to AAC-only for iOS

## Related MCP documents

- [XVideos API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — XVideos API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
