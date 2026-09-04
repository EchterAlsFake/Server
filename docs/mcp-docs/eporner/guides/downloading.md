---
title: "Downloading — Eporner API"
summary: "Explains the documented download configuration and download procedure for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner Downloading"
keywords:
  - "Eporner"
  - "Downloading"
---

# Downloading — Eporner API

Explains the documented download configuration and download procedure for the Eporner API.

Eporner serves direct MP4 media files. Download options are configured via the `DownloadConfigRAW` class, specifying the encoding type (AV1 or H.264):

```python
from base_api import DownloadConfigRAW
from eporner_api.modules.locals import Encoding

config = DownloadConfigRAW(
    quality="best",            # "best", "half", "worst", or height (e.g. 1080)
    path="./downloads",        # Output directory
    no_title=False,            # Auto-appends title + ".mp4" if False
    allow_multipart=True,      # Enable multi-threaded segmented range downloads
    max_workers=5              # Concurrent segment downloaders
)

# Download using H.264 codec
await video.download(configuration=config, mode=Encoding.mp4_h264)
```

For more configurations regarding RAW downloaders, please read the reference inside [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [Eporner API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — Eporner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
