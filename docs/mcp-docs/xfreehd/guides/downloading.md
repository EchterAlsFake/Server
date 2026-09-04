---
title: "Downloading — XFreeHD API"
summary: "Explains the documented download configuration and download procedure for the XFreeHD API."
public_url: "https://docs.echteralsfake.me/xfreehd/"
aliases:
  - "XFreeHD Downloading"
keywords:
  - "XFreeHD"
  - "Downloading"
---

# Downloading — XFreeHD API

Explains the documented download configuration and download procedure for the XFreeHD API.

XFreeHD video files are direct MP4 assets on CDNs. Configure downloads using `DownloadConfigRAW`:

```python
from base_api import DownloadConfigRAW

config = DownloadConfigRAW(
    quality="hd",             # Set to "hd" for high quality, or "sd" for standard quality
    path="./downloads",        # Destination path
    no_title=False,            # If False, automatically appends title + ".mp4"
    allow_multipart=True,      # Enable parallel segmented downloads using range requests
    max_workers=5              # Concurrent download segment threads
)

success = await video.download(configuration=config)
```

For full details on RAW download parameters, see the reference in [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [XFreeHD API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — XFreeHD API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xfreehd/](https://docs.echteralsfake.me/xfreehd/)
