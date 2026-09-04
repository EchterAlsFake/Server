---
title: "Downloading — MissAV API"
summary: "Explains the documented download configuration and download procedure for the MissAV API."
public_url: "https://docs.echteralsfake.me/missav/"
aliases:
  - "MissAV Downloading"
keywords:
  - "MissAV"
  - "Downloading"
---

# Downloading — MissAV API

Explains the documented download configuration and download procedure for the MissAV API.

MissAV video streams are delivered via HLS. The scraper reconstructs the M3U8 playlist URL from obfuscated pipe-delimited JavaScript variables embedded in each video page.

```python
from missav_api import DownloadConfigHLS, Callback

config = DownloadConfigHLS(
    quality="best",            # "best", "half", "worst", or height int (e.g. 720)
    path="./downloads",        # Destination path
    no_title=False,            # If False, appends title + ".mp4"
    callback=Callback.custom_callback, # Optional progress callback
)

success = await video.download(configuration=config)
```

For more configurations, see the shared [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [MissAV API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — MissAV API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/missav/](https://docs.echteralsfake.me/missav/)
