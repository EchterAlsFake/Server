---
title: "Downloading — SpankBang API"
summary: "Explains the documented download configuration and download procedure for the SpankBang API."
public_url: "https://docs.echteralsfake.me/spankbang/"
aliases:
  - "SpankBang Downloading"
keywords:
  - "SpankBang"
  - "Downloading"
---

# Downloading — SpankBang API

Explains the documented download configuration and download procedure for the SpankBang API.

SpankBang supports dual download configurations. Under the hood, the master playlist contains an HLS stream, but direct CDN links are also extracted if you prefer RAW MP4 chunked downloading.

## HLS Download (Recommended)

HLS provides highly reliable stream downloads, slicing chunked `.ts` packages and remuxing them to `.mp4` via PyAV:

```python
from base_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",
    path="./downloads"
)
success = await video.download(configuration_hls=config, use_hls=True)
```

## RAW CDN Download

RAW downloads request full files directly from SpankBang's media CDN servers, leveraging HTTP range requests to speed up the process across parallel workers:

```python
from base_api import DownloadConfigRAW

config = DownloadConfigRAW(
    quality="best",          # "best", "half", "worst"
    path="./downloads",
    allow_multipart=True,
    max_workers=5
)
success = await video.download(configuration_raw=config, use_hls=False)
```

## Related MCP documents

- [SpankBang API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — SpankBang API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/spankbang/](https://docs.echteralsfake.me/spankbang/)
