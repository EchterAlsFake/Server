---
title: "Downloading — xHamster API"
summary: "Explains the documented download configuration and download procedure for the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster Downloading"
keywords:
  - "xHamster"
  - "Downloading"
---

# Downloading — xHamster API

Explains the documented download configuration and download procedure for the xHamster API.

xHamster serves videos and shorts via HLS streaming. Configure downloads using `DownloadConfigHLS`:

```python
from base_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",            # "best", "half", "worst", or height int (e.g. 720)
    path="./downloads",        # Output directory
    no_title=False,            # Auto-appends title + ".mp4" if False
    return_report=True
)

report = await video.download(configuration=config)
```

For additional downloading properties, see [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [xHamster API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — xHamster API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
