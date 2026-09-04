---
title: "Downloading — Tube8 API"
summary: "Explains the documented download configuration and download procedure for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 Downloading"
keywords:
  - "Tube8"
  - "Downloading"
---

# Downloading — Tube8 API

Explains the documented download configuration and download procedure for the Tube8 API.

Tube8 serves video files via HLS streaming. The scraper auto-constructs a master M3U8 playlist from the JSON media definitions. Configure stream downloading parameters via the `DownloadConfigHLS` class:

```python
from base_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",            # "best", "half", "worst", or height int (e.g. 720)
    path="./downloads",        # Destination path
    no_title=False,            # If False, automatically appends title + ".mp4"
    return_report=True
)

report = await video.download(configuration=config)
```

For more configurations, see the shared [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [Tube8 API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — Tube8 API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
