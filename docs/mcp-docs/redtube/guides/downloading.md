---
title: "Downloading — Redtube API"
summary: "Explains the documented download configuration and download procedure for the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube Downloading"
keywords:
  - "Redtube"
  - "Downloading"
---

# Downloading — Redtube API

Explains the documented download configuration and download procedure for the Redtube API.

Redtube serves video files via HLS streaming. Configure stream downloading parameters via the `DownloadConfigHLS` class:

```python
from base_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",            # "best", "half", "worst", or height int (e.g. 720)
    path="./downloads",        # Destination path
    no_title=False,            # If False, automatically appends title + ".mp4"
)

success = await video.download(configuration=config)
```

For more configurations regarding downloading setups, please refer to the shared [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [Redtube API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — Redtube API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
