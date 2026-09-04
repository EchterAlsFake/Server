---
title: "Downloading — XNXX API"
summary: "Explains the documented download configuration and download procedure for the XNXX API."
public_url: "https://docs.echteralsfake.me/xnxx/"
aliases:
  - "XNXX Downloading"
keywords:
  - "XNXX"
  - "Downloading"
---

# Downloading — XNXX API

Explains the documented download configuration and download procedure for the XNXX API.

XNXX video downloads are HLS-only. Configure stream downloads via `DownloadConfigHLS`:

```python
from base_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",            # "best", "half", "worst", or height int
    path="./downloads",        # Destination path
    no_title=False,            # If False, automatically appends title + ".mp4"
)

success = await video.download(configuration=config)
```

For full details on download options and setup configurations, see the [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [XNXX API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — XNXX API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xnxx/](https://docs.echteralsfake.me/xnxx/)
