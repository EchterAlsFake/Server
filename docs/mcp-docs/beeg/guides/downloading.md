---
title: "Downloading — Beeg API"
summary: "Explains the documented download configuration and download procedure for the Beeg API."
public_url: "https://docs.echteralsfake.me/beeg/"
aliases:
  - "Beeg Downloading"
keywords:
  - "Beeg"
  - "Downloading"
---

# Downloading — Beeg API

Explains the documented download configuration and download procedure for the Beeg API.

Beeg video downloads are HLS-only. Configure stream downloads via `DownloadConfigHLS`:

```python
from base_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",            # "best", "half", "worst", or height int
    path="./downloads",        # Destination path
    no_title=False,            # If False, automatically appends title + ".mp4"
    return_report=True         # Return a DownloadReport instead of bool
)

report = await video.download(configuration=config)
```

For full details on download options and setup configurations, see the [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [Beeg API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — Beeg API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/beeg/](https://docs.echteralsfake.me/beeg/)
