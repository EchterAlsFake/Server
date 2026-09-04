---
title: "Downloading — Thumbzilla API"
summary: "Explains the documented download configuration and download procedure for the Thumbzilla API."
public_url: "https://docs.echteralsfake.me/thumbzilla/"
aliases:
  - "Thumbzilla Downloading"
keywords:
  - "Thumbzilla"
  - "Downloading"
---

# Downloading — Thumbzilla API

Explains the documented download configuration and download procedure for the Thumbzilla API.

Thumbzilla serves video files via HLS streaming. The scraper auto-constructs a master M3U8 playlist from the JSON media definitions. Configure stream downloading parameters via the `DownloadConfigHLS` class:

```python
from base_api import DownloadConfigHLS

config = DownloadConfigHLS(
    quality="best",
    path="./downloads",
    no_title=False,
    return_report=True
)

report = await video.download(configuration=config)
```

For more configurations, see the shared [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [Thumbzilla API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — Thumbzilla API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/thumbzilla/](https://docs.echteralsfake.me/thumbzilla/)
