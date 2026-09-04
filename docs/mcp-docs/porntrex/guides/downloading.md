---
title: "Downloading — Porntrex API"
summary: "Explains the documented download configuration and download procedure for the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex Downloading"
keywords:
  - "Porntrex"
  - "Downloading"
---

# Downloading — Porntrex API

Explains the documented download configuration and download procedure for the Porntrex API.

Porntrex media files are served directly as MP4 files. Configure downloads using `DownloadConfigRAW`:

```python
from base_api import DownloadConfigRAW

config = DownloadConfigRAW(
    quality="best",            # "best", "half", "worst", or height int (e.g. 720)
    path="./downloads",        # Destination path
    no_title=False,            # If False, automatically appends title + ".mp4"
    allow_multipart=True,      # Enable multi-threaded range requests
    max_workers=5              # Concurrent download segment threads
)

success = await video.download(configuration=config)
```

For a detailed breakdown of all available settings inside `DownloadConfigRAW`, please read the [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [Porntrex API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — Porntrex API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
