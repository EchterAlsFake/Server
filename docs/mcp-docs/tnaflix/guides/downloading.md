---
title: "Downloading — TNAFlix API"
summary: "Explains the documented download configuration and download procedure for the TNAFlix API."
public_url: "https://docs.echteralsfake.me/tnaflix/"
aliases:
  - "TNAFlix Downloading"
keywords:
  - "TNAFlix"
  - "Downloading"
---

# Downloading — TNAFlix API

Explains the documented download configuration and download procedure for the TNAFlix API.

TNAFlix serves progressive direct MP4 streams with signed tokens. Downloads are configured via `DownloadConfigRAW`:

```python
from base_api import DownloadConfigRAW

config = DownloadConfigRAW(
    quality="best",            # "best", "half", "worst", or height int (e.g. 720, 1080)
    path="./downloads",        # Destination directory or file path
    no_title=False,            # If False, automatically appends video title + ".mp4"
    allow_multipart=True,      # Enable multi-threaded byte-range chunk downloading
    max_workers=5              # Concurrent download workers
)

success = await video.download(configuration=config)
```

For more options and configuration details, refer to the [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [TNAFlix API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — TNAFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tnaflix/](https://docs.echteralsfake.me/tnaflix/)
