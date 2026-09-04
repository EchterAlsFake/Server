---
title: "Downloading — YouPorn API"
summary: "Explains the documented download configuration and download procedure for the YouPorn API."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn Downloading"
keywords:
  - "YouPorn"
  - "Downloading"
---

# Downloading — YouPorn API

Explains the documented download configuration and download procedure for the YouPorn API.

YouPorn serves videos as both HLS playlists and raw MP4 direct links. In order to handle both cases securely, provide a backup RAW configuration along with the HLS options:

```python
from base_api import DownloadConfigHLS, DownloadConfigRAW

hls_config = DownloadConfigHLS(
    quality="best",
    path="./downloads",
    no_title=False
)

raw_config = DownloadConfigRAW(
    quality="best",
    path="./downloads",
    no_title=False
)

# Will download via HLS if is_hls=True, or fall back to raw direct file downloader if false
success = await video.download(configuration=hls_config, backup_configuration=raw_config)
```

For more configurations, see references in [eaf_base_api Documentation](../../eaf-base-api/overview.md).

## Related MCP documents

- [YouPorn API getting started](../getting-started.md)
- [Download configuration — eaf_base_api](../../eaf-base-api/configuration/downloads.md)
- [Errors and troubleshooting — YouPorn API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
