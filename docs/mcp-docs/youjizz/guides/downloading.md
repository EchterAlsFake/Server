---
title: "Downloading \u2014 YouJizz API"
summary: "RAW MP4 and HLS quality selection, refresh and remuxing."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Downloading \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "guides", "downloading"]
---

# Downloading — YouJizz API

```python
from youjizz_api import DownloadConfigRAW, DownloadConfigHLS
await video.download(DownloadConfigRAW(quality="worst", path="./downloads"))
await video.download(DownloadConfigHLS(quality="best", path="./downloads", remux=True))
```

HTML loading supplies direct_urls and hls_urls by numeric encoding label.
available_qualities is their sorted union, including labels such as 288 or 368.
Downloads use per-quality masters because Auto may omit older renditions.
Presets best/half/worst select the highest/middle/lowest sorted label. Missing
numeric quality selects the nearest, preferring the higher label on a tie.
Signed queries are preserved. Refresh expired URLs with refresh_sources().
For explicit filenames set no_title=True and a complete path. Shared download
reports, callbacks and cancellation remain available. Actual dimensions can differ
from encoding labels, especially portrait media.
