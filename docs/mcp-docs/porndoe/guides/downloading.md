---
title: "Downloading \u2014 Porndoe API"
summary: "RAW MP4 and optional HLS downloads, quality selection, signed URLs and configuration ownership."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Downloading \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "downloading"
---

# Downloading — Porndoe API

MP4 is the normal public player format. Use `DownloadConfigRAW`.

```python
from porndoe_api import DownloadConfigRAW
await video.download(DownloadConfigRAW(quality="best", path="./"))
await video.download(DownloadConfigRAW(
    quality="worst", path="./chosen-name.mp4", no_title=True,
    allow_multipart=True, max_workers=2,
))
```

`best`, `half`, `worst`, integer heights and labels such as `720p` use the base
engine's quality selector. Unavailable numeric requests choose the nearest
playable tier. Only playable `mp4` entries are selected; upgrade links and
other source groups are ignored.

The download configuration is copied before applying a title or stream URL.
Callbacks and stop events remain shared with the caller. RAW downloads return
a boolean. `DownloadCancelled` propagates unchanged.

`DownloadConfigHLS` delegates to the base HLS downloader only if the player
actually exposes HLS variants. If it does not, `DownloadFailed` instructs the
caller to use RAW. HLS download reports follow base configuration settings.

Signed CDN URLs expire and can be IP-bound. Fetch a new Video when downloading
later, and use the same networking route for metadata and media. Existing
successful BaseMedia source loads are cached; loading the same source again
does not refresh it. The base response cache TTL is independently configured
through RuntimeConfig.

See [Video](../reference/video.md) and
[base RAW downloader](../../eaf-base-api/configuration/downloads.md).
