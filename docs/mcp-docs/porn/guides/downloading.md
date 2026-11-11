---
title: "Downloading — Porn.com API"
summary: "Video.download and DownloadConfigHLS, quality selectors, source refresh, MPEG-TS versus remuxed MP4, reports, callbacks and protected-media boundaries."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Downloading — Porn.com API", "Downloading Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "download", "DownloadConfigHLS", "refresh", "HLS", "remux", "quality"]
---

# Downloading — Porn.com API

Native public scenes expose HLS masters. `await video.get_qualities()` inspects
their actual width/height/bandwidth and preserves signed variant URLs. A referral
without native media raises `VideoUnavailable`; this wrapper does not follow its
outbound link to implement another site's downloader.

```python
from porn_api import Client, DownloadConfigHLS

async def download_video():
    async with Client() as client:
        video = await client.get_video("https://www.porn.com/scene/208974141")
        config = DownloadConfigHLS(
            quality="worst", path="./", remux=True, return_report=True,
            metadata={"title": video.title},
        )
        report = await video.download(config)
        print(report.status, report.downloaded, report.total, report.metadata_written)
```

`Video.download(configuration, *, refresh=True)` requires `DownloadConfigHLS`
and delegates to `BaseCore.download`. No direct full-video MP4 source or RAW
download mode was verified. `remux=True` converts the completed HLS MPEG-TS output
to MP4 with FFmpeg. With `remux=False`, the file contains MPEG-TS regardless of a
`.mp4` extension. `no_title=True` treats `path` as the exact output file path;
otherwise a sanitized title-derived filename is appended to the output directory.

## Quality selection

| Selector | Behavior |
|---|---|
| `best` | Highest actual available height. |
| `half` | Middle available height, not half the best resolution numerically. |
| `worst` | Lowest actual available height. |
| Positive integer / numeric string such as `720` or `"720p"` | Exact height if available; otherwise nearest tier, preferring the higher on a tie. |

Recorded sample sets are 360p/480p/1080p (`208974141`) and 360p/480p/720p
(`208581087`). Requesting 720 on the first set selects 480. Marketing HD labels
are not used to invent unavailable renditions.

## Configuration and source lifetime

Signed URLs can expire or vary after session cookies are established. Each
download refreshes the scene through the shared cache refresh policy by default,
using a new model so concurrent operations do not mutate the existing Video.
`refresh=False` reuses its current metadata. Caller configuration is copied;
callbacks and cancellation signals remain attached to the operation. Shared
request headers are not mutated per video.

Use shared `DownloadConfigHLS` fields for `callback`, `callback_remux`,
`stop_event`, `metadata`, `thumbnail`, `return_report`, remuxing, and supported
resume settings. Progress/report semantics remain those of the shared backend.
Native encrypted/protected variant playlists are rejected before downloading;
there is no authorization or DRM bypass.

All renditions in both sample sets were completely downloaded and checked with
ffprobe. Additional complete files covered metadata export, callbacks, reports,
presets/fallback, refreshed repeats, TS output, concurrent videos, and the CLI.
See [live validation](live-validation.md) for the measured evidence.
