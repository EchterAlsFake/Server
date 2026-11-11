---
title: "Downloading — Bellesa API"
summary: "Complete HLS and direct MP4 download configurations, actual dimensions, source label mappings, quality fallback, reports and refresh. Symbols: Video.download Video.refresh_media available_qualities advertised_qualities direct_sources source_quality return_report no_title."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Downloading — Bellesa API", "Bellesa downloading"]
keywords: ["Bellesa", "bellesa_api", "DownloadConfigHLS", "DownloadConfigRAW", "download", "quality", "best", "half", "worst", "2160", "renditions", "source_quality"]
---

# Downloading — Bellesa API

`Video.download(configuration)` uses the supplied `BaseCore` and accepts
`DownloadConfigHLS` or `DownloadConfigRAW`. Only publicly accessible video records are
eligible. Metadata and media are loaded lazily; missing/unavailable sources raise errors.

```python
import asyncio
from bellesa_api import Client, DownloadConfigHLS, DownloadConfigRAW

async def main():
    async with Client() as client:
        video = await client.get_video("https://www.bellesa.co/videos/7054")
        await video.load_sources("media")
        print(video.available_qualities)
        hls = DownloadConfigHLS(
            quality="worst", path="./hls/", remux=True, return_report=True,
        )
        report = await video.download(hls)
        print(report["status"])
        direct = DownloadConfigRAW(quality="worst", path="./mp4/")
        print(await video.download(direct))

if __name__ == "__main__":
    asyncio.run(main())
```

HLS uses the master and shared quality selection; `remux=True` produces MP4 and requires
FFmpeg. `return_report=True` requests the shared report, which includes status and
metadata-writing results. Inspect completion status. RAW uses the measured direct-source
map and returns a boolean. Transfer callbacks, cancellation, supported resume configuration
and HLS export metadata pass through the shared backend.

Configuration is copied before applying filenames and stream URLs; callback and stop-event
objects remain shared with the caller. By default `path` is a directory and a sanitized
title plus `.mp4` is appended. For an exact output file, use `no_title=True` and pass the
full filename as `path`. The input config's path and HLS URL are not overwritten.

## Actual qualities versus source labels

Quality keys use the **shorter actual dimension**, matching the backend. Metadata's
`advertised_qualities` and each rendition's `source_quality` retain Bellesa's original
file labels. They can differ from actual dimensions:

| Sample | Site labels | Actual qualities |
|---|---|---|
| Video 7054 | 360, 480, 720, 1080, 1440, 2160 | 360, 450, 720, 1080, 1440, 2160 |
| Video 1189 | 360, 480, 720 | 360, 450, 720 |
| Video 4651 | 360, 480, 720, 1080 | 360, 450, 720, 1080 |
| Video 1094 (4:3) | 360, 480, 720 | 480, 600, 960 |

The media source reads actual master renditions. If metadata lacks resolution labels,
the public player's observed 360/480/720 default requests a master, and only returned
renditions are exposed. A marketing label does not prove a measured quality.

`best` chooses the highest actual quality; `worst` the lowest; `half` the middle of the
sorted list (upper middle for an even-length list). Numeric selections use nearest
available quality, preferring the higher tier on equal distances. On 7054, requesting
480 selects actual 450. On 1094, requesting 720 selects actual 600. Inspect `renditions`
for exact dimensions, FPS, codecs, bitrate and URLs.

## Refresh, context and errors

`fresh = await video.refresh_media()` returns a new API/media-loaded object with refreshed
source data. Perform subsequent operations on `fresh`; the existing Video is unchanged.
Media queries/signatures are not stripped and session headers are not changed per video.
Observed public requests work without extra Referer/Origin headers. No authorization or
protected stream is fabricated.

`VideoUnavailable` and cancellation retain shared availability/cancellation behavior;
other preparation/transfer failures are wrapped in `DownloadFailed` with causes.
See [errors](../troubleshooting/errors.md), [live validation](live-validation.md), and
[shared download options](../../eaf-base-api/configuration/downloads.md).
