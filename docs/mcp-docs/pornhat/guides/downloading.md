---
title: "Downloading — Pornhat API"
summary: "Complete HLS downloads, real qualities, nearest-tier fallback, source refresh, FFmpeg metadata, callbacks, reports and transport limits."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Downloading — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "downloading"
---

# Downloading — Pornhat API

The verified player endpoints look like MP4 URLs but redirect to real HLS masters.
Use `DownloadConfigHLS`; the provider exposes no direct-MP4 downloader. Preserve signed
query strings and use `Video.download` rather than guessing CDN routes.

```python
from pornhat_api import DownloadConfigHLS

async def download_video(video):
    qualities = await video.get_available_qualities()
    config = DownloadConfigHLS(
        quality="best",
        path="./downloads/",
        remux=True,
        return_report=True,
        metadata={"title": video.title, "artist": video.author_name},
        callback=lambda current, total: print(current, total),
    )
    report = await video.download(config, refresh=True)
    assert report.status == "completed" and not report.missing
    return qualities, report
```

Create the output directory first. Without `no_title=True`, the shared provider helper
joins the configured directory with the sanitized video title and `.mp4` extension.
For an exact output filename, set `path="./video.mp4", no_title=True`.
Configurations are copied before the path/master is assigned. Callbacks, stop events,
metadata and caller options are preserved; the caller's path and master setting are unchanged.
Inspect the returned report for metadata success instead of relying on mutation of the original
configuration's `metadata_written` field.

## Quality selection

`await video.get_available_qualities()` returns sorted integer heights from actual resolved
sources and HLS master inspection. All representative samples expose `[360, 480, 720]`:

| Selector | Verified output |
| --- | --- |
| `360` / `"360p"` | 640×360 |
| `480` / `"480p"` | 854×480 |
| `720` / `"720p"` | 1280×720 |
| `"best"` | 720p |
| `"half"` | 480p (middle available tier) |
| `"worst"` | 360p |
| `1080` when absent | 720p, using shared nearest-tier fallback |

An explicit unavailable tier uses the shared nearest available resolution, preferring the
higher tier on a tie. The master determines available qualities; no resolution is invented
from labels, marketing flags, or URL suffixes. Additional quality sets were not observed.

## Refresh, reports and cancellation

`refresh=True` invalidates the page cache and resolves fresh sources on a new `Video` sharing
the same core and stable ID. It does not overwrite the original object's loaded fields.
This refreshes normally accessible expiring URLs without altering signatures.

Downloads delegate to `core.download`. `return_report=True` returns the shared `DownloadReport`
with `status`, `total`, `downloaded`, `missing`, and `metadata_written`; otherwise the backend
returns a boolean or raises. A returned failed/cancelled report must be inspected and is not
a successful transfer. Shared `stop_event`, segment resume options, progress callbacks and
metadata handling are passed through. `remux=True` needs FFmpeg; optional `metadata` and
`thumbnail` inputs follow shared download configuration contracts.

## Verified output and concurrency

On 2026-11-09 the full live suite passed **58 tests**, including **20 complete downloads**.
Three real videos (IDs 806155, 684951 and 138266) were downloaded at every exposed quality
and ffprobe-validated for dimensions, audio and complete duration. Further transfers covered
selectors, fallback, repeatability, refresh, concurrent different videos, German/`.one` hosts,
CLI downloading and embedded metadata titles.

Use `RuntimeConfig.max_workers_download = 4` for the configuration used by the final suite.
An earlier 20-worker repeat stalled on an HTTP/2 connection despite previous successes;
the bounded final suite completed in 94.99 seconds. The provider preserves injected core
settings. See [getting started](../getting-started.md) for the explicit runtime configuration.

For a caller-level deadline, wrap the download in `async with asyncio.timeout(seconds):`.
See [shared downloads](../../eaf-base-api/configuration/downloads.md) and
[errors](../troubleshooting/errors.md).
