---
title: "Downloading — RedGIFs API"
summary: "Direct RAW MP4/JPG quality selection, source refresh, paths, callbacks, cancellation and verified output; HLS limitations. Symbols: get_download_url get_qualities no_title stop_event allow_multipart max_workers resume_state_path has_audio."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Downloading — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "DownloadConfigRAW"
  - "download"
  - "quality"
  - "silent"
  - "HLS"
  - "refresh"
---

# Downloading — RedGIFs API

Use `DownloadConfigRAW` with `Video.download()` or `Image.download()`.
Every transfer uses the supplied `BaseCore.legacy_download()`; no second downloader is
implemented. Direct MP4/JPG downloading does not need FFmpeg.

```python
from pathlib import Path
from redgifs_api import Client, DownloadConfigRAW

async def download_video():
    output = Path("./downloads")
    output.mkdir(parents=True, exist_ok=True)
    async with Client() as client:
        video = await client.get_video("hotpinkacrobatickitfox")
        config = DownloadConfigRAW(
            quality="sd", path=output / "sample.mp4", no_title=True,
            allow_multipart=True, max_workers=3,
            callback=lambda done, total: print(done, total),
        )
        assert await video.download(config)
```

## Rendition labels

| Selector | Behavior |
| --- | --- |
| `hd` | Exact HD rendition; missing label raises |
| `sd` | Exact SD rendition; missing label raises |
| `silent` | Exact silent rendition, when supplied; never a fallback from another selector |
| `best` | HD, falling back to SD |
| `worst` | SD, falling back to HD |
| `half` | Lower middle of the available SD/HD labels; SD when both exist |

The provider rejects numeric resolution requests and strings such as `1080p`; site
labels do not guarantee one fixed resolution. Use `await video.get_qualities()` to
inspect actual labels. Absent exact labels raise `ValueError` from `get_download_url()`;
ordinary download failures, including selection failures, are wrapped in `DownloadFailed`.

## Paths, refresh and configuration

Default `path` is an output directory. An already-loaded HTML title names the MP4;
otherwise the stable ID does. No implicit HTML request is made for naming. Image
extensions follow their actual source URL. `no_title=True` makes path the exact filename.
The configuration is copied before path changes; callbacks and stop events retain their
caller identity. Do not reuse the same output path for concurrent downloads.

Downloads refresh public detail URLs on every call, retaining CDN casing and signed
queries. `get_download_url(refresh=True)` refreshes a URL without replacing committed
source metadata. RAW configuration supports multipart workers, retries, chunk size,
read timeout, resume-state path and cancellation. RAW returns `bool`, not an HLS report.
The provider does not implement remux, metadata-tag writing or thumbnail embedding.

## Verified complete output

The final paced run completed 23 MP4 matrix downloads covering four videos and all
exposed labels plus best/half/worst, two JPG renditions, concurrent different-video
transfers and a byte-for-byte repeat, and two CLI downloads. ffprobe checked complete
files, dimensions, duration and audio.

| Sample | HD | SD | Silent | Duration |
| --- | --- | --- | --- | --- |
| hotpinkacrobatickitfox | 1080×1920, audio | 480×854, audio | 1080×1920, no audio | 6.467 s |
| ivoryhauntingblackbird | 1080×1920, audio | 480×854, audio | 1080×1920, no audio | 7.767 s |
| toughlongtermbanteng | 1080×1920, audio | 480×854, audio | 1080×1920, no audio | 31.400 s |
| happyfrenchindianspinyloach | 1280×640, audio | 640×320, audio | Unavailable | 15.000 s |
| Image deliciousfrontelephant | 1200×1600 JPG | 800×1067 JPG | Unavailable | Still image |

The legacy video's API `hasAudio=false` disagrees with its audible AAC track;
`has_audio` preserves that reported value and is not a container probe.

## HLS boundary

`video.hls_urls` exposes actual HD/SD playlist URLs when the site reports HLS.
Observed playlists use `EXT-X-MAP` and byte ranges into fMP4 files. The shared HLS
implementation drops those byte ranges; the provider does not claim a working HLS
transfer and rejects `DownloadConfigHLS`. Direct MP4 renditions provide verified
complete transfers. See [validation](live-validation.md).
