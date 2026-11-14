---
title: "YouJizz API getting started"
summary: "Install the package and fetch public video metadata."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["YouJizz API getting started"]
keywords: ["YouJizz", "youjizz_api", "getting-started"]
---

# YouJizz API getting started

Version **0.1.0**. Requires Python 3.12+, `eaf-base-api[hls]>=4.2.6` and `selectolax`.

```sh
pip install unofficial-api-for-youjizz
youjizz_api -h
```

```python
import asyncio
from youjizz_api import Client, DownloadConfigRAW

async def main():
    async with Client() as client:
        video = await client.get_video("48914471", load_api=True, load_html=True)
        print(video.title, video.duration, video.available_qualities)
        await video.download(DownloadConfigRAW(quality="worst", path="./downloads"))

asyncio.run(main())
```

FFmpeg is required for HLS remuxing; ffprobe is used by live download checks.
Client closes its own core, while injected BaseCore instances remain caller-owned.
See [Client](reference/client.md), [source loading](guides/source-loading.md) and
[downloading](guides/downloading.md).
