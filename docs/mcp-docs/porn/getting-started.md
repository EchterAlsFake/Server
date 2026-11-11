---
title: "Porn.com API getting started"
summary: "Install unofficial-api-for-porn, construct Client with BaseCore, fetch scenes and browse typed result streams."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Porn.com API getting started"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "installation", "Client", "BaseCore", "quickstart"]
---

# Porn.com API getting started

Version **0.1.0**. Distribution: `unofficial-api-for-porn`. Import: `porn_api`.
Requires Python **3.12+**, `eaf-base-api[hls]>=4.2.6`, and `selectolax`.

The package is currently unpublished. From the workspace containing its checkout:

```sh
pip install ./unofficial-api-for-porn
```

FFmpeg is required when requesting MP4 remuxing or export metadata; ffprobe is used
by the live download checks. No account or browser cookies are required for the
verified public scenes.

```python
import asyncio
from contextlib import aclosing
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from porn_api import Client, DownloadConfigHLS

async def main():
    runtime = RuntimeConfig()
    runtime.request_delay = 1
    runtime.videos_concurrency = 2
    async with BaseCore(runtime) as core, Client(core) as client:
        video = await client.get_video("https://www.porn.com/scene/208974141")
        print(video.title, video.duration)
        print([(r.width, r.height) for r in await video.get_qualities()])
        await video.download(DownloadConfigHLS(
            quality="worst", path="./", remux=True, return_report=True,
        ))
        async with aclosing(client.search("yoga", pages=1)) as stream:
            async for result in stream:
                summary = result.unwrap()
                print(summary.video_id, summary.title)

if __name__ == "__main__":
    asyncio.run(main())
```

`Client()` owns its default core and closes it through its async context manager
or `await client.close()`. An injected core remains owned by the caller. Every
request and download uses that same backend; response caches, retries, proxy,
locale, timeouts, and cancellation remain configurable per core.

Porn.com includes native HLS scenes and external referrals. Both have usable
scene metadata; only native public unencrypted HLS is downloadable here.
Check `video.is_playable` after loading scene HTML. Referral summaries do not
mean that media is available on Porn.com.

See [Client](reference/client.md), [source loading](guides/source-loading.md),
[downloads](guides/downloading.md), and [supported hosts](supported-platforms.md).
