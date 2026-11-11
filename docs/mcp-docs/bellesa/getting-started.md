---
title: "Bellesa API getting started"
summary: "Install Bellesa API 1.0.0, use Python 3.12+, configure BaseCore ownership, and fetch typed video metadata."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Bellesa API getting started", "Bellesa getting started"]
keywords: ["Bellesa", "bellesa_api", "installation", "quickstart", "BaseCore", "Client"]
---

# Bellesa API getting started

Version **1.0.0**. Distribution: `unofficial-api-for-bellesa`; import: `bellesa_api`.
Requires Python 3.12+, `eaf-base-api[hls]>=4.2.6`, and `selectolax`.

```sh
pip install unofficial-api-for-bellesa
```

From a local checkout, use `pip install .`. When developing against the shared backend
checkout from the workspace root:

```sh
pip install -e ./eaf_base_api -e ./unofficial-api-for-bellesa
```

FFmpeg is needed to remux HLS output to MP4. Direct MP4 transfers use the shared RAW
downloader. No account credentials are required for the public catalog.

```python
import asyncio
from bellesa_api import Client

async def main():
    async with Client() as client:
        video = await client.get_video("https://www.bellesa.co/videos/7054")
        print(video.title, video.duration, video.pornstars)
        await video.load_sources("media")
        print(video.available_qualities)

if __name__ == "__main__":
    asyncio.run(main())
```

`Client()` owns its core and closes it on context exit or `await client.close()`.
`Client(core)` leaves the injected core caller-owned. Keep the core open until all
objects, iterators and downloads using it have finished. Requests, caching, retries,
source loading, iteration and downloads use `eaf-base-api`; session headers and the
caller's download configuration are not mutated by this provider.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from bellesa_api import Client

async def inspect_video():
    runtime = RuntimeConfig()
    runtime.request_delay = 1
    runtime.pages_concurrency = 1
    runtime.videos_concurrency = 2
    async with BaseCore(runtime) as core, Client(core) as client:
        video = await client.get_video("https://bellesa.co/videos/1094")
        print(video.title)
```

See [Client](reference/client.md), [source loading](guides/source-loading.md),
[downloads](guides/downloading.md), and
[shared runtime configuration](../eaf-base-api/configuration/runtime-config.md).
