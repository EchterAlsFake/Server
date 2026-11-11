---
title: "Pornhat API getting started"
summary: "Install Pornhat API 0.1.0, configure BaseCore, and fetch typed lazy video metadata with Python 3.12 or newer."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Pornhat API getting started"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "getting-started"
---

# Pornhat API getting started

Version **0.1.0**. Distribution: `unofficial-api-for-pornhat`. Import: `pornhat_api`.
Requires Python 3.12+ and `eaf-base-api>=4.2.6`, `selectolax`, and `m3u8`.

Install the local checkout before publication:

```sh
pip install ./unofficial-api-for-pornhat
```

When working with the current neighboring backend checkout, install both editable packages:

```sh
pip install -e ./eaf_base_api -e ./unofficial-api-for-pornhat
```

Once published, use `pip install unofficial-api-for-pornhat`.
FFmpeg is needed for MP4 remuxing and metadata tags; ffprobe is used by the live tests.

```python
import asyncio
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from pornhat_api import Client, DownloadConfigHLS

async def main():
    runtime = RuntimeConfig()
    runtime.max_workers_download = 4
    runtime.videos_concurrency = 2
    runtime.pages_concurrency = 2
    async with BaseCore(runtime) as core, Client(core) as client:
        video = await client.get_video("https://www.pornhat.com/video/armani-black-wants-her-husband-s-friend-deep-inside/")
        print(video.title, video.duration, video.views)
        print(await video.get_available_qualities())
        await video.download(DownloadConfigHLS(quality="best", path="./", remux=True))

if __name__ == "__main__":
    asyncio.run(main())
```

Every runtime request and download uses the shared `BaseCore`. `Client()` owns and closes
its own core; `Client(core)` leaves the supplied core open. Use both context managers as above
when injecting a core. Retain the client/core until you finish using returned media objects.

The API exposes videos, model profiles, grouped channels, paysite/brand collections, tags,
search, new/popular/trending video listings, and sortable model/channel directories.
Favorites and history are browser-local. There is no account, playlist or related-player API.

`html` combines matching JSON-LD and scoped page/player data from one HTML request.
`media` resolves public player redirects and depends on HTML. No separate public metadata
API was found; no `api` source or `load_api` argument is exposed.

See [Client](reference/client.md), [Video](reference/video.md),
[source loading](guides/source-loading.md), [downloads](guides/downloading.md),
and [shared configuration](../eaf-base-api/configuration/runtime-config.md).
