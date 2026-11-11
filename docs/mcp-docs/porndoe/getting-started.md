---
title: "Porndoe API getting started"
summary: "Install the Porndoe wrapper, configure BaseCore and make asynchronous requests with Python 3.12 or later."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Porndoe API getting started"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "getting-started"
---

# Porndoe API getting started

Version 1.0.1. Package: `unofficial-api-for-porndoe`. Import: `porndoe_api`.
Requires Python 3.12+ and `eaf-base-api>=4.2.2` with `selectolax`.

Install from PyPI:

```sh
pip install unofficial-api-for-porndoe
```


```python
import asyncio
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from porndoe_api import Client, DownloadConfigRAW

async def main():
    runtime = RuntimeConfig()
    runtime.request_delay = 2
    runtime.videos_concurrency = 1
    runtime.pages_concurrency = 1
    async with BaseCore(runtime) as core, Client(core) as client:
        video = await client.get_video("https://porndoe.com/watch/pd4y7n5e2j8r")
        print(video.title, video.duration, video.video_qualities)
        await video.download(DownloadConfigRAW(quality="best", path="./"))
        async for result in client.search("eva elfie", pages=1):
            item = result.unwrap()
            print(item.title, item.url)

asyncio.run(main())
```

`Client()` creates and owns a default core. Its async context manager and
`close()` close that core. A caller-supplied core remains caller-owned; use a
`BaseCore` context manager as shown above. Every request goes through that core.

Objects inherit `BaseMedia` and use the `html` source. Default individual
getters load that source. `load_html=False` constructs a lazy object.
Call `await media.load_sources("html")` or `await media.load_fields("title")`
before reading unresolved fields; otherwise `DataNotLoadedError` is raised.
Video loading fetches the HTML page and player JSON, keeping changes atomic.
`to_dict()` returns loaded fields for application integration.

Public video catalog coverage includes videos, search, category/tag browsing,
related videos, pornstar/channel directories and profiles, cross-profile
listings, and downloads. Account mutations, photos, blog articles and advertising
services are outside this interface.

See [Client](reference/client.md), [Video](reference/video.md),
[iteration](guides/iteration-and-results.md), and
[base configuration](../eaf-base-api/reference/client-lifecycle.md).
