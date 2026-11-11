---
title: "RedGIFs API getting started"
summary: "Install local RedGIFs API 0.1.0, configure BaseCore and fetch API/HTML metadata using Python 3.12 or newer."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "RedGIFs API getting started"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "installation"
  - "BaseCore"
  - "quickstart"
---

# RedGIFs API getting started

Version **0.1.0**. Distribution: `unofficial-api-for-redgifs`. Import: `redgifs_api`.
Requires Python 3.12+, `eaf-base-api>=4.2.6`, and `selectolax`.

Install from the workspace containing both checkouts before publication:

```sh
pip install -e ./eaf_base_api -e ./unofficial-api-for-redgifs
```

From the provider directory alone, use `pip install .`. Package publication and remote
CI status are not asserted. FFmpeg is not required for direct MP4/JPG transfers;
`ffprobe` is used for live media validation.

```python
import asyncio
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from redgifs_api import Client, DownloadConfigRAW

async def main():
    runtime = RuntimeConfig()
    runtime.request_delay = 2
    runtime.pages_concurrency = 1
    runtime.videos_concurrency = 2
    async with BaseCore(runtime) as core, Client(core) as client:
        video = await client.get_video(
            "https://www.redgifs.com/watch/hotpinkacrobatickitfox",
            load_api=True, load_html=True,
        )
        print(video.title, video.duration, video.tags)
        print(await video.get_qualities())
        await video.download(DownloadConfigRAW(quality="best", path="./"))

if __name__ == "__main__":
    asyncio.run(main())
```

`Client()` owns its core and closes it on context exit or `close()`.
`Client(core)` leaves that core caller-owned; retain both contexts until all object
operations and streams finish. Runtime requests and downloads use the supplied backend.
An ordinary anonymous public session token is reused per client and refreshed once after
HTTP 401. API authorization headers are not copied to CDN requests or global headers.

Videos and images have independent `api` and `html` sources. API loading defaults on;
HTML loading defaults off. Display `title` requires HTML. Users, niches and collections
have an `api` source only. No account, separate Model/Channel, or Gallery class exists.

Validation is incomplete: the final 2026-11-10 run had **38 passed / 12 failed / 0 skipped**,
with all terminal failures caused by HTTP 429. Earlier runs also demonstrated upstream
pagination omissions. Pacing is configurable, not a guarantee that quotas have reset.
See [validation](guides/live-validation.md), [Client](reference/client.md),
[source loading](guides/source-loading.md), and
[shared configuration](../eaf-base-api/configuration/runtime-config.md).
