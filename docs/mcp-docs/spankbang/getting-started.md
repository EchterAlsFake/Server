---
title: "SpankBang API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the SpankBang API."
public_url: "https://docs.echteralsfake.me/spankbang/"
aliases:
  - "SpankBang setup"
  - "install SpankBang API"
keywords:
  - "SpankBang"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# SpankBang API getting started

Explains how to install, configure, and make a first asynchronous request with the SpankBang API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-spankbang
```

For **TS→MP4 remuxing** support (recommended for HLS downloads), install with the optional `av` dependency:

```bash
pip install unofficial-api-for-spankbang[av]
```

**Note**
Requires **Python ≥ 3.12**. `eaf_base_api ≥ 4.0.0` is installed automatically as a dependency.

## Quick Start

Every method in this API is **asynchronous**. You need to run your code inside an `async` function:

```python
import asyncio
from spankbang_api import Client

async def main():
    client = Client()

    # Fetch a video
    video = await client.get_video("https://spankbang.com/...")

    # Access metadata
    print(video.title)
    print(video.length)
    print(video.video_qualities)

    # Download the video using HLS (default)
    from base_api import DownloadConfigHLS
    config = DownloadConfigHLS(quality="best", path="./downloads")
    await video.download(configuration_hls=config, use_hls=True)

asyncio.run(main())
```

## Configuration

The API uses `eaf_base_api ≥ 4.0.0`. Configure its singular proxy, bounded request attempts, timeouts, and other runtime behavior through the `BaseCore` passed to `Client`.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference on how to set up `RuntimeConfig` and properly integrate it with this API.

The current client sets `RuntimeConfig.http_version` to `"v3"` before initializing its session and installs SpankBang's required Origin/Referer headers. Pass a core whose session has not already been initialized so the HTTP/3 setting takes effect.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from spankbang_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 3

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

## Related MCP documents

- [RuntimeConfig — eaf_base_api](../eaf-base-api/configuration/runtime-config.md)
- [IteratorConfig — eaf_base_api](../eaf-base-api/configuration/iterator-config.md)
- [Errors and troubleshooting — SpankBang API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/spankbang/](https://docs.echteralsfake.me/spankbang/)
