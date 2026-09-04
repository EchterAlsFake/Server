---
title: "xHamster API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster setup"
  - "install xHamster API"
keywords:
  - "xHamster"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# xHamster API getting started

Explains how to install, configure, and make a first asynchronous request with the xHamster API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-xhamster
```

For **TS→MP4 remuxing** support (recommended for HLS streams), install with the `av` dependency:

```bash
pip install unofficial-api-for-xhamster[av]
```

**Note**
Requires **Python ≥ 3.12**. Version 2.6 uses `eaf_base_api ≥ 4.0.0`, which is installed automatically.

## Quick Start

Every operation in this wrapper is asynchronous. Run your code inside an `async` main function:

```python
import asyncio
from xhamster_api import Client
from base_api import DownloadConfigHLS

async def main():
    client = Client()

    # Fetch video metadata
    video = await client.get_video("https://xhamster.com/videos/example-video-123")
    print(video.title)
    print(video.uploader_name)

    # Download video via HLS streaming
    config = DownloadConfigHLS(quality="best", path="./downloads")
    await video.download(configuration=config)

asyncio.run(main())
```

## Configuration

Networking configurations (proxies, timeouts, limits) are defined via `RuntimeConfig` inside the `BaseCore` wrapper.

Please refer to the shared [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from xhamster_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 4
my_config.videos_concurrency = 8
my_config.pages_concurrency = 2

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

## Related MCP documents

- [RuntimeConfig — eaf_base_api](../eaf-base-api/configuration/runtime-config.md)
- [IteratorConfig — eaf_base_api](../eaf-base-api/configuration/iterator-config.md)
- [Errors and troubleshooting — xHamster API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
