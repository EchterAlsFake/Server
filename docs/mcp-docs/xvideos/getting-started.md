---
title: "XVideos API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos setup"
  - "install XVideos API"
keywords:
  - "XVideos"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# XVideos API getting started

Explains how to install, configure, and make a first asynchronous request with the XVideos API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-xvideos
```

For **TS → MP4 remuxing** support (recommended), install with the optional `av` dependency:

```bash
pip install unofficial-api-for-xvideos[av]
```

**Note**
Requires **Python ≥ 3.12**. `eaf_base_api ≥ 4.0.0` is installed automatically as a dependency.

## Quick Start

Every method in this API is **asynchronous**. You need to run your code inside an `async` function:

```python
import asyncio
from xvideos_api import Client

async def main():
    client = Client()

    # Fetch a video
    video = await client.get_video("https://www.xvideos.com/video...")

    # Access metadata
    print(video.title)
    print(video.views)
    print(video.likes)

    # Download the video
    from xvideos_api import DownloadConfigHLS
    config = DownloadConfigHLS(quality="best", path="./downloads")
    await video.download(configuration=config)

asyncio.run(main())
```

## Configuration

The API uses `eaf_base_api ≥ 4.0.0`. Pass a custom `BaseCore` to configure its singular proxy, bounded request attempts, timeouts, and other networking behavior.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference on how to set up `RuntimeConfig` and properly integrate it with this API.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from xvideos_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 3

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

## Related MCP documents

- [RuntimeConfig — eaf_base_api](../eaf-base-api/configuration/runtime-config.md)
- [IteratorConfig — eaf_base_api](../eaf-base-api/configuration/iterator-config.md)
- [Errors and troubleshooting — XVideos API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
