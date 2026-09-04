---
title: "YouPorn API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the YouPorn API."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn setup"
  - "install YouPorn API"
keywords:
  - "YouPorn"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# YouPorn API getting started

Explains how to install, configure, and make a first asynchronous request with the YouPorn API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-youporn
```

For **TS→MP4 remuxing** support (recommended for HLS downloads), install with the optional `av` dependency:

```bash
pip install unofficial-api-for-youporn[av]
```

**Note**
Requires **Python ≥ 3.12**. Version 1.8 uses `eaf_base_api ≥ 4.0.0`, which is installed automatically.

## Quick Start

Wrap YouPorn API calls inside an asynchronous main function:

```python
import asyncio
from youporn_api import Client
from base_api import DownloadConfigHLS, DownloadConfigRAW

async def main():
    client = Client()

    # Fetch a video profile
    video = await client.get_video("https://www.youporn.com/watch/12345/example-video")
    print(video.title)
    print(video.views)

    # Download video via stream-matching HLS/RAW configurations
    hls_config = DownloadConfigHLS(quality="best", path="./downloads")
    raw_config = DownloadConfigRAW(quality="best", path="./downloads")
    await video.download(configuration=hls_config, backup_configuration=raw_config)

asyncio.run(main())
```

## Configuration

Proxy/interface, timeout, request-attempt/delay, bandwidth, cache, and concurrency settings are managed by `RuntimeConfig` inside the shared `BaseCore` package.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from youporn_api import Client

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
- [Errors and troubleshooting — YouPorn API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
