---
title: "Tube8 API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 setup"
  - "install Tube8 API"
keywords:
  - "Tube8"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# Tube8 API getting started

Explains how to install, configure, and make a first asynchronous request with the Tube8 API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-tube8
```

For **TS→MP4 remuxing** support (recommended for HLS downloads), install with the optional `av` dependency:

```bash
pip install unofficial-api-for-tube8[av]
```

**Note**
Requires **Python ≥ 3.12**. Version 1.3 uses `eaf_base_api ≥ 4.0.0`, which is installed automatically.

## Quick Start

```python
import asyncio
from tube8_api import Client
from base_api import DownloadConfigHLS

async def main():
    client = Client()

    # Fetch video metadata
    video = await client.get_video("https://www.tube8.com/porn-video/12345")
    print(video.title)
    print(video.views)

    # Download video via HLS
    config = DownloadConfigHLS(quality="best", path="./downloads")
    await video.download(configuration=config)

asyncio.run(main())
```

## Configuration

Proxy/interface, timeout, request-attempt/delay, cache, and concurrency settings are handled via `RuntimeConfig` passed to `BaseCore`.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for details.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from tube8_api import Client

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
- [Errors and troubleshooting — Tube8 API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
