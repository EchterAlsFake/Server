---
title: "Beeg API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the Beeg API."
public_url: "https://docs.echteralsfake.me/beeg/"
aliases:
  - "Beeg setup"
  - "install Beeg API"
keywords:
  - "Beeg"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# Beeg API getting started

Explains how to install, configure, and make a first asynchronous request with the Beeg API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-beeg
```

For **TS→MP4 remuxing** support (recommended for HLS downloads), install with the optional `av` dependency:

```bash
pip install unofficial-api-for-beeg[av]
```

**Note**
Requires **Python ≥ 3.12**. `eaf_base_api ≥ 4.0.0` is installed automatically as a dependency.

## Quick Start

Every method in this API is **asynchronous**. You need to run your code inside an `async` function:

```python
import asyncio
from beeg_api import Client

async def main():
    client = Client()

    # Fetch a video
    video = await client.get_video("https://beeg.com/1234567")

    # Access metadata
    print(video.title)
    print(video.duration)

    # Download the video
    from base_api import DownloadConfigHLS
    config = DownloadConfigHLS(quality="best", path="./downloads")
    await video.download(configuration=config)

asyncio.run(main())
```

## Configuration

The entire API relies on `eaf_base_api` for its networking. You can configure global settings (proxies, timeouts, etc.) via a custom `BaseCore` passed into the Client.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference on how to set up `RuntimeConfig` and properly integrate it with this API.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from beeg_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 4

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

**eaf_base_api 4**
Version 1.7 uses the v4 request and source-aware media contracts. `RuntimeConfig.proxy` is a single proxy URL (the old `proxies` mapping was removed), and request retries are configured with `request_attempts` plus the `request_retry_*` settings.

## Related MCP documents

- [RuntimeConfig — eaf_base_api](../eaf-base-api/configuration/runtime-config.md)
- [IteratorConfig — eaf_base_api](../eaf-base-api/configuration/iterator-config.md)
- [Errors and troubleshooting — Beeg API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/beeg/](https://docs.echteralsfake.me/beeg/)
