---
title: "Redtube API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the Redtube API."
public_url: "https://docs.echteralsfake.me/redtube/"
aliases:
  - "Redtube setup"
  - "install Redtube API"
keywords:
  - "Redtube"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# Redtube API getting started

Explains how to install, configure, and make a first asynchronous request with the Redtube API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-redtube
```

For **TS→MP4 remuxing** support (recommended for HLS downloads), install with the optional `av` dependency:

```bash
pip install unofficial-api-for-redtube[av]
```

**Note**
Requires **Python ≥ 3.12**. `eaf_base_api ≥ 4.0.0` is installed automatically.

## Quick Start

Every scraper operation is asynchronous. Wrap calls in a running event loop:

```python
import asyncio
from redtube_api import Client
from base_api import DownloadConfigHLS

async def main():
    client = Client()

    # Fetch video metadata
    video = await client.get_video("https://www.redtube.com/12345")
    print(video.title)
    print(video.author_name)

    # Download video via HLS streaming
    config = DownloadConfigHLS(quality="best", path="./downloads")
    await video.download(configuration=config)

asyncio.run(main())
```

## Configuration

Redtube API uses `eaf_base_api ≥ 4.0.0`. Its singular proxy, request attempts, timeouts, and other networking behavior are configured through `RuntimeConfig` passed to `BaseCore`.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for details.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from redtube_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 3

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

## Related MCP documents

- [RuntimeConfig — eaf_base_api](../eaf-base-api/configuration/runtime-config.md)
- [IteratorConfig — eaf_base_api](../eaf-base-api/configuration/iterator-config.md)
- [Errors and troubleshooting — Redtube API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/redtube/](https://docs.echteralsfake.me/redtube/)
