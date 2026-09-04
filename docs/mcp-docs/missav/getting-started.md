---
title: "MissAV API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the MissAV API."
public_url: "https://docs.echteralsfake.me/missav/"
aliases:
  - "MissAV setup"
  - "install MissAV API"
keywords:
  - "MissAV"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# MissAV API getting started

Explains how to install, configure, and make a first asynchronous request with the MissAV API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-missav
```

For **TS→MP4 remuxing** support (recommended for HLS downloads), install with the optional `av` dependency:

```bash
pip install unofficial-api-for-missav[av]
```

**Note**
Requires **Python ≥ 3.12**. Version 2.6 depends on `eaf-base-api>=4.0.0`, which is installed automatically.

## Quick Start

```python
import asyncio
from missav_api import Client, DownloadConfigHLS

async def main():
    client = Client()

    # Fetch video metadata
    video = await client.get_video("https://missav.ws/en/abc-123")
    print(video.title)
    print(video.keywords)

    # Download via HLS
    config = DownloadConfigHLS(quality="best", path="./downloads")
    await video.download(configuration=config)

asyncio.run(main())
```

## Configuration

Proxy/interface, timeout, request-attempt/delay, cache, and concurrency settings are handled via `RuntimeConfig` passed to `BaseCore`.

`Client` sets the core's impersonation profile to `"safari17_2_ios"` before creating its session and installs the headers required by MissAV's current media endpoints. Pass a core whose session has not already been initialized so that profile takes effect.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for details.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from missav_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 4  # Total attempts, including the first request

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

### Iterator, retry, and error policy

`search()` accepts one `IteratorConfig | None`. MissAV's default deliberately limits page concurrency to `1`, eagerly loads `"html"`, and skips terminal page failures. Preserve those settings when customizing it.

```python
from base_api import ErrorAction, ErrorMode, ResultOrder, RetryPolicy, ScrapeErrorContext
from base_api.modules.config import IteratorConfig

async def handle_scrape_error(context: ScrapeErrorContext) -> ErrorAction:
    print(context.stage, context.url, context.attempt, context.error)
    return ErrorAction.RETRY

retry = RetryPolicy(
    max_attempts=3, base_delay=0.5, multiplier=2.0, max_delay=8.0, jitter=0.25
)
iterator_config = IteratorConfig(
    max_page_concurrency=1,
    max_item_concurrency=10,
    load_specific_sources=("html",),
    order=ResultOrder.ORIGINAL,
    page_retry=retry,
    item_retry=retry,
    page_error_mode=ErrorMode.SKIP,
    item_error_mode=ErrorMode.YIELD,
    page_error_handler=handle_scrape_error,
    item_error_handler=handle_scrape_error,
)
```

## Related MCP documents

- [RuntimeConfig — eaf_base_api](../eaf-base-api/configuration/runtime-config.md)
- [IteratorConfig — eaf_base_api](../eaf-base-api/configuration/iterator-config.md)
- [Errors and troubleshooting — MissAV API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/missav/](https://docs.echteralsfake.me/missav/)
