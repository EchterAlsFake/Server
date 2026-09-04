---
title: "Porntrex API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex setup"
  - "install Porntrex API"
keywords:
  - "Porntrex"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# Porntrex API getting started

Explains how to install, configure, and make a first asynchronous request with the Porntrex API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-porntrex
```

**Note**
Requires **Python ≥ 3.12** and `eaf-base-api>=4.0.0`. The compatible networking core is installed automatically.

## Quick Start

All operations are asynchronous and should run within an `async` context:

```python
import asyncio
from porntrex_api import Client
from base_api import DownloadConfigRAW

async def main():
    client = Client()

    # Fetch a video
    video = await client.get_video("https://www.porntrex.com/videos/12345/example-video/")

    # Access metadata
    print(video.title)
    print(video.video_qualities)  # list of available resolutions (e.g., ["360", "480", "720", "1080"])

    # Download video using RAW downloader (direct MP4)
    config = DownloadConfigRAW(quality="best", path="./downloads")
    await video.download(configuration=config)

asyncio.run(main())
```

## Configuration

Porntrex API uses `eaf_base_api` 4.x for networking. You can configure a proxy, timeouts, request attempts, limits, and headers via a custom `BaseCore`.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference on how to set up `RuntimeConfig` and `BaseCore`.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from porntrex_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 4

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

### IteratorConfig, retry policy, and custom scrape errors

Iterator methods take one `iterator_config` object. Keep `load_specific_sources=("html",)` when replacing Porntrex's package defaults so full `Video` metadata is loaded.

```python
from base_api import ErrorAction, ErrorMode, ResultOrder, RetryPolicy, ScrapeErrorContext
from base_api.modules.config import IteratorConfig

async def handle_scrape_error(context: ScrapeErrorContext) -> ErrorAction:
    print(context.stage, context.url, context.error, context.attempt)
    return ErrorAction.RETRY

retry = RetryPolicy(
    max_attempts=3, base_delay=0.5, multiplier=2, max_delay=8, jitter=0.25
)
iterator_config = IteratorConfig(
    max_page_concurrency=2,
    max_item_concurrency=5,
    order=ResultOrder.ORIGINAL,
    load_specific_sources=("html",),
    page_retry=retry,
    item_retry=retry,
    page_error_mode=ErrorMode.SKIP,
    item_error_mode=ErrorMode.YIELD,
    page_error_handler=handle_scrape_error,
    item_error_handler=handle_scrape_error,
)

async for result in client.search("college", iterator_config=iterator_config):
    print(result.unwrap().title if result.succeeded else result.error)
```

## Related MCP documents

- [RuntimeConfig — eaf_base_api](../eaf-base-api/configuration/runtime-config.md)
- [IteratorConfig — eaf_base_api](../eaf-base-api/configuration/iterator-config.md)
- [Errors and troubleshooting — Porntrex API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
