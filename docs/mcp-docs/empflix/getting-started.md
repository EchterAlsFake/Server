---
title: "EMPFlix API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the EMPFlix API."
public_url: "https://docs.echteralsfake.me/empflix/"
aliases:
  - "EMPFlix setup"
  - "install EMPFlix API"
keywords:
  - "EMPFlix"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# EMPFlix API getting started

Explains how to install, configure, and make a first asynchronous request with the EMPFlix API.

## Installation

Install the library from PyPI using pip:

```bash
pip install unofficial-api-for-empflix
```

**Note**
Requires **Python ≥ 3.12** and `eaf-base-api>=4.2.5`. The networking engine is installed automatically.

Release **1.0.1** requires `eaf-base-api>=4.2.5` from PyPI. A local base-API checkout is not required.

## Quick Start

All operations are asynchronous and should be executed within an `async` context:

```python
import asyncio
from empflix_api import Client
from base_api import DownloadConfigRAW

async def main():
    client = Client()

    # Fetch a video
    video = await client.get_video("https://www.empflix.com/videos/example-video-12345")

    # Print metadata
    print(f"Title: {video.title}")
    print(f"Duration: {video.length} ({video.duration}s)")
    print(f"Available Qualities: {video.video_qualities}")

    # Download video using progressive MP4 downloader
    config = DownloadConfigRAW(quality="best", path="./downloads")
    success = await video.download(configuration=config)
    print(f"Download complete: {success}")

asyncio.run(main())
```

## Configuration

EMPFlix API uses `eaf_base_api` for networking. Configure proxies, request attempts, timeouts, limits, and headers through a custom `BaseCore`.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference on how to set up `RuntimeConfig` and `BaseCore`.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from empflix_api import Client

config = RuntimeConfig()
config.proxy = "socks5://127.0.0.1:9050"
config.request_attempts = 3

core = BaseCore(configuration=config)
client = Client(core=core)
```

### IteratorConfig, retry policy, and custom scrape errors

Iterator methods accept an `iterator_config` object. By default, the API eagerly loads the `html` source for extracted media items.

```python
from base_api import ErrorAction, ErrorMode, ResultOrder, RetryPolicy, ScrapeErrorContext
from base_api.modules.config import IteratorConfig

async def handle_scrape_error(context: ScrapeErrorContext) -> ErrorAction:
    print(context.stage, context.url, context.error, context.attempt)
    return ErrorAction.RETRY

retry = RetryPolicy(max_attempts=3, base_delay=0.5, multiplier=2, max_delay=8)
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
- [Errors and troubleshooting — EMPFlix API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/empflix/](https://docs.echteralsfake.me/empflix/)
