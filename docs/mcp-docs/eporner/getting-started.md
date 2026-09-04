---
title: "Eporner API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner setup"
  - "install Eporner API"
keywords:
  - "Eporner"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# Eporner API getting started

Explains how to install, configure, and make a first asynchronous request with the Eporner API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-eporner
```

For custom CLI printing support, install with the optional `cli` components:

```bash
pip install unofficial-api-for-eporner[cli]
```

**Note**
Requires **Python ≥ 3.12**. Version 2.4.1 depends on `eaf-base-api>=4.0.0`, which is installed automatically.

## Quick Start

Run your scraping scripts inside an active event loop using `async` context:

```python
import asyncio
from eporner_api import Client, DownloadConfigRAW
from eporner_api.modules.locals import Encoding

async def main():
    client = Client()

    # Retrieve video info
    video = await client.get_video("https://www.eporner.com/video-12345/example-video")
    print(video.title)
    print(video.views)

    # Download video in best quality using H264 encoding
    config = DownloadConfigRAW(quality="best", path="./downloads")
    await video.download(configuration=config, mode=Encoding.mp4_h264)

asyncio.run(main())
```

## Configuration

Adjust timeouts, a proxy or bound interface, request retry/delay settings, cache limits, and iterator concurrency using the shared `RuntimeConfig` passed into `BaseCore`.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from eporner_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 4  # Total attempts, including the first request

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

### Iterator, retry, and error policy

All listing methods accept one `IteratorConfig | None`. If omitted, Eporner eagerly loads both `"api"` and `"html"`, skips terminal page failures, and installs a handler that skips `ResourceGone`/`NotFound` failures (including those nested in media-load errors) while retrying other failures within the resolved budget. A supplied config replaces that complete default.

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
    max_page_concurrency=2,
    max_item_concurrency=10,
    load_specific_sources=("api", "html"),
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
- [Errors and troubleshooting — Eporner API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
