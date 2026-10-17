---
title: "HQPorner API getting started"
summary: "Explains how to install, configure, and make a first asynchronous request with the HQPorner API."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner setup"
  - "install HQPorner API"
keywords:
  - "HQPorner"
  - "pip install"
  - "asyncio"
  - "RuntimeConfig"
  - "BaseCore"
---

# HQPorner API getting started

Explains how to install, configure, and make a first asynchronous request with the HQPorner API.

## Installation

Install from PyPI using pip:

```bash
pip install unofficial-api-for-hqporner
```

For **CLI formatting** support (recommended), install with the optional `cli` dependency:

```bash
pip install unofficial-api-for-hqporner[cli]
```

**Note**
Requires **Python ≥ 3.12**. Version 2.5 depends on `eaf-base-api>=4.0.0`, which is installed automatically.

## Quick Start

Every method in this API is **asynchronous**. You need to run your code inside an `async` function:

```python
import asyncio
from hqporner_api import Client

async def main():
    client = Client()

    # Fetch a video
    video = await client.get_video("https://hqporner.com/hd/...")

    # Access metadata
    print(video.title)
    print(video.length)
    print(video.pornstars)

    # Download the video
    from hqporner_api import DownloadConfigRAW
    config = DownloadConfigRAW(quality="best", path="./downloads")
    await video.download(configuration=config)

asyncio.run(main())
```

## Configuration

The entire API relies on `eaf_base_api` for its networking. Configure one proxy, timeouts, and request attempts through `RuntimeConfig`, or pass a custom `BaseCore` into the Client.

Please refer to the [eaf_base_api Documentation](../eaf-base-api/overview.md) for the complete reference on how to set up `RuntimeConfig` and properly integrate it with this API.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from hqporner_api import Client

my_config = RuntimeConfig()
my_config.proxy = "socks5://127.0.0.1:9050"
my_config.request_attempts = 4  # Total attempts, including the first request

core = BaseCore(configuration=my_config)
client = Client(core=core)
```

### Iterator, retry, and error policy

Every listing method now accepts one `IteratorConfig | None`. HQPorner's default eagerly loads `"html"`, skips terminal page failures, and otherwise resolves concurrency and bounded retries from the core's `RuntimeConfig`.

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
- [Errors and troubleshooting — HQPorner API](troubleshooting/errors.md)
- [Overview — eaf_base_api](../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
