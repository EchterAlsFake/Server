---
title: "RetryPolicy and custom error handling — eaf_base_api"
summary: "Identifies documented eaf_base_api API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API RetryPolicy and custom error handling"
  - "eaf base RetryPolicy and custom error handling"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "RetryPolicy and custom error handling"
---

# RetryPolicy and custom error handling — eaf_base_api

Identifies documented eaf_base_api API errors, their meanings, and the safe handling behavior.

`RetryPolicy.max_attempts` includes the first attempt. Without a custom handler, eligible exception classes are selected with `retry_for`; the delay is bounded exponential backoff plus uniformly random jitter.

**Resolved defaults and nested retry budgets**
A standalone `RetryPolicy()` performs one stage attempt. When an `IteratorConfig` leaves `page_retry` or `item_retry` unset, `resolve()` instead creates both policies from the active `RuntimeConfig`; the shipped defaults are four stage attempts, `base_delay=0.5`, `multiplier=2.0`, `max_delay=30.0`, and `jitter=0.5`. A stage attempt may call `BaseCore`, whose separate four-attempt request budget can therefore multiply the number of HTTP calls. Set both layers deliberately for your workload.

```python
from base_api import (
    ErrorAction,
    ErrorMode,
    MediaLoadError,
    MediaLoadErrors,
    ResultOrder,
    RetryPolicy,
    ScrapeErrorContext,
)
from base_api.modules.config import IteratorConfig
from base_api.modules.errors import ResourceGone

def resource_is_gone(error: BaseException) -> bool:
    if isinstance(error, ResourceGone):
        return True
    if isinstance(error, MediaLoadError):
        return resource_is_gone(error.original_error)
    if isinstance(error, MediaLoadErrors):
        return any(resource_is_gone(item) for item in error.errors)
    return False

def handle_page_error(context: ScrapeErrorContext) -> ErrorAction:
    print("page", context.url, context.attempt, context.error)
    return ErrorAction.RETRY

async def handle_item_error(context: ScrapeErrorContext) -> ErrorAction:
    print("item", context.url, context.attempt, context.error)
    if resource_is_gone(context.error):
        return ErrorAction.SKIP
    return ErrorAction.RETRY

iterator_config = IteratorConfig(
    max_page_concurrency=2,
    max_item_concurrency=8,
    order=ResultOrder.ORIGINAL,
    item_retry=RetryPolicy(
        max_attempts=3,
        base_delay=0.5,
        multiplier=2.0,
        max_delay=8.0,
        jitter=0.25,
        retry_for=(Exception,),
    ),
    page_error_handler=handle_page_error,
    item_error_handler=handle_item_error,
    item_error_mode=ErrorMode.YIELD,
    page_error_mode=ErrorMode.SKIP,
    load_specific_sources=("html",),
)
```

Page and item handlers are independent; each receives only failures from its own stage, and either field may be left unset to use automatic policy for that stage. A sync or async handler runs on every failed stage attempt and may return `RETRY`, `RAISE`, `YIELD`, or `SKIP`. An explicit `RETRY` can override `retry_for`, but it cannot exceed the policy's hard limit; on the final attempt it falls back to the configured error mode. Page failures containing a nested HTTP 404 remain terminal. A handler that raises or returns another value produces a fatal `ErrorHandlerError`.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
