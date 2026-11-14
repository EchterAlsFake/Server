---
title: "Errors and troubleshooting — Bellesa API"
summary: "Handle DataNotLoadedError, MediaLoadError original causes, resource-gone detection, stream errors, DownloadFailed and mobile transport issues."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Errors and troubleshooting — Bellesa API", "Bellesa errors"]
keywords: ["Bellesa", "bellesa_api", "DataNotLoadedError", "MediaLoadError", "MediaLoadErrors", "NotFound", "NetworkError", "DownloadFailed", "VideoUnavailable", "DownloadCancelled"]
---

# Errors and troubleshooting — Bellesa API

Bellesa re-exports shared provider errors through `bellesa_api.modules.errors`; use
shared `base_api` imports for media-loading and iterator contracts.

| Error | Meaning / handling |
|---|---|
| `ValueError` / `TypeError` | Unsupported URL, inconsistent video ID, invalid filter types, bounds, sort or page arguments |
| `DataNotLoadedError` | A lazy field has not been loaded; await `load_fields()`/`load_sources()` |
| `LoaderConfigurationError` | A source does not exist for the model, such as HTML for Channel |
| `MediaLoadError` | One source failed; inspect `original_error` and the cause chain |
| `MediaLoadErrors` | Multiple source failures; inspect `errors` |
| `NotFound` | HTTP 404 or target identity/application data missing; often wrapped by `MediaLoadError` |
| `NetworkError` | Translated request/HTTP transport failure; inspect original causes |
| `BotDetection`, `ProxyError`, `UnknownNetworkError` | Shared translated transport conditions |
| `PageFetchError` / `ItemFetchError` | Terminal scheduler failure, yielded or raised according to iterator policy |
| `VideoUnavailable` | No eligible public video/source or availability failure |
| `DownloadFailed` | Download preparation/transfer failed; `__cause__` retains the underlying failure |
| `DownloadCancelled` / `asyncio.CancelledError` | Cancellation propagates without conversion to DownloadFailed |

```python
from base_api import MediaLoadError, is_resource_gone
from bellesa_api import Client

async def inspect_missing():
    async with Client() as client:
        try:
            await client.get_video("https://www.bellesa.co/videos/999999999")
        except MediaLoadError as error:
            if is_resource_gone(error):
                print("Resource unavailable", error.original_error)
            else:
                raise
```

Do not catch only bare `NotFound` around a source-loading getter: the shared media
contract wraps ordinary loader exceptions. Translation retains causes, URL and context.
The initial pagination request is outside Helper scheduling and can raise a core request
exception directly. Under default iterator policy terminal stage errors raise; under
YIELD policy, inspect every result or call `unwrap()` so failures are not silently ignored.

If a title exists but measured qualities are unresolved, load `media`. Missing HTML-only
canonical metadata requires loading HTML, not another download attempt. A loaded `None`
description is valid on sparse pages. Use rendition dimensions to diagnose source label
mismatches; do not assume Bellesa's 480 label guarantees 480 actual pixels.

Timeouts while travelling, using mobile data, or changing a VPN can originate in the
connection. Preserve the cause/status and use bounded shared retries and configurable
pacing; do not classify a transport timeout as a deleted resource or claim a site outage.
A VPN does not establish that a previous transfer completed. Recheck only unresolved
checks, and avoid repeating already validated media transfers for documentation changes.

No login-cookie, account, or protection-bypass workaround is part of this provider.
See [shared errors](../../eaf-base-api/troubleshooting/errors.md) and
[source loading](../guides/source-loading.md).
