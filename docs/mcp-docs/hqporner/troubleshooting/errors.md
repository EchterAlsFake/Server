---
title: "Errors and troubleshooting — HQPorner API"
summary: "Identifies documented HQPorner API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner Errors and troubleshooting"
keywords:
  - "HQPorner"
  - "Errors and troubleshooting"
  - "InvalidActress"
  - "NotAvailable"
  - "NotFound"
  - "NetworkError"
  - "BotDetection"
  - "ProxyError"
  - "UnknownNetworkError"
  - "DownloadFailed"
  - "Video does not exist"
  - "Bypassing bot protection failed"
---

# Errors and troubleshooting — HQPorner API

Identifies documented HQPorner API errors, their meanings, and the safe handling behavior.

Source loaders translate request failures into exceptions from `hqporner_api.modules.errors`. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors` as shown. Operations outside media loading may still raise package or core exceptions directly.

Request and download failures are logged with the operation, target URL, and full original traceback. Translated exceptions retain the original error in `__cause__`. Download preparation failures (including metadata loading, quality selection, and output path setup) are also wrapped in `DownloadFailed`; inspect its cause when diagnosing a failure. The specific availability exceptions listed below remain supported. An explicit `DownloadCancelled` or `asyncio.CancelledError` propagates without being wrapped in `DownloadFailed`. Base downloader `False` and `DownloadReport` results remain supported; inspect the result as well as handling exceptions.

The common provider errors `NotFound`, `NetworkError`, `BotDetection`, `ProxyError`, `UnknownNetworkError`, and `DownloadFailed` are catchable through `base_api.modules.errors`. They derive from `ScraperException`, which now derives from `BaseScraperError`. Existing provider import paths remain valid.

See [Logging and cleanup](../../eaf-base-api/guides/logging-and-cleanup.md) for application logging setup.

`InvalidActress` derives from `ScraperException`. `NotAvailable` derives from the shared `VideoUnavailable` and is still raised directly when no download qualities are available. Both retain their default messages and accept a custom message.

## InvalidActress

When Raised: The actress name or URL pattern did not match checks

## NotAvailable

When Raised: No download qualities are available; this error subclasses `VideoUnavailable`

## NotFound

When Raised: Server returned HTTP 404

## NetworkError

When Raised: Request failed due to a network error, exhausted request retries, or a non-404 `HTTPStatusError`

## BotDetection

When Raised: Bot protection triggered

## ProxyError

When Raised: Invalid or failing proxy

## UnknownNetworkError

When Raised: Unexpected network errors

## DownloadFailed

When Raised: Download preparation or transfer failed; the video URL is included and `__cause__` retains the original exception

```python
from base_api import MediaLoadError
from hqporner_api.modules.errors import NotFound, BotDetection

try:
    video = await client.get_video(url)
except MediaLoadError as error:
    if isinstance(error.original_error, NotFound):
        print("Video does not exist")
    elif isinstance(error.original_error, BotDetection):
        print("Bypassing bot protection failed")
    else:
        raise
```

## Example diagnostic messages

The public page presents these strings as output from its handling example, not as text raised by the library:

- `Video does not exist` is printed when the example handles `NotFound`.
- `Bypassing bot protection failed` is printed when the example handles `BotDetection`.

Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.

## Related MCP documents

- [HQPorner API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
