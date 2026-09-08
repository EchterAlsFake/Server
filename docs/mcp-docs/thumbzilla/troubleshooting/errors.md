---
title: "Errors and troubleshooting — Thumbzilla API"
summary: "Identifies documented Thumbzilla API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/thumbzilla/"
aliases:
  - "Thumbzilla Errors and troubleshooting"
keywords:
  - "Thumbzilla"
  - "Errors and troubleshooting"
  - "NotFound"
  - "NetworkError"
  - "BotDetection"
  - "ProxyError"
  - "UnknownNetworkError"
  - "DownloadFailed"
  - "This video does not exist!"
  - "Scraper was blocked by anti-bot measures."
---

# Errors and troubleshooting — Thumbzilla API

Identifies documented Thumbzilla API errors, their meanings, and the safe handling behavior.

Source loaders translate request failures into exceptions from `thumbzilla_api.modules.errors`. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors` as shown. Operations outside media loading may still raise package or core exceptions directly.

Request and download failures are logged with the operation, target URL, and full original traceback. Translated exceptions retain the original error in `__cause__`. Download preparation failures (including metadata loading, quality selection, and output path setup) are also wrapped in `DownloadFailed`; inspect its cause when diagnosing a failure. The specific availability exceptions listed below remain supported. An explicit `DownloadCancelled` or `asyncio.CancelledError` propagates without being wrapped in `DownloadFailed`. Base downloader `False` and `DownloadReport` results remain supported; inspect the result as well as handling exceptions.

The common provider errors `NotFound`, `NetworkError`, `BotDetection`, `ProxyError`, `UnknownNetworkError`, and `DownloadFailed` are catchable through `base_api.modules.errors`. They derive from `ScraperException`, which now derives from `BaseScraperError`. Existing provider import paths remain valid.

See [Logging and cleanup](../../eaf-base-api/guides/logging-and-cleanup.md) for application logging setup.

A missing main video container raises `ValueError` instead of returning an empty successful extraction. During iteration, `Helper` logs the page URL and traceback, then applies the page retry/error policy; a terminal failure is a `PageFetchError` when raised or yielded. An existing container with no matching videos can still produce an empty result.

## NotFound

Trigger Cause: Server returned HTTP 404 (e.g. video deleted)

## NetworkError

When Raised: Request failed due to a network error, exhausted request retries, or a non-404 `HTTPStatusError`

## BotDetection

Trigger Cause: Anti-bot challenge block detected

## ProxyError

Trigger Cause: Proxy configuration failed or proxy is down

## UnknownNetworkError

Trigger Cause: Unexpected network errors

## DownloadFailed

When Raised: Download preparation or transfer failed; the video URL is included and `__cause__` retains the original exception

```python
from base_api import MediaLoadError
from thumbzilla_api.modules.errors import NotFound, BotDetection

try:
    video = await client.get_video(url)
except MediaLoadError as error:
    if isinstance(error.original_error, NotFound):
        print("This video does not exist!")
    elif isinstance(error.original_error, BotDetection):
        print("Scraper was blocked by anti-bot measures.")
    else:
        raise
```

## Example diagnostic messages

The public page presents these strings as output from its handling example, not as text raised by the library:

- `This video does not exist!` is printed when the example handles `NotFound`.
- `Scraper was blocked by anti-bot measures.` is printed when the example handles `BotDetection`.

Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.

## Related MCP documents

- [Thumbzilla API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/thumbzilla/](https://docs.echteralsfake.me/thumbzilla/)
