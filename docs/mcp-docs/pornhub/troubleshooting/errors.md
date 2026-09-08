---
title: "Errors and troubleshooting — PornHub API"
summary: "Identifies documented PornHub API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Errors and troubleshooting"
keywords:
  - "PornHub"
  - "Errors and troubleshooting"
  - "PornhubAPIError"
  - "NotFound"
  - "NetworkError"
  - "BotDetection"
  - "ProxyError"
  - "UnknownNetworkError"
  - "DownloadFailed"
  - "LoginFailed"
  - "ClientAlreadyLogged"
  - "VideoDisabled"
  - "GifPendingReview"
  - "Video does not exist"
  - "Bypassing bot protection failed"
  - "PornHub API error occurred"
---

# Errors and troubleshooting — PornHub API

Identifies documented PornHub API errors, their meanings, and the safe handling behavior.

All custom exceptions inherit from `PornhubAPIError`, which inherits from the shared `ScraperException` and `BaseScraperError`. Source loaders translate request failures into these library exceptions. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors` as shown. Operations outside media loading, such as login, raise package or core exceptions directly.

Request and download failures are logged with the operation, target URL, and full original traceback. Translated exceptions retain the original error in `__cause__`. Download preparation failures (including metadata loading, quality selection, and output path setup) are also wrapped in `DownloadFailed`; inspect its cause when diagnosing a failure. The specific availability exceptions listed below remain supported. An explicit `DownloadCancelled` or `asyncio.CancelledError` propagates without being wrapped in `DownloadFailed`. Base downloader `False` and `DownloadReport` results remain supported; inspect the result as well as handling exceptions.

The common provider errors `NotFound`, `NetworkError`, `BotDetection`, `ProxyError`, `UnknownNetworkError`, and `DownloadFailed` are catchable through `base_api.modules.errors`. They derive from `ScraperException`, which now derives from `BaseScraperError`. Existing provider import paths remain valid.

See [Logging and cleanup](../../eaf-base-api/guides/logging-and-cleanup.md) for application logging setup.

Pornhub retains its own exception classes: each common error also subclasses the corresponding shared error. For example, `pornhub_api.modules.errors.DownloadFailed` can be caught as either `PornhubAPIError` or `base_api.modules.errors.DownloadFailed`.

## PornhubAPIError

When Raised: Base exception class for PornHub API errors; inherits from `ScraperException`

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

## LoginFailed

When Raised: Authentication failed (invalid credentials or token)

## ClientAlreadyLogged

When Raised: Attempted login when already authenticated

## VideoDisabled

When Raised: The video has been disabled by the platform

## GifPendingReview

When Raised: The GIF is still pending review and cannot be accessed

```python
from base_api import MediaLoadError
from pornhub_api.modules.errors import PornhubAPIError, NotFound, BotDetection, LoginFailed

try:
    video = await client.get_video(url, load_html=True, load_api=False)
except MediaLoadError as error:
    if isinstance(error.original_error, NotFound):
        print("Video does not exist")
    elif isinstance(error.original_error, BotDetection):
        print("Bypassing bot protection failed")
    elif isinstance(error.original_error, PornhubAPIError):
        print("PornHub API error occurred")
    else:
        raise

try:
    await client.login()
except LoginFailed as e:
    print(f"Login failed: {e}")
```

## Example diagnostic messages

The public page presents these strings as output from its handling example, not as text raised by the library:

- `Video does not exist` is printed when the example handles `NotFound`.
- `Bypassing bot protection failed` is printed when the example handles `BotDetection`.
- `PornHub API error occurred` is printed when the example handles `PornhubAPIError`.

Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
