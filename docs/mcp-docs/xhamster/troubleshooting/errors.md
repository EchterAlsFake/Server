---
title: "Errors and troubleshooting — xHamster API"
summary: "Identifies documented xHamster API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster Errors and troubleshooting"
keywords:
  - "xHamster"
  - "Errors and troubleshooting"
  - "NotFound"
  - "NetworkError"
  - "BotDetection"
  - "ProxyError"
  - "UnknownNetworkError"
  - "DownloadFailed"
  - "LoginFailed"
  - "Login failed. Please verify credentials."
---

# Errors and troubleshooting — xHamster API

Identifies documented xHamster API errors, their meanings, and the safe handling behavior.

Source loaders translate request failures into exceptions from `xhamster_api.modules.errors`. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors`. Operations outside media loading, such as login, may still raise package or core exceptions directly.

Request and download failures are logged with the operation, target URL, and full original traceback. Translated exceptions retain the original error in `__cause__`. Download preparation failures (including metadata loading, quality selection, and output path setup) are also wrapped in `DownloadFailed`; inspect its cause when diagnosing a failure. The specific availability exceptions listed below remain supported. An explicit `DownloadCancelled` or `asyncio.CancelledError` propagates without being wrapped in `DownloadFailed`. Base downloader `False` and `DownloadReport` results remain supported; inspect the result as well as handling exceptions.

The common provider errors `NotFound`, `NetworkError`, `BotDetection`, `ProxyError`, `UnknownNetworkError`, and `DownloadFailed` are catchable through `base_api.modules.errors`. They derive from `ScraperException`, which now derives from `BaseScraperError`. Existing provider import paths remain valid.

`LoginFailed` now derives from the shared `ScraperException`; its existing provider import and `msg` attribute remain available.

See [Logging and cleanup](../../eaf-base-api/guides/logging-and-cleanup.md) for application logging setup.

## NotFound

Trigger Cause: Server returned HTTP 404 (e.g. video deleted)

## NetworkError

When Raised: Request failed due to a network error, exhausted request retries, or a non-404 `HTTPStatusError`

## BotDetection

Trigger Cause: Bot-protection challenge block detected

## ProxyError

Trigger Cause: Proxy configuration failed or proxy is down

## UnknownNetworkError

Trigger Cause: Unexpected network errors

## DownloadFailed

When Raised: Download preparation or transfer failed; the video URL is included and `__cause__` retains the original exception

## LoginFailed

Trigger Cause: Sign-in credentials or API challenge failed

```python
from xhamster_api.modules.errors import NotFound, LoginFailed

try:
    account = await client.login(username, password)
except LoginFailed:
    print("Login failed. Please verify credentials.")
```

## Example diagnostic messages

The public page presents these strings as output from its handling example, not as text raised by the library:

- `Login failed. Please verify credentials.` is printed when the example handles `LoginFailed`.

Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.

## Related MCP documents

- [xHamster API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
