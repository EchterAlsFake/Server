---
title: "Errors and troubleshooting — YouPorn API"
summary: "Identifies documented YouPorn API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn Errors and troubleshooting"
keywords:
  - "YouPorn"
  - "Errors and troubleshooting"
  - "VideoUnavailable"
  - "RegionBlocked"
  - "NetworkError"
  - "BotDetection"
  - "ProxyError"
  - "UnknownNetworkError"
  - "DownloadFailed"
  - "This video is blocked in your country! Try a permitted proxy if appropriate."
---

# Errors and troubleshooting — YouPorn API

Identifies documented YouPorn API errors, their meanings, and the safe handling behavior.

Source loaders translate request failures into exceptions from `youporn_api.modules.errors`. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors` as shown. Direct unresolved-field access raises `base_api.DataNotLoadedError`, while operations outside media loading may raise package or core exceptions directly.

Request and download failures are logged with the operation, target URL, and full original traceback. Translated exceptions retain the original error in `__cause__`. Download preparation failures (including metadata loading, quality selection, and output path setup) are also wrapped in `DownloadFailed`; inspect its cause when diagnosing a failure. The specific availability exceptions listed below remain supported. An explicit `DownloadCancelled` or `asyncio.CancelledError` propagates without being wrapped in `DownloadFailed`. Base downloader `False` and `DownloadReport` results remain supported; inspect the result as well as handling exceptions.

The common provider errors `NotFound`, `NetworkError`, `BotDetection`, `ProxyError`, `UnknownNetworkError`, and `DownloadFailed` are catchable through `base_api.modules.errors`. They derive from `ScraperException`, which now derives from `BaseScraperError`. Existing provider import paths remain valid.

The provider-specific `RegionBlocked` and legacy `youporn_api.modules.errors.DataNotLoadedError` now derive from `ScraperException`. The legacy class is distinct from `base_api.DataNotLoadedError`, which is raised for unresolved media fields.

See [Logging and cleanup](../../eaf-base-api/guides/logging-and-cleanup.md) for application logging setup.

## VideoUnavailable

Trigger Cause: The server returned HTTP 404, or the requested video is deleted or unavailable

## RegionBlocked

Trigger Cause: Video content is blocked in user's geographic region

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

```python
from base_api import MediaLoadError
from youporn_api.modules.errors import RegionBlocked

try:
    video = await client.get_video(url)
except MediaLoadError as error:
    if isinstance(error.original_error, RegionBlocked):
        print("This video is blocked in your country! Try a permitted proxy if appropriate.")
    else:
        raise
```

## Example diagnostic messages

The public page presents these strings as output from its handling example, not as text raised by the library:

- `This video is blocked in your country! Try a permitted proxy if appropriate.` is printed when the example handles `RegionBlocked`.

Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.

## Related MCP documents

- [YouPorn API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
