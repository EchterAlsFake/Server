---
title: "Errors and troubleshooting — XVideos API"
summary: "Identifies documented XVideos API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Errors and troubleshooting"
keywords:
  - "XVideos"
  - "Errors and troubleshooting"
  - "NotFound"
  - "NetworkError"
  - "BotDetection"
  - "ProxyError"
  - "UnknownNetworkError"
  - "DownloadFailed"
  - "NoLoginCookies"
  - "Video does not exist"
  - "Bot protection triggered — try a proxy"
---

# Errors and troubleshooting — XVideos API

Identifies documented XVideos API errors, their meanings, and the safe handling behavior.

Source loaders translate request failures into exceptions from `xvideos_api.modules.errors`. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors` as shown. Operations outside media loading may still raise package or core exceptions directly.

## NotFound

When Raised: Server returned HTTP 404

## NetworkError

When Raised: General network failure (wraps NetworkRequestError )

## BotDetection

When Raised: Bot protection triggered

## ProxyError

When Raised: Invalid or failing proxy

## UnknownNetworkError

When Raised: Unexpected network errors

## DownloadFailed

When Raised: Download operation failed

## NoLoginCookies

When Raised: Account accessed without cookies set

```python
from base_api import MediaLoadError
from xvideos_api.modules.errors import NotFound, BotDetection

try:
    video = await client.get_video(url)
except MediaLoadError as error:
    if isinstance(error.original_error, NotFound):
        print("Video does not exist")
    elif isinstance(error.original_error, BotDetection):
        print("Bot protection triggered — try a proxy")
    else:
        raise
```

## Example diagnostic messages

The public page presents these strings as output from its handling example, not as text raised by the library:

- `Video does not exist` is printed when the example handles `NotFound`.
- `Bot protection triggered — try a proxy` is printed when the example handles `BotDetection`.

Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.

## Related MCP documents

- [XVideos API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
