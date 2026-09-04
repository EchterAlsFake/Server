---
title: "Errors and troubleshooting — PornHub API"
summary: "Identifies documented PornHub API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Errors and troubleshooting"
keywords:
  - "PornHub"
  - "Errors and troubleshooting"
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
---

# Errors and troubleshooting — PornHub API

Identifies documented PornHub API errors, their meanings, and the safe handling behavior.

Source loaders translate request failures into exceptions from `pornhub_api.modules.errors`. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors` as shown. Operations outside media loading, such as login, may still raise package or core exceptions directly.

## NotFound

When Raised: Server returned HTTP 404

## NetworkError

When Raised: General network request failure (wraps NetworkRequestError )

## BotDetection

When Raised: Bot protection triggered

## ProxyError

When Raised: Invalid or failing proxy

## UnknownNetworkError

When Raised: Unexpected network errors

## DownloadFailed

When Raised: Download operation failed

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
from pornhub_api.modules.errors import NotFound, BotDetection, LoginFailed

try:
    video = await client.get_video(url, load_html=True, load_api=False)
except MediaLoadError as error:
    if isinstance(error.original_error, NotFound):
        print("Video does not exist")
    elif isinstance(error.original_error, BotDetection):
        print("Bypassing bot protection failed")
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

Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
