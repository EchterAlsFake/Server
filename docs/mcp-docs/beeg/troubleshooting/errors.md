---
title: "Errors and troubleshooting — Beeg API"
summary: "Identifies documented Beeg API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/beeg/"
aliases:
  - "Beeg Errors and troubleshooting"
keywords:
  - "Beeg"
  - "Errors and troubleshooting"
  - "NotFound"
  - "NetworkError"
  - "BotDetection"
  - "ProxyError"
  - "UnknownNetworkError"
  - "DownloadFailed"
  - "This video was not found on Beeg!"
---

# Errors and troubleshooting — Beeg API

Identifies documented Beeg API errors, their meanings, and the safe handling behavior.

Source loaders translate request failures into exceptions from `beeg_api.modules.errors`. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors` as shown. Operations outside media loading may still raise package or core exceptions directly.

## NotFound

Trigger Cause: Server returned HTTP 404 (e.g. video deleted)

## NetworkError

Trigger Cause: Request failed due to network parameters

## BotDetection

Trigger Cause: Bot-protection challenge block detected

## ProxyError

Trigger Cause: Proxy connection failed

## UnknownNetworkError

Trigger Cause: Unexpected network errors

## DownloadFailed

Trigger Cause: HLS segment download operation failed

```python
from base_api import MediaLoadError
from beeg_api.modules.errors import NotFound

try:
    video = await client.get_video(url)
except MediaLoadError as error:
    if isinstance(error.original_error, NotFound):
        print("This video was not found on Beeg!")
    else:
        raise
```

## Example diagnostic messages

The public page presents these strings as output from its handling example, not as text raised by the library:

- `This video was not found on Beeg!` is printed when the example handles `NotFound`.

Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.

## Related MCP documents

- [Beeg API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/beeg/](https://docs.echteralsfake.me/beeg/)
