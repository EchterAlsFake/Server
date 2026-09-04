---
title: "Errors and troubleshooting — Porntrex API"
summary: "Identifies documented Porntrex API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex Errors and troubleshooting"
keywords:
  - "Porntrex"
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

# Errors and troubleshooting — Porntrex API

Identifies documented Porntrex API errors, their meanings, and the safe handling behavior.

Source loaders translate request failures into exceptions from `porntrex_api.modules.errors`. Calls that load media expose ordinary loader failures through `base_api.MediaLoadError` (or `MediaLoadErrors` for several sources); inspect `original_error`/`errors` as shown. Operations outside media loading may still raise package or core exceptions directly.

## NotFound

Trigger Cause: Server returned HTTP 404 (e.g. video/model deleted)

## NetworkError

Trigger Cause: Request failed due to HTTP connection problems

## BotDetection

Trigger Cause: Bot-protection challenge block detected

## ProxyError

Trigger Cause: Proxy configuration failed or proxy is down

## UnknownNetworkError

Trigger Cause: Unexpected network errors

## DownloadFailed

Trigger Cause: Raw segmented download failed

```python
from base_api import MediaLoadError
from porntrex_api.modules.errors import NotFound, BotDetection

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

- [Porntrex API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
