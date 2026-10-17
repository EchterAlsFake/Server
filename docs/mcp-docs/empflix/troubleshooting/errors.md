---
title: "Errors and troubleshooting — EMPFlix API"
summary: "Identifies documented EMPFlix API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/empflix/"
aliases:
  - "EMPFlix Errors and troubleshooting"
keywords:
  - "EMPFlix"
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

# Errors and troubleshooting — EMPFlix API

Identifies documented EMPFlix API errors, their meanings, and the safe handling behavior.

Source loaders wrap low-level network errors into typed exceptions from `empflix_api.modules.errors`. Media-loading calls expose errors via `base_api.MediaLoadError`.

## NotFound

Trigger Cause: Server returned HTTP 404 (e.g. video or profile removed)

## NetworkError

Trigger Cause: Request failed due to connection error, exhausted retries, or HTTP status error

## BotDetection

Trigger Cause: Cloudflare or anti-bot challenge block encountered

## ProxyError

Trigger Cause: Proxy configuration error or proxy endpoint unavailable

## UnknownNetworkError

Trigger Cause: Unrecognized networking exception

## DownloadFailed

Trigger Cause: Download transfer or preparation failed with full cause retained in __cause__

```python
from base_api import MediaLoadError
from empflix_api.modules.errors import NotFound, BotDetection

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

- [EMPFlix API getting started](../getting-started.md)
- [Error reference — eaf_base_api](../../eaf-base-api/troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/empflix/](https://docs.echteralsfake.me/empflix/)
