---
title: "Provider Helpers — eaf_base_api"
summary: "Documents the centralized provider request helpers, download error decorators, and configuration utilities in base_api.modules.provider."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Provider Helpers"
  - "eaf base provider"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "fetch_content"
  - "download_errors"
  - "prepare_download_config"
  - "download_hls"
  - "provider"
---

# Provider Helpers — eaf_base_api

Documents centralized request dispatching, download error handling, and configuration normalization helpers in `base_api.modules.provider`.

Introduced in version 4.2.0, these functions establish uniform logging, diagnostic context variables, error translation, and cancellation semantics across all scraper packages.

## Request Helpers

### fetch_content

```python
async def fetch_content(
    core,
    url: str,
    *,
    logger,
    owner=None,
    get_json: bool = False,
    error_types=errors,
    not_found_error=None,
    access_denied_error=None,
) -> str | dict | list
```

Executes a text or JSON fetch using `core.fetch_text(url)` wrapped in contextual logging (`log_context(owner, url)`).

Automatically translates low-level transport errors (`HTTPStatusError`, `NetworkRequestError`, `InvalidProxy`, `BotProtectionDetected`, etc.) into structured provider or shared exceptions (`NotFound`, `NetworkError`, `ProxyError`, `BotDetection`), preserving the original error in `__cause__` and attaching `.url`, `.class_name`, and `.api` metadata.

Explicit cancellations (`DownloadCancelled`) pass through unwrapped.

## Download Helpers

### @download_errors

```python
def download_errors(error_type=errors.DownloadFailed)
```

Decorator for media download methods. Enforces consistent logging, execution context, cancellation pass-through, and error translation:
- Sets contextual logger attributes: `[class=<MediaClass> url=<url>]`.
- If the wrapped download function returns `False`, converts the failure into `error_type("Downloader returned False")`.
- Passes through `DownloadCancelled` and `asyncio.CancelledError` cleanly without error logs.
- Enriches `VideoUnavailable` with `.url`, `.class_name`, and `.api` properties.
- Wraps any other unexpected exception into `error_type` (defaulting to `DownloadFailed`) with diagnostic metadata and chained cause.

### prepare_download_config

```python
def prepare_download_config(configuration, title: str | None)
```

Copies the caller's download configuration object (`DownloadConfigHLS` or `DownloadConfigRAW`) and resolves the output destination path:
- If `configuration.no_title` is `False`, appends `f"{title}.mp4"` to `configuration.path`.
- Preserves user-supplied callbacks, cancellation `stop_event`, and quality options on the copied instance.

### download_hls

```python
async def download_hls(media, configuration) -> bool | DownloadReport
```

Convenience helper for HLS-based media downloads:
1. Loads required `title` and `m3u8_base_url` fields via `await media.load_fields()`.
2. Validates that `m3u8_base_url` is non-empty (raising `DownloadFailed` if missing).
3. Prepares the configuration using `prepare_download_config()`.
4. Dispatches the download via `await media.core.download(configuration=config)`.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Logging and cleanup — eaf_base_api](../guides/logging-and-cleanup.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
