---
title: "Logging and cleanup — eaf_base_api"
summary: "Documents Logging and cleanup behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Logging and cleanup"
  - "eaf base Logging and cleanup"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Logging and cleanup"
---

# Logging and cleanup — eaf_base_api

Documents Logging and cleanup behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

Configure logging once at application startup to capture provider and base API records in the same console or file output:

```python
import logging
from base_api import configure_app_logging, DownloadFailed

configure_app_logging(log_file="api.log", level=logging.INFO)
```

With no `logger_name`, `configure_app_logging()` configures the root logger. Omit `log_file` for console output only. Log files append by default; `overwrite_file=True` truncates the selected file. The default format includes timestamp, logger name, level, filename, line number, function, and message. Logged exceptions include the original traceback and chained causes.

## Contextual Logging (4.2.0)

Every library logger is wrapped in a `ContextLogger` adapter obtained via `get_logger(name, owner=None)`. When operations run inside a `log_context(owner, url)` block, messages are automatically prefixed with `[class=<class_name> url=<url>]`, and the context variables are injected into `LogRecord.class_name` and `LogRecord.url`. Because context is stored in `ContextVar` instances, concurrent downloads and background tasks offloaded via `asyncio.to_thread` keep their log context completely separate.

```text
ERROR xvideos_api.api [class=xvideos_api.api.Video url=https://example.test/video/123] Download failed: disk full
Traceback (most recent call last):
  ...
OSError: disk full
```

Creating a client or core does _not_ attach handlers or change your application's logging configuration. Without application setup, Python's default logging handler prints warnings and errors to stderr.

Provider CLI entry points configure INFO-level console logging automatically and log caught per-URL failures with tracebacks. Library imports do not configure the root logger; importing Tube8 or Thumbzilla no longer enables root DEBUG logging.

## Logging a caught or stored exception

Use `logger.exception()` inside an `except` block. The APIs already log failures at their handling boundaries; add application logging when more context is needed. Outside the original handler, pass the stored exception explicitly:

```python
logger = logging.getLogger(__name__)

try:
    await video.download(configuration=config)
except DownloadFailed as error:
    print(error.api, error.class_name, error.url)
    # The failure and its full traceback have already been logged.
except Exception:
    logger.exception("Application download failed for %s", video.url)
    raise

if not result.succeeded:
    error = result.error
    logger.error(
        "Scrape failed for %s: %s", result.url, error,
        exc_info=(type(error), error, error.__traceback__),
    )
```

`exc_info=True` alone cannot recover a traceback from a stored `ScrapeResult`. Ordinary download failures now raise `DownloadFailed` instead of returning `False`. Explicit cancellation via `stop_event` raises `DownloadCancelled`, and async task cancellation propagates `asyncio.CancelledError` without error logs. With `DownloadConfigHLS(return_report=True)`, incomplete or cancelled downloads still return their explicit `DownloadReport`.

## Core logging and cleanup

`core.enable_logging()` configures the core logger specifically. Use root logging above when the file should also receive provider and media-loader records. Optional remote logging uses `log_ip`/`log_port` on the core or `http_ip`/`http_port` on `configure_app_logging()`.

```python
import logging

core.enable_logging(level=logging.DEBUG)
core.enable_logging(log_file="api.log", level=logging.INFO)
core.enable_logging(
    log_ip="192.168.1.100",
    log_port=8080,
    level=logging.DEBUG,
)

# Always release the curl_cffi connection pool.
await core.close()
```

## Behavior and edge cases

Contextual log messages handle percent-escaped URLs without corrupting printf-style message arguments.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
