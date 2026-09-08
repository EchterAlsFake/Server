---
title: "Logging and cleanup — eaf_base_api"
summary: "Configure application-wide logging with URL context, full tracebacks, source locations, and retained exception causes; close the networking core after use."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Logging and cleanup"
  - "eaf base Logging and cleanup"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Logging and cleanup"
  - "configure_app_logging"
  - "traceback"
  - "exc_info"
  - "__cause__"
---

# Logging and cleanup — eaf_base_api

Configure logging once at application startup to capture provider and base API records in the same console or file output.

## Application logging

```python
import logging
from base_api.modules.logger import configure_app_logging

configure_app_logging(log_file="api.log", level=logging.INFO)
```

With no `logger_name`, `configure_app_logging()` configures the root logger. Omit `log_file` for console output only. Log files append by default; `overwrite_file=True` truncates the selected file. The default format includes timestamp, logger name, level, filename, line number, function, and message. Logged exceptions include the original traceback and chained causes.

Provider request and download failures include the requested URL or video URL. Direct media loading also logs the model, source, and URL before raising a loader error. Iterator failures are logged even under `ErrorMode.SKIP` or `ErrorMode.YIELD`; retry messages identify the attempt, and an error-handler failure is logged before raising `ErrorHandlerError`. Segment/download failures include stream or segment URLs and output paths where available.

Provider CLI entry points configure INFO-level console logging automatically and log caught per-URL failures with tracebacks. Library imports do not configure the root logger; in particular, importing Tube8 or Thumbzilla no longer enables root DEBUG logging.

## Logging a caught or stored exception

Use `logger.exception()` inside an `except` block. Do not log only `str(error)`, which omits the traceback. The APIs already log failures at their handling boundaries, so application logging is only needed when adding context or handling another operation.

```python
logger = logging.getLogger(__name__)

try:
    await video.download(configuration=config)
except Exception:
    logger.exception("Application download failed for %s", video.url)
    raise
```

Outside the original `except` block, pass the stored exception explicitly. `exc_info=True` alone cannot recover a traceback from a yielded `ScrapeResult`:

```python
if not result.succeeded:
    error = result.error
    logger.error(
        "Scrape failed for %s: %s", result.url, error,
        exc_info=(type(error), error, error.__traceback__),
    )
```

Ordinary status messages and failures reported only by a boolean or download report have no exception traceback to attach. Explicit cancellation is not wrapped as `DownloadFailed`; callers should still inspect `False` or `DownloadReport.status` when the downloader reports an outcome that way.

## Core logging and cleanup

`core.enable_logging()` configures the core logger specifically. Use the root configuration above when the file should also receive provider and media-loader records. Optional remote logging uses `log_ip` and `log_port` on the core, or `http_ip` and `http_port` on `configure_app_logging()`.

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

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
