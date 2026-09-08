---
title: "Error reference — eaf_base_api"
summary: "Identifies documented eaf_base_api API errors, their meanings, and the safe handling behavior."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Error reference"
  - "eaf base Error reference"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Error reference"
  - "BaseScraperError"
  - "ScraperException"
  - "DownloadFailed"
  - "DownloadCancelled"
  - "__cause__"
  - "NetworkRequestError"
  - "HTTPStatusError"
  - "RateLimitError"
  - "RequestRetriesExhausted"
  - "ResourceGone"
  - "AccessDeniedError"
  - "InvalidProxy"
  - "ProxySSLError"
  - "UnknownMediaFieldError"
  - "FieldNotLoadableError"
  - "DataNotLoadedError"
  - "LoaderConfigurationError"
  - "LoaderContractError"
  - "MediaLoadError"
  - "MediaLoadErrors"
  - "PageFetchError"
  - "ItemFetchError"
---

# Error reference — eaf_base_api

Identifies documented eaf_base_api API errors, their meanings, and the safe handling behavior.

Errors live in `base_api.modules.errors`; frequently used version 4 errors are also exported from `base_api`.

**Loader exceptions are wrapped**
An exception raised by one source loader is exposed as `MediaLoadError`; inspect its `original_error` for a site package's `NotFound`, `RegionBlocked`, or similar exception. If several requested sources fail together, `MediaLoadErrors.errors` contains each failure. Helper item failures add one more typed `ItemFetchError` layer whose `original_error` is the media-load error.

Provider request wrappers retain the original error through `raise ... from original_error`. Download wrappers also cover preparation failures, including metadata loading, quality selection, and output path setup. Their `DownloadFailed.__cause__` may therefore be a `MediaLoadError` or `MediaLoadErrors`, rather than a network or file error. Specific availability exceptions remain supported. Existing provider import paths remain valid.

Request, media source, iterator, download, and error-handler failures are logged with URL context and original tracebacks. See [Logging and cleanup](../guides/logging-and-cleanup.md) for application configuration and logging stored exceptions.

## BaseScraperError

Shared base for core scraper errors and, through `ScraperException`, the common provider errors. It is not the base of every low-level exception in this module.

## ScraperException

Base for common provider errors; now inherits `BaseScraperError`. Existing `msg` values remain available. Pornhub's `PornhubAPIError` derives from this class, and its common errors also subclass the corresponding shared error, so both local and shared catches work.

## NotFound

Remote resource was not found. Provider request wrappers translate HTTP 404 into this type, except YouPorn uses `VideoUnavailable`; HQPorner first tries its mobile fallback. XNXX now distinguishes HTTP 404 from access denial.

## NetworkError

A provider request failed due to networking, exhausted request retries, or a non-404 `HTTPStatusError`. The original exception is retained in `__cause__`. Core request methods themselves continue to raise their documented low-level error types.

## BotDetection

A provider wrapper translated `BotProtectionDetected`.

## ProxyError

A provider wrapper translated `InvalidProxy`.

## UnknownNetworkError

A provider wrapper translated `UnknownError`. Unexpected exceptions outside that category are logged and re-raised without reclassification by the request wrapper.

## DownloadFailed

A provider download failed during preparation or transfer. The message includes the video URL and `__cause__` retains the original exception. XFreeHD now raises this exception instead of returning an exception object. Explicit cancellation is not wrapped in this type. Existing base downloader `False` and `DownloadReport` outcomes remain supported; callers must also inspect those results.

## VideoUnavailable

A provider reports unavailable media. HQPorner's `NotAvailable` subclasses this type and remains directly raised when there are no download qualities; Spankbang translates a `ResourceGone` raised during downloading into this type with the original cause.

## NetworkRequestError

Family: HTTP/network

## HTTPStatusError

Family: HTTP/network

## RateLimitError

Family: HTTP/network

## RequestRetriesExhausted

Family: HTTP/network

## ResourceGone

Family: HTTP/network

## AccessDeniedError

Family: HTTP/network

## InvalidProxy

Family: HTTP/network

## ProxySSLError

Family: HTTP/network

## UnknownMediaFieldError

Family: Media fields

## FieldNotLoadableError

Family: Media fields

## DataNotLoadedError

Family: Media fields

## LoaderConfigurationError

Family: Media loaders

## LoaderContractError

Family: Media loaders

## MediaLoadError

Family: Media loaders

## MediaLoadErrors

Family: Media loaders

## PageFetchError

Family: Scrape operations

## ItemFetchError

Family: Scrape operations

## ErrorHandlerError

Family: Scrape operations

## DownloadCancelled

Family: Downloads/playlists. Provider wrappers let an explicit `DownloadCancelled` propagate unchanged, as they do `asyncio.CancelledError`; neither is wrapped as `DownloadFailed`. Some base download paths instead report cancellation with `False` or `DownloadReport.status == "cancelled"`.

## SegmentError

Family: Downloads/playlists

## PlaylistExtractionError

Family: Downloads/playlists

## StateLoadError

Family: Downloads/playlists

## MaxRetriesExceeded

Family: Downloads/playlists

## BotProtectionDetected

Family: Bot challenges

## ChallengeRegexError

Family: Bot challenges

## ChallengeMathError

Family: Bot challenges

## SecurityAbort

Family: Bot challenges

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
