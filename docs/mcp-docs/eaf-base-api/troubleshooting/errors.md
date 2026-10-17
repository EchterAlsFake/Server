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
  - "NotFound"
  - "NetworkError"
  - "BotDetection"
  - "ProxyError"
  - "UnknownNetworkError"
  - "DownloadFailed"
  - "VideoUnavailable"
  - "NetworkRequestError"
  - "HTTPStatusError"
  - "RateLimitError"
  - "RequestRetriesExhausted"
  - "ResourceGone"
  - "AccessDeniedError"
  - "InvalidProxy"
  - "ProxySSLError"
---

# Error reference — eaf_base_api

Identifies documented eaf_base_api API errors, their meanings, and the safe handling behavior.

Errors live in `base_api.modules.errors`; frequently used version 4 errors are also exported from `base_api`.

The common provider errors derive from `ScraperException`, which now derives from `BaseScraperError`. Catch common failures from `base_api`: `DownloadFailed`, `NetworkError`, `NotFound`, `ProxyError`, `BotDetection`, `VideoUnavailable`, `LoginFailed`, and `RegionBlocked`. Existing provider imports remain valid. Pornhub retains its own classes: its common errors subclass both the corresponding shared type and `PornhubAPIError`, preserving both ways of catching them.

Translated exceptions carry rich diagnostic attributes: `error.url`, `error.class_name`, and `error.api`. Provider request wrappers chain translated exceptions with `raise ... from original_error`, preserving lower-level causes in `__cause__`.

Download operations now raise `DownloadFailed` on failure instead of returning `False`. Download wrappers cover preparation failures (metadata loading, quality selection, output path setup); `DownloadFailed` includes the video URL and retains the original error in `__cause__`. An explicit `DownloadCancelled` or `asyncio.CancelledError` propagates without being wrapped as `DownloadFailed` and without error logs. With `DownloadConfigHLS(return_report=True)`, incomplete or cancelled downloads still return their explicit `DownloadReport`.

**Loader exceptions are wrapped**
An exception raised by one source loader is exposed as `MediaLoadError`; inspect its `original_error` for a site package's `NotFound`, `RegionBlocked`, or similar exception. If several requested sources fail together, `MediaLoadErrors.errors` contains each failure. Helper item failures add one more typed `ItemFetchError` layer whose `original_error` is the media-load error.

## BaseScraperError

Family: Shared provider errors

## ScraperException

Family: Shared provider errors

## NotFound

Family: Shared provider errors

## NetworkError

Family: Shared provider errors

## BotDetection

Family: Shared provider errors

## ProxyError

Family: Shared provider errors

## UnknownNetworkError

Family: Shared provider errors

## DownloadFailed

Family: Shared provider errors

## VideoUnavailable

Family: Shared provider errors

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

Family: Downloads/playlists

## SegmentError

Family: Downloads/playlists

## PlaylistExtractionError

Family: Downloads/playlists

## StateLoadError

Family: Downloads/playlists

## MaxRetriesExceeded

Family: Downloads/playlists

## MetadataWriteError

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
