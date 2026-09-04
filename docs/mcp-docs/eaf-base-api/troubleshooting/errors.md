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
