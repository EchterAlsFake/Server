---
title: "Errors and troubleshooting \u2014 Porndoe API"
summary: "Media loading failures, HTTP 429 pacing, unavailable videos, lazy fields and source errors."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Errors and troubleshooting \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "errors"
---

# Errors and troubleshooting — Porndoe API

Provider exception imports are available under `porndoe_api.errors`:
`NotFound`, `NetworkError`, `UnknownNetworkError`, `BotDetection`, `ProxyError`,
`DownloadFailed`, and `ScraperException`, re-exported from the base engine.

An individual source failure raises `MediaLoadError` with its original cause.
Inspect `media.source_errors`, `media.source_state("html")`, and the exception
chain. `is_resource_gone(error)` from `base_api` detects missing resources
through wrappers. Missing videos redirected to the general listing are reported
as `NotFound`. Source commits are atomic; a failed player parse does not
leave a Video marked successfully loaded.

`DataNotLoadedError` means a field needs explicit loading:
`await media.load_fields("title")` or `await media.load_sources("html")`.
Listings initially contain only metadata present in the summary. Missing values
after a successful load are `None` or empty collections.

HTTP 429 is a real site rate limit. Use `RuntimeConfig.request_delay = 2` (or
slower), small page counts and limited concurrency. Avoid eager full loads when
only summary metadata is needed. Let a rate limit clear before retrying a
large scrape. The API does not treat 429 responses as empty successful pages.

An invalid host/path raises `ValueError` before a resource getter requests it.
Unknown HTML layouts, unsuccessful service responses, or player responses for
another video fail extraction. Inspect the page/service before changing tests.
Signup entries are not downloadable media; absence of playable variants raises
`DownloadFailed` from `download()`.

Run `pytest` to execute the live site/CDN tests, including a complete MP4 download.
Tests use real network requests without saved HTML responses or network mocks;
network and scraping failures are not silently skipped.
See [iteration](../guides/iteration-and-results.md) and
[getting started](../getting-started.md).
