---
title: "Supported platforms \u2014 Porndoe API"
summary: "Python and dependency requirements for the asynchronous Porndoe video wrapper."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Supported platforms \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "supported-platforms"
---

# Supported platforms — Porndoe API

Requires Python 3.12 or later, `selectolax` and `eaf-base-api>=4.2.2`.
The base engine uses curl-cffi for asynchronous networking. Platform availability
depends on compatible dependency wheels or a working native build environment.
No browser or JavaScript runtime is required by the wrapper.

All network access is asynchronous. Video/profile parsing and shared listing
extraction run in worker threads. Shared BaseCore supplies proxy, timeout,
cookies, cache, pacing and concurrency configuration. See
[base client lifecycle](../eaf-base-api/reference/client-lifecycle.md).

See [getting started](getting-started.md).
