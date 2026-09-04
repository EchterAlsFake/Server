---
title: "RuntimeConfig — eaf_base_api"
summary: "Documents RuntimeConfig behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API RuntimeConfig"
  - "eaf base RuntimeConfig"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "RuntimeConfig"
  - "response_cache_size_bytes"
  - "response_cache_ttl"
  - "segment_cache_size_bytes"
  - "segment_cache_ttl"
  - "request_attempts"
  - "request_retry_initial_delay"
  - "request_retry_max_delay"
  - "request_multiplier"
  - "request_retry_jitter"
  - "request_delay"
  - "timeout"
  - "max_bandwidth_mb"
  - "proxy"
  - "proxy_auth"
  - "interface"
  - "http_version"
  - "dns_over_https"
---

# RuntimeConfig — eaf_base_api

Documents RuntimeConfig behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

Create a `RuntimeConfig` for each independently configured `BaseCore`. A process-wide `config` instance remains available as the default, but a dedicated instance avoids unrelated clients changing one another.

## response_cache_size_bytes

Type: int; Default: 32 MiB; Description: Maximum encoded size of cached text responses; set to 0 to disable

## response_cache_ttl

Type: float; Default: 300.0; Description: Text-response lifetime in seconds

## segment_cache_size_bytes

Type: int; Default: 8 MiB; Description: Maximum encoded size of cached HLS segment URL lists

## segment_cache_ttl

Type: float; Default: 300.0; Description: HLS segment-list lifetime in seconds

## request_attempts

Type: int; Default: 4; Description: Total request attempts, including the first call

## request_retry_initial_delay

Type: float; Default: 0.5; Description: Initial exponential retry delay in seconds

## request_retry_max_delay

Type: float; Default: 30.0; Description: Maximum exponential retry delay

## request_multiplier

Type: float; Default: 2.0; Description: Exponential base for BaseCore request backoff and multiplier for derived page/item retry policies

## request_retry_jitter

Type: float; Default: 0.5; Description: Maximum random jitter added to retry delays

## request_delay

Type: int; Default: 0; Description: Minimum delay between requests made by this core

## timeout

Type: int; Default: 20; Description: Default request timeout in seconds

## max_bandwidth_mb

Type: float | None; Default: None; Description: Aggregate download receive limit in MB/s

## proxy

Type: str | None; Default: None; Description: One HTTP, HTTPS, or SOCKS proxy URL

## proxy_auth

Type: str | None; Default: None; Description: Proxy credentials as "username:password"

## interface

Type: str | None; Default: None; Description: Local interface IP address to bind

## http_version

Type: str; Default: "v2"; Description: "v1" , "v2" , or "v3"

## dns_over_https

Type: str | None; Default: None; Description: DNS-over-HTTPS endpoint

## impersonation

Type: str; Default: "chrome"; Description: curl_cffi browser impersonation profile

## custom_ja3

Type: str | None; Default: None; Description: Advanced custom TLS JA3 fingerprint

## verify_ssl

Type: bool; Default: True; Description: Verify TLS certificates

## trust_env

Type: bool; Default: False; Description: Use proxy and CA settings from the environment

## cookies

Type: dict[str, str] | None; Default: None; Description: Initial cookie mapping applied when each new HTTP session is created

## locale

Type: str; Default: "en-US,en;q=0.9"; Description: Default Accept-Language ; changing it can affect site parsers

## max_workers_download

Type: int; Default: 20; Description: HLS download worker count for this core

## videos_concurrency

Type: int; Default: 5; Description: Fallback item concurrency for resolved iterator configs

## pages_concurrency

Type: int; Default: 2; Description: Fallback page concurrency for resolved iterator configs

## When changes take effect

Cache limits/TTLs and the initial locale header are captured when `BaseCore` is constructed. Proxy, interface, TLS, HTTP, DoH, impersonation, cookies, and bandwidth options are captured whenever its session is created. Request budgets, retry delays/multiplier, and request delay are read for each request; HLS timeout/workers are read when a download begins; and omitted `IteratorConfig` values are resolved whenever a new stream is created.

**Applying changed session settings**
`initialize_session()` is idempotent: it creates a session only while `core.session` is `None`. To apply changed session-bound settings such as proxy, cookies, TLS, or interface, call `await core.close()`; the next request, context-manager entry, or explicit `initialize_session()` creates a fresh session from the current configuration.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
