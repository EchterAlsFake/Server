---
title: "Request retries — eaf_base_api"
summary: "Documents Request retries behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Request retries"
  - "eaf base Request retries"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Request retries"
---

# Request retries — eaf_base_api

Documents Request retries behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

`RuntimeConfig.request_attempts` includes the first request. Backoff uses `request_retry_initial_delay`, `request_multiplier` as Tenacity's exponential base, `request_retry_max_delay`, and `request_retry_jitter`. Idempotent methods (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`, and `TRACE`) retry network failures plus HTTP 408, 425, 429, and 5xx responses. A 429 response honors `Retry-After` when available.
- POST/PATCH and other non-idempotent operations are attempted once unless `retry_non_idempotent=True` is explicitly safe.
- Non-retryable HTTP failures—including 401/403, 404, 410, and 4xx responses other than 408, 425, and 429—are terminal.
- Exhaustion raises `RequestRetriesExhausted` with `.url`, `.attempts`, and `.last_error`.

**Two separate retry layers**
`RuntimeConfig` controls individual HTTP requests. `RetryPolicy` controls complete page extraction or media-item loading inside `Helper`. When those policies are derived, both layers use `RuntimeConfig.request_multiplier`; avoid multiplying both budgets unnecessarily.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
