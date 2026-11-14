---
title: "Errors and troubleshooting — RedGIFs API"
summary: "Loading and download wrappers, HTTP 429 backoff, unstable pagination, raw date/audio discrepancies and strict URL/type validation."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Errors and troubleshooting — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "errors"
  - "429"
  - "rate limits"
  - "MediaLoadError"
  - "RequestRetriesExhausted"
---

# Errors and troubleshooting — RedGIFs API

`redgifs_api.modules.errors` re-exports shared `BotDetection`, `DownloadFailed`,
`NetworkError`, `NotFound`, `ProxyError`, `ResourceGone`, `UnknownNetworkError`, and
`VideoUnavailable`. Original HTTP failures and their causes are preserved; not every
HTTP failure is translated to a provider alias.

`BaseMedia` wraps ordinary loader failures in `MediaLoadError` or `MediaLoadErrors`.
An unavailable resource must not become an empty successful object. Catch the outer
loading wrapper, then inspect the original cause or use `is_resource_gone()`.

```python
from base_api import MediaLoadError, MediaLoadErrors, is_resource_gone

async def fetch_video(client, url):
    try:
        return await client.get_video(url)
    except (MediaLoadError, MediaLoadErrors) as error:
        if is_resource_gone(error):
            print("Resource unavailable:", url)
        raise
```

| Symptom | Meaning / action |
| --- | --- |
| `ValueError` before fetching | Unsupported host/route/identifier, invalid enum, page range or count |
| `DataNotLoadedError` | Explicitly await load_fields/load_sources; API-only title remains unloaded |
| Wrong media type | get_video rejects images; get_image rejects videos, including HTML-only loading |
| HTTP 404 / 410 | Missing/deleted resource; preserve cause, do not fabricate metadata |
| HTTP 401 | Anonymous API session refreshes once through ordinary public authentication |
| HTTP 429 / RequestRetriesExhausted | Respect bounded backend retry/backoff and Retry-After; wait for quotas to permit requests, configure pacing/concurrency |
| HTTP 403 or challenge | Access failure; the provider does not solve CAPTCHA or bypass access protection |
| Missing ID-matched structured data | HTML loader fails rather than merging another video, recommendations or a directory page |
| ScrapeResult error | Unwrap or configure shared iterator policy intentionally; discovery errors raise directly |
| Duplicate IDs and missing upload across pages | Upstream equal-timestamp ordering; no deduplication can recover a genuinely omitted ID |
| Published count exceeds listing | Counts may include images or unavailable records; compare exact intended tabs |
| Null/empty API description overwrites HTML description | Declared API precedence; HTML text stays in page_description |
| Malformed HTML date | Preserved in html_publish_date; use normalized API publish_date |
| has_audio false but audible MP4 | Known legacy API metadata error; inspect files when audio decisions matter |
| Exact rendition missing | get_download_url raises ValueError; download wraps the cause in DownloadFailed |
| Numeric quality / HLS config | Unsupported by this provider; choose actual RAW rendition labels |

The final run's 12 failures were all HTTP 429 after four attempts, despite two-second
per-core pacing. No quota-reset time was established. More immediate full-suite retries
are not evidence of success. Earlier two-page profile completeness failures persist as
an independent upstream ordering issue. See [validation](../guides/live-validation.md).

`asyncio` cancellation and `DownloadCancelled` propagate. Close streams with context
managers and keep an injected core alive for their work. Do not swallow cancellation
inside broad retry loops. Tenacity's `initial` deprecation warning comes from the shared
backend; it is not itself an extraction failure.
