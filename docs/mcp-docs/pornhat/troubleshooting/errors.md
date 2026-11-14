---
title: "Errors and troubleshooting — Pornhat API"
summary: "URL validation, missing resources, atomic source errors, scrape failures, unknown fields, expiring sources and download stalls."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Errors and troubleshooting — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "errors"
---

# Errors and troubleshooting — Pornhat API

Provider exception imports in `pornhat_api.modules.errors` re-export shared `BotDetection`,
`DownloadFailed`, `NetworkError`, `NotFound`, `ProxyError`, `UnknownNetworkError` and
`VideoUnavailable`. BaseMedia loading wraps ordinary loader failures in `MediaLoadError`,
or `MediaLoadErrors` for multiple sources. Inspect the original cause; catching only the
inner provider error around `get_video()` will miss the loading wrapper.

```python
from base_api import MediaLoadError, MediaLoadErrors, is_resource_gone

async def fetch_video(client, url):
    try:
        return await client.get_video(url)
    except (MediaLoadError, MediaLoadErrors) as error:
        if is_resource_gone(error):
            print("Resource no longer available:", url)
        raise
```

| Symptom | Meaning / action |
| --- | --- |
| `ValueError` on URL construction | Use an absolute URL on a verified host and the correct resource route; arbitrary mirrors and directory URLs are rejected. |
| `ValueError` for pages/letter/sort | Positive integer page options or pages="all" are required; letters require ABC; models have no other group. |
| `DataNotLoadedError` reading a field | Await load_fields or load_sources first; synchronous access does not start requests. |
| Missing video / HTTP 404 | Source loading retains a NotFound cause through shared error wrappers; no empty success object is fabricated. |
| HTTP 403 or access denied | Preserve the error. The library does not bypass protection; check the ordinary route and legitimate access. |
| Missing player, identity mismatch, missing listing block | VideoUnavailable; an unrelated page or incomplete response must not become a valid video/list. |
| Empty search/channel | Valid only when the expected listing block contains its explicit empty-state marker. |
| `ScrapeResult` failure | Call unwrap, or set IteratorConfig error modes/handlers intentionally. Initial pagination discovery errors propagate directly. |
| Expiring player/CDN URL | Try download(config, refresh=True) through ordinary public access. |
| Download stall with many workers | The final suite used max_workers_download=4. An earlier 20-worker HTTP/2 repeat stalled. Configure a caller deadline as needed. |
| TS output named .mp4 | Set remux=True for an MP4 container and install FFmpeg. |
| Tenacity initial deprecation warning | Emitted by the shared backend; the final live suite passed despite these warnings. |

`asyncio` cancellation and the shared `DownloadCancelled` exception propagate; do not swallow
them in broad retry loops. Keep streams and cores scoped with context managers.
Protected, authenticated or unavailable capabilities remain explicit failures.

See [source loading](../guides/source-loading.md), [iteration](../guides/iteration-and-results.md),
and [shared errors](../../eaf-base-api/troubleshooting/errors.md).
