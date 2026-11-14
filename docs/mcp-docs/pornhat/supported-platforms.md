---
title: "Supported platforms and hosts — Pornhat API"
summary: "Verified Linux/Python environment, dependency requirements, accepted .com/.one hosts and six locale subdomains."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Supported platforms and hosts — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "supported-platforms"
---

# Supported platforms and hosts — Pornhat API

Requires Python 3.12 or newer. Live validation was performed on Linux x86_64 with
Python 3.15.2, local eaf-base-api 4.2.6, curl-cffi 0.17.0, selectolax 1.0.2, m3u8 6.0.0,
FFmpeg and ffprobe. Other Python versions and platforms have not been live-verified here.

## Accepted hosts

| Host | Response locale / behavior |
| --- | --- |
| `pornhat.com`, `www.pornhat.com` | English; bare host redirects to www |
| `pornhat.one`, `www.pornhat.one` | English alias linked in the site's alternate metadata; bare host redirects to www |
| `de.pornhat.com` | German |
| `fr.pornhat.com` | French |
| `it.pornhat.com` | Italian |
| `es.pornhat.com` | Spanish |
| `pt.pornhat.com` | Portuguese |
| `hi.pornhat.com` | Hindi |

Each host was checked for video ID 806155, duration 991 seconds, the expected response
language, a working three-quality media master, and model ID 22070. Complete downloads
additionally covered `.one` and German hosts. Arbitrary subdomains and mirror domains
are rejected. No other host family has been verified or accepted.

```python
from pornhat_api import Client

async def localized_video():
    async with Client(base_url="https://de.pornhat.com") as client:
        video = await client.get_video(
            "https://de.pornhat.com/video/armani-black-wants-her-husband-s-friend-deep-inside/"
        )
        print(video.language)
```

`base_url` controls constructed listing URLs. Individual getters use the host supplied in
the resource URL. URL normalization keeps that verified host and resource path, enforces
HTTPS, and drops query/fragment; `resolved_url` records a final response URL when available.
Signed media URL queries are separate and preserved during resolution/download.

See [getting started](getting-started.md) and [downloads](guides/downloading.md).
