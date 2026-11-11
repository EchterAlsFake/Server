---
title: "Source loading \u2014 YouJizz API"
summary: "Independent API, HTML, comments and deferred metadata."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Source loading \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "guides", "source-loading"]
---

# Source loading — YouJizz API

```python
async with Client() as client:
    video = await client.get_video("30792291", load_api=False, load_html=False)
    print(video.to_dict())
    await video.load_sources("api")
    await video.load_fields("tags")
    await video.load_sources("comments")
```

The thumbnail API provides listing metadata; HTML supplies media encodings and
richer fields. Comments are loaded only when explicitly requested. API-only,
HTML-only, both and deferred modes are independent, with stable field precedence.
Listing results initially contain identity only. IteratorConfig can load selected
sources or fields. Networking, caches, retries and proxies use the supplied BaseCore.
