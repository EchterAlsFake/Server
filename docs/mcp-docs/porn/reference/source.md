---
title: "Source — Porn.com API"
summary: "Source website indexes such as XNXX, source_name/source_url listing provenance and get_source relationships."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Source — Porn.com API", "Source Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "Source", "get_source", "source_name", "source_url", "XNXX"]
---

# Source — Porn.com API

`Source(Collection)` represents the site-wide index for a source website, for
example `https://www.porn.com/xnxx`. It validates HTML body type `single-source`.
It is distinct from a studio [Channel](channel.md).

```python
from contextlib import aclosing
from porn_api import Client

async def browse_source():
    async with Client() as client:
        source = await client.get_source("https://www.porn.com/xnxx")
        print(source.name, source.video_count)
        async with aclosing(source.videos(pages=1)) as stream:
            async for result in stream:
                summary = result.unwrap()
                print(summary.video_id, summary.source_name)
```

The inherited metadata and `.videos(...)` contract are in
[Collection](collection.md). An originating listing card can supply
`Video.source_name`, `source_url`, and its original `link_url`.
`await summary.get_source(load_html=True)` resolves the actual source URL, or
returns `None` when there is no such observation. Direct scene fetching does
not automatically infer source metadata from the title.

Fetching this collection or a referral's metadata does not fetch its external
website. Large source indexes are validated on representative pages; the
initial validation did not enumerate their entire multi-million-entry catalogs.
