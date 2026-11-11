---
title: "Iteration and results \u2014 YouJizz API"
summary: "Pagination, bounded concurrency and ScrapeResult streams."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Iteration and results \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "guides", "iteration-and-results"]
---

# Iteration and results — YouJizz API

`pages` is a positive page count or `"all"`; `start_page` is one based.
HTML pagination follows actual Next links, retains filters and detects repeated
pages. Public user uploads use the same 24-ID slices as the website UI.
IteratorConfig controls item concurrency, loading, errors and original/completion
order. HTML discovery is sequential; page concurrency does not prefetch unknown links.

```python
from contextlib import aclosing
from youjizz_api import Client, IteratorConfig

async with Client() as client:
    async with aclosing(client.videos(pages=2, iterator_config=IteratorConfig(order="original"))) as stream:
        async for result in stream:
            video = result.unwrap()
            await video.load_fields("title")
            print(video.video_id, video.title)
```

Close partially consumed generators with contextlib.aclosing.
