---
title: "Iteration and results \u2014 Porndoe API"
summary: "ScrapeResult iteration, explicit HTML loading, page counts, errors and early stream cleanup."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Iteration and results \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "iteration-and-results"
---

# Iteration and results — Porndoe API

Every listing returns an asynchronous `ScrapeResult` stream from the base
helper. `result.unwrap()` returns the media object or raises its error.
The provider defaults to `IteratorConfig()` with page/item errors yielded and
summary metadata loaded. It does not eagerly fetch every listed video's page.

```python
from contextlib import aclosing
from base_api.modules.config import IteratorConfig

config = IteratorConfig(
    max_page_concurrency=1,
    max_item_concurrency=1,
    load_specific_sources=("html",),
)
async with aclosing(client.search("eva elfie", pages=1, iterator_config=config)) as stream:
    async for result in stream:
        video = result.unwrap()
        print(video.title, video.direct_download_urls)
        break
```

Early consumers should close streams with `aclosing`. The provider closes the
underlying shared helper on generator cleanup. The caller's configuration is
forwarded unchanged, including load fields/sources, error policy, concurrency,
order and retries. Default result order is completion order; choose
`order="original"` for page/card order.

English, German (`de`), French (`fr`), Spanish (`es`), Italian (`it`) and Brazilian
Portuguese (`br`) profile URLs retain their regional host for video listings.
Translated totals and profile labels are supported. Surrounding whitespace in
pasted resource URLs is removed.

`pages=2, start_page=2` fetches pages 2 and 3. `pages="all"` first reads the
requested start page and discovers the last page from the pager, including the
active page number when it has no link. Starting on the final page returns that
page; starting after the end returns no videos. Huge catalogs
can have many thousands of pages; use explicit small counts for interactive
applications. Discovery fetch failures raise directly. Other page/item failures
follow the supplied iterator error policy. No network failure is converted into
a successful empty media object.

See [base iteration](../../eaf-base-api/reference/scrape-stream-and-result.md) and
[errors](../troubleshooting/errors.md).
