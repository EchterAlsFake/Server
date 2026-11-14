---
title: "Iteration and results — RedGIFs API"
summary: "ScrapeStream lifecycle, ScrapeResult errors, page ranges, source policies, and known upstream duplicate/omission evidence."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Iteration and results — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "ScrapeStream"
  - "ScrapeResult"
  - "pagination"
  - "IteratorConfig"
  - "duplicates"
---

# Iteration and results — RedGIFs API

Search, profile tabs, niche directories/videos and public collections return lazy
`ScrapeStream` objects. Each item is a `ScrapeResult`; call `.unwrap()` to surface errors.
Tag directory getters instead return an awaited plain list.

| Option | Meaning |
| --- | --- |
| `pages=1` | One page, the default |
| `pages=N` | Positive number of pages starting at start_page, clamped to the last page |
| `pages="all"` | All server-reported remaining pages |
| `start_page=1` | Positive one-based requested first page |
| `count=40` | Records requested per page; integer 1–100 |
| `iterator_config=None` | API-loaded objects, original page/card order, raised terminal page/item failures |

The stream first reads page 1 to discover pagination, even for another start page.
Valid beyond-last ranges end cleanly. Collection beyond-last endpoints return HTTP 404;
page-1 discovery distinguishes exhaustion from an unavailable resource. No result-length
heuristic drops a partial final page or invents another page for exact multiples.
Invalid booleans/nonpositive page options and invalid counts raise `ValueError`.

```python
from redgifs_api import make_iterator_config

async def deferred_items(client):
    user = await client.get_user("nickiipeach", load_api=False)
    config = make_iterator_config(
        load_specific_sources=(), order="original",
        page_error_mode="raise", item_error_mode="raise",
        max_page_concurrency=1, max_item_concurrency=2,
    )
    async with user.videos(pages="all", count=40, iterator_config=config) as results:
        async for result in results:
            video = result.unwrap()
            print(video.video_id, video.loaded_sources)
```

Listing video/image cards supply the API loader's seed data, avoiding a detail request
per item. Deferred iteration does not commit those metadata fields until explicitly
loaded. Niche detail loading makes its own API request for omitted directory fields.
An explicit `IteratorConfig` controls sources/fields, ordering, concurrency and terminal
failure policy. For example, `load_specific_sources=(), load_specific_fields=("title",)`
loads HTML titles. The default is API rather than another provider's HTML source.

The shared Helper handles item/page work. Discovery/authentication failures raise
directly; subsequent failures follow iterator policy. Use `async with` or
`await stream.aclose()` when breaking early to cancel pending work. Injected cores must
remain open until all streams and object operations finish. Completion ordering may be
requested explicitly; default ordering preserves the returned page/card sequence.

Separate promoted/boosted arrays are excluded. There is no automatic deduplication,
pinned-card insertion or missing-record manufacture. Server counts do not establish
completeness by themselves.

## Reconciled boundaries and upstream limits

| Example | Expected / actual public IDs | Evidence |
| --- | --- | --- |
| Collection weirdjack/d7ddef5fb0 | 246 / 246 | Final run; 100/100/46, including two images |
| Niche duo-chastity | 5 / 5 | Final run; 2/2/1 |
| User nickiipeach videos | 17 / 17 | Earlier run; six per page, partial final page; plus one image |
| User rubycammilf videos | 4 / 4 | Earlier run; two per page, exact multiple; plus six images |
| User naughtygardengirl videos | 76 / 76 | Earlier run; plus one image versus stored published count 78 |
| User dainty-blossomx2, count=40 | 10 / 10 | Earlier single-page comparison |
| Same user, count=5 or 6 | 10 slots / 9 unique IDs | Earlier failing completeness gates; omitted/repeated IDs |

All ten dainty-blossomx2 uploads share timestamp 1782281354. Equal-time ordering differs
at page boundaries: count 6 repeated `activetiredaustralianfreshwatercrocodile` and omitted
`icyhappyhamadryad`; count 5 did the reverse during diagnosis. These cases remain failing
completeness assertions. A single page of 40 is an observed workaround for this small
profile, not a general guarantee. Quotas block final profile revalidation; fixing rate
limits does not resolve the independently observed unstable ordering.

See [live validation](live-validation.md) and
[shared iterator configuration](../../eaf-base-api/configuration/iterator-config.md).
