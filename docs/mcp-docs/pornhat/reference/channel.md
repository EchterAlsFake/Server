---
title: "Channel — Pornhat API"
summary: "Channel URLs, lazy HTML metadata fields, identity, counts and complete paginated video streams."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Channel — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "channel"
---

# Channel — Pornhat API

`Channel` inherits the keyword-only `Collection(BaseMedia)` dataclass.
Use `await client.get_channel("https://www.pornhat.com/sites/60-plus-milfs/")`;
pass `load_html=False` to defer all metadata. Absolute `/sites/<slug>/` URLs are required.

This object represents the grouped channel (`dvd_group_id`). A `/paysite/` brand collection is a distinct `Site`; use `video.get_channel()` and `video.get_site()` for the two relationships.

## Fields

All metadata fields below load from `html`. URL/core/resolved URL are transport identity.

| Field | Type | Meaning |
| --- | --- | --- |
| `url` | `str` | Normalized absolute collection URL on a verified host. |
| `core` | `BaseCore` | Shared backend; keep it open for iteration and field loading. |
| `resolved_url` | `str \| None` | Final HTML response URL, when recorded. |
| `name` | `str \| None` | Profile/tag title from setup; paysite collections use the h1 text. |
| `description` | `str \| None` | Page meta description; not an invented profile biography. |
| `thumbnail_url` | `str \| None` | Setup screenshot when supplied; None for observed paysite collections. |
| `object_id` | `str \| None` | Model, grouped-channel, or tag numeric ID as a string; None for paysite collections. |
| `total_videos` | `int \| None` | Exact setup count when supplied; can be zero or None. |
| `total_pages` | `int \| None` | Live last page; 1 for single-page or observed empty collections. |
| `language` | `str \| None` | Response html language. |

## videos / get_videos

```python
def videos(*, pages: int | Literal['all']=1, start_page: int=1, iterator_config: IteratorConfig | None=None) -> ScrapeStream[Video]: ...
```

`get_videos` is an alias of `videos` with the same arguments and return type.
Results are `ScrapeResult[Video]` values, sharing this collection's core. Default iteration
loads each video's HTML. Pass an `IteratorConfig` to select fields/sources, concurrency,
ordering and error handling. `pages` is a positive count or `"all"`, and `start_page` is one based.

```python
from base_api import make_iterator_config

async def list_collection(client):
    collection = await client.get_channel("https://www.pornhat.com/sites/60-plus-milfs/")
    config = make_iterator_config(load_specific_sources=())
    async with collection.videos(pages="all", iterator_config=config) as results:
        async for result in results:
            video = result.unwrap()
            print(video.video_id, video.url)
```

Iteration uses the collection's intended listing region, excluding navigation, ads and other
page regions. There are 59 real cards on observed full profile pages; the library follows
actual numbered pagination rather than calculating offsets from an assumed capacity.
Beyond-last ranges return an empty stream. Known zero-video channels remain valid profiles.
The library does not apply global deduplication across rendered pages.

See [iteration](../guides/iteration-and-results.md),
[Client](client.md), and [source loading](../guides/source-loading.md).
