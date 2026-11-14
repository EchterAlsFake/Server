---
title: "Collection — RedGIFs API"
summary: "Public collection identity, stored counts, mixed Video/Image streams and beyond-last behavior. Symbols: get_collection collection_id thumbnail_url content_count publish_date raw_metadata Collection.items."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Collection — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "Collection"
  - "items"
  - "content_count"
  - "mixed media"
---

# Collection — RedGIFs API

Use `await client.get_collection(username, collection_id, load_api=True)`.
The getter takes two identity inputs. A user URL may be supplied as the owner, but a
collection URL alone is not a supported getter signature. `user.collections()` streams
this owner's published collections.

## Fields

| Field | Type | Source | Meaning |
| --- | --- | --- | --- |
| `url` | `str` | identity | Canonical www watch URL, or canonical profile/niche/collection URL. |
| `core` | `BaseCore` | identity | Shared caller-configurable backend; omitted from to_dict() by default. |
| `username` | `str` | identity | Canonical lowercase profile owner username. |
| `collection_id` | `str` | identity | Stable folderId; supplied separately to Client.get_collection(). |
| `name` | `str \| None` | api | Site display name. |
| `description` | `str \| None` | api | Site profile/niche/collection description, or null when absent. |
| `thumbnail_url` | `str \| None` | api | Thumbnail/profile image URL supplied by the selected source. |
| `content_count` | `int \| None` | api | Stored contentCount, which may differ from public listing total. |
| `publish_date` | `str \| None` | api | UTC ISO 8601 string normalized from API Unix seconds. |
| `published` | `bool \| None` | api | Site-reported publication flag. |
| `raw_metadata` | `dict \| None` | api | Original matched API record, preserving additional site fields. |

Collections have an `api` loader only. Stored `content_count` is not a promise that
all those records appear in the public item listing; the latter has its own total.

## items

```python
def items(*, pages=1, start_page=1, count=40, iterator_config=None): ...
```

Returns a result stream containing actual typed `Video` and `Image` instances in the
server's mixed-media order. There is no `.videos()` alias, sort, tag or media-type filter
on Collection. Separate boosted/promoted arrays are excluded.

```python
from redgifs_api import Image

async def collection_items(client):
    collection = await client.get_collection("weirdjack", "d7ddef5fb0")
    async with collection.items(pages="all", count=100) as results:
        async for result in results:
            item = result.unwrap()
            print("image" if isinstance(item, Image) else "video", item.video_id)
```

The final live run matched all 246 public records for this example in pages of
100/100/46, including two images on the last page. Stored `content_count` was 258;
the API does not disclose the 12 additional IDs or their absence reasons.

The backend returns HTTP 404 beyond the last collection item page. The provider first
reads page 1 metadata and clamps the range, so a valid beyond-last request yields
nothing while an unavailable collection still raises.
