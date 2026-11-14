---
title: "Searching and filtering — RedGIFs API"
summary: "Video/image/creator searches, exact filter and sort options, tag semantics and verified-only ranking limits."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Searching and filtering — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "search"
  - "search_images"
  - "search_users"
  - "verified"
  - "tags"
---

# Searching and filtering — RedGIFs API

Video search supports query, tag names, `trending`/`latest`/`top`, verified-only filtering
and the common page options. Free text is passed as the site's `query` parameter; no
literal substring assertion or local filter is imposed. Multiple tags are comma-joined.
Use exact returned tag names for classification filters.

```python
from redgifs_api import Client, sorting

async def find_videos():
    async with Client() as client:
        async with client.search(
            query="Amateur", tags=["Amateur"], sort=sorting.Sort.TOP,
            pages=2, start_page=1, count=20,
        ) as results:
            return [result.unwrap() async for result in results]
```

| Entry point | Filters and ordering | Items |
| --- | --- | --- |
| `Client.search()` | query, tags, sort, verified | Video |
| `Client.search_images()` | query, tags; latest ordering | Image |
| `Client.search_users()` | query, verified; no exposed sort/tags | User |
| `User.videos()` | tags, new/top ordering | Video |
| `User.images()` | new ordering; no exposed filters | Image |
| `Niche.videos()` | new/top ordering | Video |
| `Collection.items()` | Stored mixed-media order; no filters | Video or Image |

No upload-date, duration, numeric-resolution, alphabet or account/search-history filters
are exposed. Do not copy filter enums from another provider. Server ranking and caps
can limit accessible results; `pages="all"` means all server-reported remaining pages,
not an unrestricted full-site export. Latest rankings can change during pagination.

Verified-only trending returned zero records in investigation while verified latest/top
were nonempty. The provider preserves the requested sort and genuine empty responses.
HTTP 429 is a failure, not an empty search. The final paced run's search gates remain
blocked by those rate limits; see [validation](live-validation.md).
