---
title: "Searching and filtering \u2014 Porndoe API"
summary: "Search query encoding, sorting enums, directory filters and category/tag listing URLs."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Searching and filtering \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "searching-and-filtering"
---

# Searching and filtering — Porndoe API

Import enums from `porndoe_api.sorting`. Plain string values also work.
`Sort` applies to videos and profile videos. Search defaults to relevance;
browse/profile pages default to newest when the sort parameter is absent.
`release` explicitly selects newest in search.

```python
from porndoe_api.sorting import Sort
async for result in client.search("eva elfie", sorting_sort=Sort.Sort_most_viewed, pages=1):
    print(result.unwrap().url)
```

### Sort

| Member | Value |
| --- | --- |
| `Sort_relevance` | `` |
| `Sort_newest` | `release` |
| `Sort_most_liked` | `likes` |
| `Sort_longest` | `length` |
| `Sort_most_viewed` | `views` |

### SortPornstar

| Member | Value |
| --- | --- |
| `Sort_famous` | `` |
| `Sort_most_viewed` | `rank` |
| `Sort_most_videos` | `movies` |
| `Sort_trending` | `trending` |

### SortChannel

| Member | Value |
| --- | --- |
| `Sort_ranking` | `` |
| `Sort_name` | `name` |
| `Sort_most_videos` | `movies` |
| `Sort_most_viewed` | `views` |

### SortCategory

| Member | Value |
| --- | --- |
| `Sort_popular` | `` |
| `Sort_name` | `name` |
| `Sort_most_videos` | `movies` |

`get_pornstars(gender="male", country="us", ...)` uses the site's gender and
country routes. `get_channels(section="exclusive", ...)` or `"trending"`
selects that channel directory.

For site filters not represented as dedicated arguments, pass the real
filtered listing URL to `get_videos`. Existing query keys survive pagination.
`get_videos("https://porndoe.com/category/32/hd-videos", pages=1)` and
`get_videos("https://porndoe.com/tag/2240/american-porn", pages=1)` are examples.
Search queries are URL encoded once, preserving spaces, plus signs and ampersands.

See [Client](../reference/client.md).
