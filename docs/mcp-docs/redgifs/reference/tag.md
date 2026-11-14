---
title: "Tag — RedGIFs API"
summary: "Frozen Tag records from get_tags, reported counts and using tag names as search filters. Symbols: get_tags."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Tag — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "Tag"
  - "get_tags"
  - "trending tags"
---

# Tag — RedGIFs API

`Tag` is a frozen, slotted dataclass, not a `BaseMedia` object.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | `str` | Site tag spelling |
| `count` | `int \| None` | Reported record count; nullable if absent |

`await client.get_tags(trending=False)` returns `list[Tag]` from the full directory.
`trending=True` selects the trending directory. Neither result is paginated or wrapped
in `ScrapeResult`. Tags do not have a `.videos()` method or source loader.

```python
async def tagged_results(client):
    tags = await client.get_tags()
    selected = next(tag for tag in tags if tag.name == "Amateur")
    async with client.search(tags=[selected.name], count=5) as results:
        return [result.unwrap() async for result in results]
```

Counts are reported by the site and do not guarantee exhaustive retrievability through
ranked search; search caps and availability remain server-owned.
