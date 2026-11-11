---
title: "Niche — RedGIFs API"
summary: "Niche classification metadata, detail loading, subscribers and new/top video streams. Symbols: get_niche get_niches niche_id thumbnail_url cover_url video_count raw_metadata."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Niche — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "Niche"
  - "get_niches"
  - "subscribers"
  - "duo-chastity"
---

# Niche — RedGIFs API

Use `await client.get_niche(id_or_niche_url, load_api=True)` or stream
`client.get_niches()`. `Niche` has an `api` source only. Directory cards omit some
metadata, so API loading fetches the actual niche detail endpoint even for directory items.

## Fields

| Field | Type | Source | Meaning |
| --- | --- | --- | --- |
| `url` | `str` | identity | Canonical www watch URL, or canonical profile/niche/collection URL. |
| `core` | `BaseCore` | identity | Shared caller-configurable backend; omitted from to_dict() by default. |
| `niche_id` | `str` | identity | Stable niche slug. |
| `name` | `str \| None` | api | Site display name. |
| `description` | `str \| None` | api | Site profile/niche/collection description, or null when absent. |
| `thumbnail_url` | `str \| None` | api | Thumbnail/profile image URL supplied by the selected source. |
| `cover_url` | `str \| None` | api | Niche cover image URL. |
| `video_count` | `int \| None` | api | Raw niche gifs counter; can include video and image records. |
| `subscribers` | `int \| None` | api | Reported niche subscriber count. |
| `tags` | `list[str] \| None` | api | Site tag names; preserve returned spelling. |
| `preferences` | `list[str] \| None` | api | Niche preference/classification strings. |
| `raw_metadata` | `dict \| None` | api | Original matched API record, preserving additional site fields. |

`url` is a canonical `/niches/<id>` route. Niche `video_count` retains the raw `gifs`
counter and may include image records. The type exposes no owner getter or subscriber
mutation operations.

## videos

```python
def videos(*, pages=1, start_page=1, count=40, sort="new", iterator_config=None): ...
```

Returns `ScrapeStream[Video]`. Ordering is `new` or `top`; it selects the niche video
filter and has no tags, shuffle or image-tab argument. Use [iteration options](../guides/iteration-and-results.md).
The small `duo-chastity` niche was reconciled at five expected/actual IDs across pages
of 2/2/1, including beyond-last behavior.
