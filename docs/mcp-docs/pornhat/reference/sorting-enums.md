---
title: "Sorting enums — Pornhat API"
summary: "Exact Sort and ProfileSort enum values, new/popular/trending listings, model/channel directory sorting and alphabet groups."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Sorting enums — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "sorting-enums"
---

# Sorting enums — Pornhat API

Import from `pornhat_api.modules.sorting`, or use `from pornhat_api import sorting`.

## Sort

| Member | Value | Video catalog |
| --- | --- | --- |
| `Sort.NEW` | `""` | Root latest-video listing |
| `Sort.POPULAR` | `"popular"` | Popular videos |
| `Sort.TRENDING` | `"trending"` | Trending videos |

Used by `Client.get_videos(sort=...)`. Its default is `Sort.NEW`.

## ProfileSort

| Member | Value | Directory behavior |
| --- | --- | --- |
| `ProfileSort.RANK` | `""` | Default ranked model/channel directory |
| `ProfileSort.VIDEOS` | `"videos"` | Video-count order |
| `ProfileSort.UPDATED` | `"updated"` | Recently updated |
| `ProfileSort.ABC` | `"abc"` | Alphabet groups |

Used by `Client.get_models` and `Client.get_channels`. Their default is `ProfileSort.RANK`.
For `ABC`, `letter` is `"A"`–`"Z"` or `None` for All. Channels also accept `"other"`.
Models have no `other` group. A letter with another sort raises `ValueError`.
No duration, quality, upload-date, tag-sort, or search-sort enums are provided.

See [searching and filtering](../guides/searching-and-filtering.md).
