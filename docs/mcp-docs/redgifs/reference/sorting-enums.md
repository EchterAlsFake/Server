---
title: "Sorting enums — RedGIFs API"
summary: "Exact Sort and ProfileSort members, accepted methods and unsupported sorting combinations."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Sorting enums — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "Sort"
  - "ProfileSort"
  - "trending"
  - "latest"
  - "new"
  - "top"
---

# Sorting enums — RedGIFs API

Import from `redgifs_api.modules.sorting` or `redgifs_api.sorting`.
Both enums inherit `StrEnum`; supported literal values are accepted by their methods.

## Sort

| Member | Value | Method |
| --- | --- | --- |
| `Sort.TRENDING` | `trending` | `Client.search()` (default) |
| `Sort.LATEST` | `latest` | `Client.search()` |
| `Sort.TOP` | `top` | `Client.search()` |

## ProfileSort

| Member | Value | Methods |
| --- | --- | --- |
| `ProfileSort.NEW` | `new` | `User.videos()`, `Niche.videos()` (default) |
| `ProfileSort.TOP` | `top` | `User.videos()`, `Niche.videos()` |

`latest` and `new` are not interchangeable. Image search always uses `latest`;
user image streams always use `new`. Creator/niche directories and collection items
expose no sort argument. There are no duration, date, quality, alphabet, top7 or top28
enums. Unknown enum values raise `ValueError` before stream work starts.

Verified-only trending can be empty while latest/top return records; ordering is not
silently changed to work around that site behavior.
