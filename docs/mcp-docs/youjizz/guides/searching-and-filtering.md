---
title: "Searching and filtering \u2014 YouJizz API"
summary: "Listing, Sort, Duration and Phrase controls."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Searching and filtering \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "guides", "searching-and-filtering"]
---

# Searching and filtering — YouJizz API

Use `Client.videos(listing=Listing.POPULAR)` for popular/newest/top/week/month,
trending and HD listings, and `Client.random_videos()` for the random page.
Enums are in `youjizz_api.modules.sorting`.
`Client.search_videos` supports relevance/newest/views/rating/length sorting,
duration ranges, phrase mode, title_only and date_from/date_to calendar dates.
Empty queries raise ValueError. The website disables HD keyword search; use the
separate HD listing rather than assuming a search HD filter works.

```python
from youjizz_api.modules.sorting import Sort
stream = client.search_videos("Leah Gotti", pages=2, sort=Sort.VIEWS)
```

Category/tag listings and the alphabetical pornstar directory are separate APIs;
account management, uploads, favorites and playlists are unsupported.
