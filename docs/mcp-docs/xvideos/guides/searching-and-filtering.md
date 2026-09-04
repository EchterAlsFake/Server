---
title: "Search and filtering — XVideos API"
summary: "Explains the documented search, filtering, sorting, and result behavior for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Search and filtering"
keywords:
  - "XVideos"
  - "Search and filtering"
---

# Search and filtering — XVideos API

Explains the documented search, filtering, sorting, and result behavior for the XVideos API.

Use the `client.search()` method with the sorting enums for powerful filtering:

```python
from xvideos_api.modules.sorting import Sort, SortDate, SortVideoTime, SortQuality

async for result in client.search(
    query="example search",
    sorting_sort=Sort.Sort_rating,
    sorting_date=SortDate.Sort_month,
    sorting_time=SortVideoTime.Sort_long,
    sort_quality=SortQuality.Sort_1080_plus,
    pages=5,
):
    if result.succeeded:
        video = result.unwrap()
        print(f"{video.title}")
```

## Sorting Enums

### Sort (Relevance)

Enum Value| Description
---|---
`Sort.Sort_relevance`| Most relevant (default)
`Sort.Sort_upload_date`| Newest first
`Sort.Sort_rating`| Highest rated
`Sort.Sort_length`| Longest first
`Sort.Sort_views`| Most viewed
`Sort.Sort_random`| Random order

### SortDate (Time Period)

Enum Value| Description
---|---
`SortDate.Sort_all`| All time (default)
`SortDate.Sort_last_3_days`| Last 3 days
`SortDate.Sort_week`| This week
`SortDate.Sort_month`| This month
`SortDate.Sort_last_3_months`| Last 3 months
`SortDate.Sort_last_6_months`| Last 6 months

### SortVideoTime (Duration)

Enum Value| Description
---|---
`SortVideoTime.Sort_all`| Any duration (default)
`SortVideoTime.Sort_short`| 1–3 minutes
`SortVideoTime.Sort_middle`| 3–10 minutes
`SortVideoTime.Sort_long`| 10+ minutes
`SortVideoTime.Sort_long_10_20min`| 10–20 minutes
`SortVideoTime.Sort_really_long`| 20+ minutes

### SortQuality (Resolution)

Enum Value| Description
---|---
`SortQuality.Sort_all`| Any quality (default)
`SortQuality.Sort_720p`| 720p and above
`SortQuality.Sort_1080_plus`| 1080p and above

## Related MCP documents

- [XVideos API getting started](../getting-started.md)
- [Errors and troubleshooting — XVideos API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
