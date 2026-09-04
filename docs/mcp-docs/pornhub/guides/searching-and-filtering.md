---
title: "Search and filtering — PornHub API"
summary: "Explains the documented search, filtering, sorting, and result behavior for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Search and filtering"
keywords:
  - "PornHub"
  - "Search and filtering"
  - "production_type"
  - "sort_by"
  - "duration_min"
  - "duration_max"
  - "category"
  - "search_filter"
  - "period"
---

# Search and filtering — PornHub API

Explains the documented search, filtering, sorting, and result behavior for the PornHub API.

The PornHub API offers three distinct search methods with rich filtering options:

## Video Search Filters

## production_type

Values: "professional" , "homemade"; Description: Filter by content type

## sort_by

Values: "mr" , "mv" , "tr"; Description: Most Recent, Most Viewed, Top Rated

## duration_min

Values: "10" , "20" , "30"; Description: Minimum duration in minutes

## duration_max

Values: "10" , "20" , "30"; Description: Maximum duration in minutes

## GIF Search Filters

## category

Values: "gay" , "transgender"; Description: Category filter (default: straight)

## search_filter

Values: "mr" , "mv" , "tr"; Description: Most Recent, Most Viewed, Top Rated

## HubTraffic API Filters

## category

Values: Any category string; Description: Free-form category filter

## sort_by

Values: "newest" , "mostviewed" , "rating"; Description: Sort order

## period

Values: "weekly" , "monthly" , "alltime"; Description: Time period filter

```python
# Search professional videos, sorted by most viewed
async for result in client.search_videos(
    query="blonde",
    production_type="professional",
    sort_by="mv",
    pages=3
):
    if result.succeeded:
        video = result.unwrap()
        await video.load_sources("html")
        print(video.title)

# Fast search via HubTraffic API
async for result in client.search_hubtraffic(
    query="amateur",
    sort_by="newest",
    period="weekly"
):
    if result.succeeded:
        video = result.unwrap()
        print(video.title, video.views)
```

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
