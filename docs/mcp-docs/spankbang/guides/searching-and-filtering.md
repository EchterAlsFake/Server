---
title: "Search and filtering — SpankBang API"
summary: "Explains the documented search, filtering, sorting, and result behavior for the SpankBang API."
public_url: "https://docs.echteralsfake.me/spankbang/"
aliases:
  - "SpankBang Search and filtering"
keywords:
  - "SpankBang"
  - "Search and filtering"
  - "filter"
  - "quality"
  - "duration"
  - "date"
---

# Search and filtering — SpankBang API

Explains the documented search, filtering, sorting, and result behavior for the SpankBang API.

Perform advanced searches on SpankBang by passing filter keywords to the `client.search()` generator:

```python
# Search for popular 1080p videos uploaded this week
async for result in client.search(
    query="college",
    filter="popular",
    quality="fhd",     # 1080p resolution
    date="w",           # weekly
    pages=3
):
    if result.succeeded:
        video = result.unwrap()
        print(video.title, video.url)
```

## Filter Parameters Map

## filter

Value| Description
---|---
`"trending"`| Trending videos (Default option)
`"new"`| Most recent videos
`"featured"`| Featured videos
`"popular"`| Most popular videos

## quality

Value| Target Quality
---|---
`"hd"`| High Definition (720p)
`"fhd"`| Full High Definition (1080p)
`"uhd"`| Ultra High Definition (4k resolution)

## duration

Value| Target Range
---|---
`"10"`| Videos longer than 10 minutes
`"20"`| Videos longer than 20 minutes
`"40"`| Videos longer than 40 minutes

## date

Value| Timeline
---|---
`"d"`| Uploaded today
`"w"`| Uploaded this week
`"m"`| Uploaded this month
`"y"`| Uploaded this year

## Related MCP documents

- [SpankBang API getting started](../getting-started.md)
- [Errors and troubleshooting — SpankBang API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/spankbang/](https://docs.echteralsfake.me/spankbang/)
