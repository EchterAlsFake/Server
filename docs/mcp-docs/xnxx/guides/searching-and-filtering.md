---
title: "Search and filtering — XNXX API"
summary: "Explains the documented search, filtering, sorting, and result behavior for the XNXX API."
public_url: "https://docs.echteralsfake.me/xnxx/"
aliases:
  - "XNXX Search and filtering"
keywords:
  - "XNXX"
  - "Search and filtering"
  - "Mode"
  - "Length"
  - "UploadTime"
  - "SearchingQuality"
---

# Search and filtering — XNXX API

Explains the documented search, filtering, sorting, and result behavior for the XNXX API.

XNXX video searches use customized StrEnums for constructing query filters. Import them from `xnxx_api.modules.search_filters`:

```python
from xnxx_api.modules.search_filters import Length, UploadTime, SearchingQuality, Mode

async for result in client.search_videos(
    query="college",
    pages=3,
    mode=Mode.hits,
    length=Length.X_10min_plus,
    searching_quality=SearchingQuality.X_1080p_plus,
    upload_time=UploadTime.month
):
    if result.succeeded:
        video = result.unwrap()
        print(video.title)
```

## Filter Options

## Mode

Enum Member| Path Suffix| Description
---|---|---
`Mode.default`| `""`| Standard relevant sort
`Mode.hits`| `"/hits"`| Sort by total hits / views
`Mode.random`| `"/random"`| Randomized ordering

## Length

Enum Member| Path Suffix| Range
---|---|---
`Length.X_0_10min`| `"/0-10min"`| Under 10 minutes
`Length.X_10min_plus`| `"/10min+"`| 10 minutes and longer
`Length.X_10_20min`| `"/10-20min"`| Between 10 and 20 minutes
`Length.X_20min_plus`| `"/20min+"`| 20 minutes and longer

## UploadTime

Enum Member| Path Suffix| Timeline
---|---|---
`UploadTime.month`| `"/month"`| Uploaded within this month
`UploadTime.year`| `"/year"`| Uploaded within this year

## SearchingQuality

Enum Member| Path Suffix| Target Quality
---|---|---
`SearchingQuality.X_720p`| `"/hd-only"`| HD resolutions (720p)
`SearchingQuality.X_1080p_plus`| `"/fullhd"`| Full HD & UHD (1080p and higher)

## Related MCP documents

- [XNXX API getting started](../getting-started.md)
- [Errors and troubleshooting — XNXX API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xnxx/](https://docs.echteralsfake.me/xnxx/)
