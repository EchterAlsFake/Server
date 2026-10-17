---
title: "Sorting enums — EMPFlix API"
summary: "Documents Sorting enums behavior, signatures, fields, constraints, and examples for the EMPFlix API."
public_url: "https://docs.echteralsfake.me/empflix/"
aliases:
  - "EMPFlix Sorting enums"
keywords:
  - "EMPFlix"
  - "Sorting enums"
---

# Sorting enums — EMPFlix API

Documents Sorting enums behavior, signatures, fields, constraints, and examples for the EMPFlix API.

The search interface accepts sorting options defined in `empflix_api.modules.sorting`:

## Sort (Order)

Enum Member| API String Value| Description
---|---|---
`Sort.RECENT`| `"recent"`| Sort by latest upload date (default)
`Sort.POPULAR`| `"popular"`| Sort by most popular
`Sort.TOP_RATED`| `"top_rated"`| Sort by highest community rating
`Sort.MOST_VIEWED`| `"most_viewed"`| Sort by highest view counts
`Sort.MOST_FAVORITED`| `"most_favorited"`| Sort by most favorited
`Sort.LONGEST`| `"longest"`| Sort by video duration descending

## SortDate (Period)

Enum Member| API String Value| Description
---|---|---
`SortDate.ALL_TIME`| `"all_time"`| All time historical search (default)
`SortDate.TODAY`| `"today"`| Videos uploaded today
`SortDate.THIS_WEEK`| `"this_week"`| Videos uploaded within this week
`SortDate.THIS_MONTH`| `"this_month"`| Videos uploaded within this month

## Related MCP documents

- [EMPFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — EMPFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/empflix/](https://docs.echteralsfake.me/empflix/)
