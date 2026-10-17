---
title: "Sorting enums — TNAFlix API"
summary: "Documents Sorting enums behavior, signatures, fields, constraints, and examples for the TNAFlix API."
public_url: "https://docs.echteralsfake.me/tnaflix/"
aliases:
  - "TNAFlix Sorting enums"
keywords:
  - "TNAFlix"
  - "Sorting enums"
---

# Sorting enums — TNAFlix API

Documents Sorting enums behavior, signatures, fields, constraints, and examples for the TNAFlix API.

The search interface accepts sorting options defined in `tnaflix_api.modules.sorting`:

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

- [TNAFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — TNAFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tnaflix/](https://docs.echteralsfake.me/tnaflix/)
