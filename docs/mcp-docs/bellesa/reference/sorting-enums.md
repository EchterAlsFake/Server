---
title: "Sort — Bellesa API"
summary: "Sort values RECENT, POPULAR, LONGEST and search RELEVANCE, their request fields and valid use."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Sort — Bellesa API", "Bellesa sorting enums"]
keywords: ["Bellesa", "bellesa_api", "Sort", "RECENT", "POPULAR", "LONGEST", "RELEVANCE", "sorting"]
---

# Sort — Bellesa API

Import `Sort` from `bellesa_api` or `bellesa_api.modules.sorting`.
It is a `StrEnum`; string values are accepted by the same public methods.

| Member | Value | Site order field |
|---|---|---|
| `Sort.RECENT` | `recent` | `posted_on`, descending |
| `Sort.POPULAR` | `popular` | `views`, descending |
| `Sort.LONGEST` | `longest` | `duration`, descending |
| `Sort.RELEVANCE` | `relevance` | `relevance`, descending |

Video/profile/category listings default to RECENT. Search defaults to RELEVANCE.
Use RELEVANCE for search; relevance ordering without a query is not a verified listing
capability. Unknown values raise `ValueError` when converted to `Sort`. These values
are ordering choices, not download quality labels or upload-date filters.

See [search and filters](../guides/searching-and-filtering.md).
