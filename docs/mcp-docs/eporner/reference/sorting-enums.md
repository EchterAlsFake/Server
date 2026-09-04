---
title: "Sorting enums — Eporner API"
summary: "Documents Sorting enums behavior, signatures, fields, constraints, and examples for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner Sorting enums"
keywords:
  - "Eporner"
  - "Sorting enums"
  - "Gay"
  - "Order"
  - "LowQuality"
---

# Sorting enums — Eporner API

Documents Sorting enums behavior, signatures, fields, constraints, and examples for the Eporner API.

Search endpoints accept sorting parameters defined inside `eporner_api.modules.sorting`:

## Gay

Enum Member| API String Value| Filter Result
---|---|---
`Gay.exclude_gay_content`| `"0"`| Exclude gay search listings
`Gay.include_gay_content`| `"1"`| Include gay search listings
`Gay.only_gay_content`| `"2"`| Only show gay search listings

## Order

Enum Member| API String Value| Description
---|---|---
`Order.latest`| `"latest"`| Order by upload date
`Order.longest`| `"longest"`| Order by duration (descending)
`Order.shortest`| `"shortest"`| Order by duration (ascending)
`Order.top_rated`| `"top-rated"`| Order by rating score
`Order.most_popular`| `"most-popular"`| Order by views count
`Order.top_weekly`| `"top-weekly"`| Order by popular weekly trends
`Order.top_monthly`| `"top-monthly"`| Order by popular monthly trends

## LowQuality

Enum Member| API String Value| Filter Description
---|---|---
`LowQuality.exclude_low_quality_content`| `"0"`| Only include high quality video files (HD)
`LowQuality.include_low_quality_content`| `"1"`| Include both low quality (SD) and high quality (HD) video files
`LowQuality.only_low_quality_content`| `"2"`| Only include low quality video files (SD)

## Related MCP documents

- [Eporner API getting started](../getting-started.md)
- [Errors and troubleshooting — Eporner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
