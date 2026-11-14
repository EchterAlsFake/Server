---
title: "Category \u2014 Porndoe API"
summary: "Category discovery, available metadata and paginated video browsing."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Category \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "category"
---

# Category — Porndoe API

`await client.get_categories()` returns category objects from the site's
category directory. These contain `name`, `url`, `thumbnail_url`, and
`total_videos` without fetching every category page. A later `html` load reads
the category heading, image metadata, counters and pagination.

| Field | Type | Meaning |
| --- | --- | --- |
| `url` | `str` | Resource page URL, preserving the requested host and filters. |
| `core` | `BaseCore` | Shared BaseCore networking and download backend. |
| `resolved_url` | `str \| None` | Final response URL, when recorded by the shared request helper. |
| `name` | `str \| None` | Profile or category name. |
| `thumbnail_url` | `str \| None` | Poster, profile image, category image, or directory thumbnail URL. |
| `total_videos` | `int \| None` | Total videos reported by the site. |
| `per_page` | `int \| None` | Number of videos displayed on the loaded profile/category page. |
| `total_pages` | `int \| None` | Last page from pagination, or calculated for a single page. |

### videos

```python
Category.videos(pages: 'int | str' = 2, sorting_sort: 'str | Sort | None' = None, iterator_config: 'IteratorConfig | None' = None, start_page: 'int' = 1) -> 'AsyncGenerator[ScrapeResult[Video], None]'
```

```python
categories = await client.get_categories()
async for result in categories[0].videos(pages=1):
    print(result.unwrap().title)
```

Tag pages can be browsed with `client.get_videos(tag_url, pages=1)`.
See [Client](client.md).
