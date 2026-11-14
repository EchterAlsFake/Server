---
title: "Pornstar \u2014 Porndoe API"
summary: "Pornstar metadata, paginated videos and related profile listings for Porndoe."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Pornstar \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "pornstar"
---

# Pornstar — Porndoe API

`Pornstar` is a keyword-only `BaseMedia` dataclass sharing
`BaseChannelPornstar` with the other profile class. Use
`await client.get_pornstar("https://porndoe.com/pornstars-profile/<slug>")`.
The `html` loader reads the first profile page with the requested host and
filters; a stale input `page` or fragment does not change that metadata load.

| Field | Type | Meaning |
| --- | --- | --- |
| `url` | `str` | Resource page URL, preserving the requested host and filters. |
| `core` | `BaseCore` | Shared BaseCore networking and download backend. |
| `resolved_url` | `str \| None` | Final response URL, when recorded by the shared request helper. |
| `name` | `str \| None` | Profile or category name. |
| `description` | `str \| None` | Description or plain-text profile biography. |
| `thumbnail_url` | `str \| None` | Poster, profile image, category image, or directory thumbnail URL. |
| `total_videos` | `int \| None` | Total videos reported by the site. |
| `total_pages` | `int \| None` | Last page from pagination, or calculated for a single page. |
| `per_page` | `int \| None` | Number of videos displayed on the loaded profile/category page. |
| `rank` | `int \| None` | Site ranking as an integer. |
| `external_urls` | `list[str] \| None` | External profile/site URLs from sameAs metadata. |
| `age` | `int \| None` | Displayed age as an integer. |
| `country` | `str \| None` | Displayed birth country. |
| `birth_date` | `str \| None` | ISO birth date from structured metadata. |
| `birth_place` | `str \| None` | Birthplace/nationality string reported by the site. |
| `gender` | `str \| None` | Gender code reported by the site. |
| `measurements` | `str \| None` | Displayed body measurements. |
| `ethnicity` | `str \| None` | Displayed ethnicity. |

### videos

```python
Pornstar.videos(pages: 'int | str' = 2, sorting_sort: 'str | Sort | None' = None, iterator_config: 'IteratorConfig | None' = None, start_page: 'int' = 1) -> 'AsyncGenerator[ScrapeResult[Video], None]'
```

### get_channels

```python
Pornstar.get_channels(pages: 'int | str' = 2, iterator_config: 'IteratorConfig | None' = None) -> 'AsyncGenerator[ScrapeResult[Channel], None]'
```

`videos()` returns `ScrapeResult[Video]` using the shared iterator pipeline.
The profile URL retains its host and filters. `sorting_sort=None` preserves an
existing sort query; passing an enum/string replaces it. `pages=2` fetches two
pages starting at `start_page=1`. `pages="all"` discovers the last page.
Profile counters and rankings are site-reported, not recalculated estimates.

`get_channels()` returns `ScrapeResult[Channel]` from
`/pornstar/<slug>/channels`.

See [iteration](../guides/iteration-and-results.md) and [Client](client.md).
