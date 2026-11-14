---
title: "Channel \u2014 Porndoe API"
summary: "Channel metadata, paginated videos and related profile listings for Porndoe."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Channel \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "channel"
---

# Channel — Porndoe API

`Channel` is a keyword-only `BaseMedia` dataclass sharing
`BaseChannelPornstar` with the other profile class. Use
`await client.get_channel("https://porndoe.com/channel-profile/<slug>")`.
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
| `website` | `str \| None` | Official website URL from structured metadata. |
| `total_videos_views` | `str \| None` | Total channel video views as a string; directory values may be abbreviated. |

### videos

```python
Channel.videos(pages: 'int | str' = 2, sorting_sort: 'str | Sort | None' = None, iterator_config: 'IteratorConfig | None' = None, start_page: 'int' = 1) -> 'AsyncGenerator[ScrapeResult[Video], None]'
```

### get_pornstars

```python
Channel.get_pornstars(gender: 'str' = 'female', pages: 'int | str' = 2, iterator_config: 'IteratorConfig | None' = None) -> 'AsyncGenerator[ScrapeResult[Pornstar], None]'
```

`videos()` returns `ScrapeResult[Video]` using the shared iterator pipeline.
The profile URL retains its host and filters. `sorting_sort=None` preserves an
existing sort query; passing an enum/string replaces it. `pages=2` fetches two
pages starting at `start_page=1`. `pages="all"` discovers the last page.
Profile counters and rankings are site-reported, not recalculated estimates.

`get_pornstars()` returns `ScrapeResult[Pornstar]` from
`/channel/<slug>/<gender>`. `gender` accepts `female`, `male` or `models`.

See [iteration](../guides/iteration-and-results.md) and [Client](client.md).
