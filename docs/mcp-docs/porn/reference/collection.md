---
title: "Collection — Porn.com API"
summary: "Shared Collection fields and videos signatures inherited by Pornstar, Channel, Category and Source; advertised count semantics."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Collection — Porn.com API", "Collection Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "Collection", "video_count", "profile_id", "info", "videos"]
---

# Collection — Porn.com API

`Collection` is the keyword-only `BaseMedia` base for `Pornstar`, `Channel`,
`Category`, and `Source`. Use the corresponding Client getter to validate the
actual domain type. Its only metadata source is `html`.

| Field | Type | Meaning |
|---|---|---|
| `url` | `str` | Actual profile/category/source URL on a verified host. |
| `core` | `BaseCore` | Shared caller-configured backend. |
| `resolved_url` | `str \| None` | Actual response URL where recorded. |
| `name` | `str \| None` | Target page heading. |
| `description` | `str \| None` | Plain-text biography/description where exposed. |
| `language` | `str \| None` | Response HTML locale. |
| `video_count` | `int \| None` | Advertised total, including positions replaced by native ads where observed. |
| `profile_id` | `str \| None` | Body data-pi entity ID, with zero/missing values represented as None. |
| `info` | `dict[str, str] \| None` | Native localized labels and text values for profile details/statistics. |
| `social_links` | `list[str] \| None` | Observed links in profile information, including an official site where supplied. |

```python
collection.videos(*, pages: int | Literal["all"] = 1,
                  start_page: int = 1, filters: Filters | None = None,
                  iterator_config: IteratorConfig | None = None)
```

Returns an async stream of `ScrapeResult[Video]`, initially containing listing
summaries. `pages` counts requested pages from the one-based `start_page`;
`"all"` follows the complete exposed feed. URL filters survive pagination unless
the caller supplies a replacement `Filters` object. Ads are excluded; real
duplicate/pinned entries and entries blended into the grid retain their order.

`video_count` is the website's advertised count, not `len(unique_ids)`.
The initial implementation reconciled total grid positions exactly after native
ad replacements were accounted for. It does not fabricate results to match a
counter. See [live validation](../guides/live-validation.md).

Native profile `info` retains localized labels rather than silently converting
them into another provider's schema. A verified German heading renders malformed
`ge Videos`; its valid `Gesamtzahl der Videos` statistic is used as a fallback.
Generated biography prose is not used to infer the video count.

See [iteration](../guides/iteration-and-results.md), [filters](filters.md), and
[source loading](../guides/source-loading.md).
