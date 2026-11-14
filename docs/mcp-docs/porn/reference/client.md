---
title: "Client — Porn.com API"
summary: "Client constructors, getters, search, pornstars/channels/categories directories, base_url, orientation and resource ownership."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Client — Porn.com API", "Client Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "Client", "get_video", "get_pornstar", "get_channel", "get_category", "get_source", "search", "base_url", "orientation"]
---

# Client — Porn.com API

```python
Client(core: BaseCore | None = None, *,
       base_url: str = "https://www.porn.com",
       orientation: Literal["straight", "gay", "trans"] = "straight")
```

Supports `async with Client() as client` and `await client.close()`. Only an
internally created `BaseCore` is closed by the client. `base_url` is a verified
host URL without a resource path or query. Orientation prefixes apply to search
and directory methods, not to the URLs passed to individual getters.

| Method | Result | Behavior |
|---|---|---|
| `await get_video(url, load_html=True)` | `Video` | Valid `/scene/<numeric-id>[/<slug>]` URL; eager HTML by default. |
| `await get_pornstar(url, load_html=True)` | `Pornstar` | A real `single-pornstar` profile page. |
| `await get_channel(url, load_html=True)` | `Channel` | A real `single-channel` studio profile. |
| `await get_category(url, load_html=True)` | `Category` | Category page or `/gay`/`/trans` directory root. |
| `await get_source(url, load_html=True)` | `Source` | A source-website index such as `/xnxx`. |
| `search(query, *, pages=1, start_page=1, filters=None, iterator_config=None)` | Async `ScrapeResult[Video]` stream | Encoded `sq` search; preserves legitimate redirects to a category. |
| `pornstars(*, pages=1, start_page=1, iterator_config=None)` | Async `ScrapeResult[Pornstar]` stream | `/pornstars` directory. |
| `channels(*, pages=1, start_page=1, iterator_config=None)` | Async `ScrapeResult[Channel]` stream | `/sites` directory. |
| `categories(*, iterator_config=None)` | Async `ScrapeResult[Category]` stream | A–Z `/categories` directory; no page-count argument. |

Getters take absolute URLs on [accepted hosts](../supported-platforms.md);
relative URLs and outbound `/out/...` links are not accepted by `get_video`.
Constructors validate URL identity; HTML loading checks the actual scene ID or
profile type before committing fields. A channel URL does not become a valid
performer object just because it contains videos.

Individual `load_html=False` constructs a deferred object. Listing methods
return directly observed summaries without loading every detail page. Use
`result.unwrap()` before reading an item. `pages` accepts a positive integer or
`"all"`; `start_page` is one-based. `filters` is a [Filters](filters.md) object.

There are no `get_videos`, `get_categories`, `get_channels`, or `get_pornstars`
aliases: directory method names are exactly `categories`, `channels`, and
`pornstars`. No account, playlist, independent Model/User, or JSON video API is
implemented.

See [iteration](../guides/iteration-and-results.md) and [Video](video.md).
