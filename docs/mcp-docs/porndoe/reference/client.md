---
title: "Client \u2014 Porndoe API"
summary: "Client constructors, resource getters, search, directories, categories and lifecycle for Porndoe."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "Client \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "client"
---

# Client — Porndoe API

`Client(core: BaseCore | None = None)` shares its core with every returned object.
Supports `async with Client() as client` and `await client.close()`.
Only an internally created core is closed by the client.

### get_video

```python
await Client.get_video(url: 'str', load_html: 'bool' = True) -> 'Video'
```

### get_pornstar

```python
await Client.get_pornstar(url: 'str', load_html: 'bool' = True) -> 'Pornstar'
```

### get_channel

```python
await Client.get_channel(url: 'str', load_html: 'bool' = True) -> 'Channel'
```

### search

```python
Client.search(query: 'str', sorting_sort: 'str | Sort' = Sort.Sort_relevance, pages: 'int | str' = 2, iterator_config: 'IteratorConfig | None' = None, start_page: 'int' = 1) -> 'AsyncGenerator[ScrapeResult[Video], None]'
```

### get_videos

```python
Client.get_videos(url: 'str' = 'https://porndoe.com/videos', pages: 'int | str' = 2, sorting_sort: 'str | Sort | None' = None, iterator_config: 'IteratorConfig | None' = None, start_page: 'int' = 1) -> 'AsyncGenerator[ScrapeResult[Video], None]'
```

### get_pornstars

```python
Client.get_pornstars(pages: 'int | str' = 2, sorting_sort: 'str | SortPornstar' = SortPornstar.Sort_famous, iterator_config: 'IteratorConfig | None' = None, gender: 'str | None' = None, country: 'str | None' = None, start_page: 'int' = 1) -> 'AsyncGenerator[ScrapeResult[Pornstar], None]'
```

### get_channels

```python
Client.get_channels(pages: 'int | str' = 2, sorting_sort: 'str | SortChannel' = SortChannel.Sort_ranking, iterator_config: 'IteratorConfig | None' = None, section: 'str' = '', start_page: 'int' = 1) -> 'AsyncGenerator[ScrapeResult[Channel], None]'
```

### get_categories

```python
await Client.get_categories(sorting_sort: 'str | SortCategory' = SortCategory.Sort_popular) -> 'list[Category]'
```

Individual getters return a loaded object unless `load_html=False`.
They require individual `/watch/<hash>`, `/pornstars-profile/<slug>` or
`/channel-profile/<slug>` URLs respectively. Relative site paths work.
Localized Porndoe subdomains are preserved; unrelated hosts are rejected.

`search` sends the query under `keywords` with standard URL encoding.
`get_videos` accepts `/videos`, category, tag, or another public video listing
URL, preserving query filters. `get_pornstars` supports the site's optional
`gender` and country-code routes. Combined filters use `/pornstars/country/<code>`
with a `gender` query parameter, as linked by the site. `get_channels` supports section `""`,
`"exclusive"`, or `"trending"`.

All listings return async iterators of `ScrapeResult` objects. The initial
objects contain listing metadata; full item loading is opt-in via
`IteratorConfig(load_specific_sources=("html",))`. The exact supplied iterator
configuration is honored. `get_categories` is an awaited list of `Category`
objects containing directory metadata.

`pages` is a positive page count or `"all"`; `start_page` is a positive,
one-based start index. The `"all"` option fetches the first requested page to
discover its last-page link. Discovery errors raise directly. Other listing
page/item errors use the configured `ScrapeResult` error policy.

See [sorting](../guides/searching-and-filtering.md) and
[iteration](../guides/iteration-and-results.md).
