---
title: "Client — Bellesa API"
summary: "Exact Client getters, typed search, video filters, performer directory, categories, loading defaults, and core ownership. Symbols: Client.close Client.get_video Client.get_performer Client.get_channel Client.get_category Client.get_categories Client.get_videos Client.get_performers Client.search."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Client — Bellesa API", "Bellesa client"]
keywords: ["Bellesa", "bellesa_api", "Client", "get_video", "get_performer", "get_channel", "get_category", "get_categories", "get_videos", "get_performers", "search"]
---

# Client — Bellesa API

`Client(core: BaseCore | None = None)` constructs objects sharing a configurable backend.
An internally created core is closed by `close()` or the async context manager. An
injected core remains caller-owned. The client has no login or account state.

## Object getters

```python
async def get_video(url: str, load_html: bool = False, load_api: bool = True) -> Video: ...
async def get_performer(url: str, load_html: bool = False, load_api: bool = True) -> Performer: ...
async def get_channel(url: str, load_api: bool = True) -> Channel: ...
async def get_category(url: str, load_api: bool = True) -> Category: ...
async def get_categories() -> list[Category]: ...
```

Getters require complete supported URLs, not bare IDs/handles. Video paths are
`/videos/{numeric-id}` or `/videos/{numeric-id}/{title-slug}`; performer, channel and
category routes are `/performers/{handle}`, `/channels/{handle}` and
`/videos/categories/{handle}`. Accepted hosts are `bellesa.co` and `www.bellesa.co`.
Only individual resources are accepted by object getters.

Setting all available source flags false constructs a deferred object. Video and
Performer have independent API/HTML loaders. Channel and Category have API-only
metadata. `get_categories()` is an awaited list of loaded categories, not a stream.

## get_videos

```python
def get_videos(*, sort=Sort.RECENT, categories=(), channels=(), performers=(), tags=(),
               min_duration: int | None = None, max_duration: int | None = None,
               pages=1, start_page=1, iterator_config=None) -> ScrapeStream[Video]: ...
```

Filters are sequences of handles/tags, for example `channels=["zero-to-hero"]`, not
individual strings or profile URLs. Duration bounds are nonnegative integer **seconds**;
when both are given, `min_duration <= max_duration` is required. Provider/performer
multiselects use the site's OR filter. Category/tag combinations retain site semantics.
Use recent, popular or longest ordering. See [filters](../guides/searching-and-filtering.md).

## get_performers

```python
def get_performers(*, gender="female", pages=1, start_page=1,
                   iterator_config=None) -> ScrapeStream[Performer]: ...
```

`gender` is `"female"`, `"male"` or `"all"`. The directory orders by the site's video
count descending and has 12 items per page. Profile metadata is loaded through API by
default. It is distinct from `Performer.videos()`, which lists videos at 9 per page.

## search

```python
def search(query: str, *, kind="video", sort=Sort.RELEVANCE,
           pages=1, start_page=1, iterator_config=None) -> ScrapeStream[Video | Performer | Channel]: ...
```

The trimmed query must have at least three characters. `kind` selects `"video"`,
`"performer"`, or `"channel"`; results are the corresponding typed objects. Searches use
the site's search endpoint, not local substring matching. Supports relevance, recent,
longest and popular ordering; exact ranking and matching belong to the site. Search
pages contain up to 24 items. There is no separate `search_channels()` method.

## Stream defaults

All listing methods return `ScrapeStream` and accept a positive page count or
`pages="all"`, positive one-based `start_page`, and optional `IteratorConfig`. Defaults
load the `api` source, preserve original ordering, and raise terminal page/item errors.
An explicitly provided configuration replaces those defaults. The initial pagination
request occurs outside the Helper scheduler, so its failure propagates directly even
when a custom item/page error policy is configured.

See [iteration and results](../guides/iteration-and-results.md),
[Video](video.md), [Performer](performer.md), [Channel](channel.md), and [Category](category.md).
