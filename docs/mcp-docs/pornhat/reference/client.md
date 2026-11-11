---
title: "Client — Pornhat API"
summary: "Client lifecycle, get_video, get_model, get_channel, get_category, get_site, get_categories, search and paginated directories."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Client — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "client"
---

# Client — Pornhat API

`Client(core: BaseCore | None = None, *, base_url: str = "https://www.pornhat.com")`
creates typed objects sharing one configured backend. `base_url` must be a verified origin,
with no resource path; it controls search, catalog, tag directory and profile-directory requests.
Individual getters retain the host in their supplied URL.

Use `async with Client() as client` or `await client.close()`. Only an internally created core
is closed. An injected core remains caller-owned.

## get_video

```python
async def get_video(url: str, *, load_html: bool=True, load_media: bool=False) -> Video: ...
```

Return `Video`. HTML loads by default. `load_html=False` creates a deferred object; `load_media=True` resolves media (loading HTML first even if `load_html=False`). Requires an absolute `/video/<slug>/` URL.

## get_model

```python
async def get_model(url: str, *, load_html: bool=True) -> Model: ...
```

Return `Model` from an absolute `/models/<slug>/` URL. `load_html=False` defers profile metadata.

## get_channel

```python
async def get_channel(url: str, *, load_html: bool=True) -> Channel: ...
```

Return a grouped `Channel` from an absolute `/sites/<slug>/` URL. This is distinct from the paysite/brand collection.

## get_category

```python
async def get_category(url: str, *, load_html: bool=True) -> Category: ...
```

Return a tag `Category` from an absolute `/tags/<slug>/` URL.

## get_site

```python
async def get_site(url: str, *, load_html: bool=True) -> Site: ...
```

Return a paysite/brand `Site` from an absolute `/paysite/<slug>/` URL.

## search

```python
def search(query: str, *, pages: int | Literal['all']=1, start_page: int=1, iterator_config: IteratorConfig | None=None) -> ScrapeStream[Video]: ...
```

Return a lazy `ScrapeStream[Video]`. Whitespace in the stripped query becomes hyphens before URL encoding, matching the site form. A blank query raises `ValueError`. No duration, date, quality or search-sort arguments exist.

## get_videos

```python
def get_videos(*, sort: Sort=Sort.NEW, pages: int | Literal['all']=1, start_page: int=1, iterator_config: IteratorConfig | None=None) -> ScrapeStream[Video]: ...
```

Return new, popular or trending `Video` results. `sort` is `sorting.Sort.NEW`, `POPULAR` or `TRENDING`. This method takes no arbitrary listing URL.

## get_models

```python
def get_models(*, sort: ProfileSort=ProfileSort.RANK, letter: str | None=None, pages: int | Literal['all']=1, start_page: int=1, iterator_config: IteratorConfig | None=None) -> ScrapeStream[Model]: ...
```

Return model-directory `ScrapeResult[Model]` objects. Supports `ProfileSort.RANK`, `VIDEOS`, `UPDATED` and `ABC`. Alphabet `letter` accepts A–Z or `None` for All. The model directory has no `other` group.

## get_channels

```python
def get_channels(*, sort: ProfileSort=ProfileSort.RANK, letter: str | None=None, pages: int | Literal['all']=1, start_page: int=1, iterator_config: IteratorConfig | None=None) -> ScrapeStream[Channel]: ...
```

Return channel-directory `ScrapeResult[Channel]` objects. Uses the same sorting enum as models, with the additional alphabet group `letter="other"`.

## get_categories

```python
async def get_categories(*, load_html: bool=False) -> list[Category]: ...
```

Await a list of all tag `Category` objects. These are deferred by default (`load_html=False`), with only URL/core identity loaded. `load_html=True` loads each category sequentially and can issue many requests; prefer loading selected categories.

## Listing options

`pages` is a positive count or `"all"`. `start_page` is a positive, one-based index.
The first listing page is fetched lazily at iteration time to discover pagination for every
range. The requested range is clamped to the live last page. Beyond-last ranges yield nothing;
invalid page options raise `ValueError`. `pages="all"` follows all remaining numbered pages.

Listings return `ScrapeResult` values: call `result.unwrap()` to surface failures. Defaults
load `html` for each result, preserve original page/card order, and yield terminal page/item
failures. An explicitly supplied `IteratorConfig` is honored. Initial pagination-discovery
failures propagate directly. See [iteration](../guides/iteration-and-results.md).

See [hosts](../supported-platforms.md) and [sorting](sorting-enums.md).
