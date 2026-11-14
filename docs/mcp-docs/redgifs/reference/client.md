---
title: "Client — RedGIFs API"
summary: "Exact public Client getters, searches, tag and niche directories, source flags, ownership and listing defaults. Symbols: Client.get_video Client.get_image Client.get_user Client.get_niche Client.get_collection Client.search Client.search_images Client.search_users Client.get_niches Client.get_tags."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Client — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "Client"
  - "get_video"
  - "get_image"
  - "get_user"
  - "get_niche"
  - "get_collection"
  - "search"
  - "get_tags"
---

# Client — RedGIFs API

`Client(core: BaseCore | None = None)` constructs typed objects sharing a configured
backend. The internal `_api` argument is private. There is no `base_url`, account login,
`get_model`, `get_channel`, `get_playlist`, or generic `get_videos` method.

Use `async with Client() as client` or `await client.close()`. Only an internally created
core is closed. Injected cores remain caller-owned.

## Media and collection getters

```python
async def get_video(url: str, load_html: bool = False, load_api: bool = True) -> Video: ...
async def get_image(url: str, *, load_api: bool = True, load_html: bool = False) -> Image: ...
async def get_user(url: str, *, load_api: bool = True) -> User: ...
async def get_niche(url: str, *, load_api: bool = True) -> Niche: ...
async def get_collection(username: str, collection_id: str, *, load_api: bool = True) -> Collection: ...
```

Video/image getters accept a stable ID or supported watch/embed/CDN URL; getters validate
the requested object type. User and niche getters accept an identifier or the corresponding
`/users/<username>` or `/niches/<id>` URL. `get_collection()` takes an owner (username or
user URL) **and** a separate folder ID, not one arbitrary collection URL.

Setting all available source flags false creates a deferred object. Users, niches and
collections accept `load_api` only. See [source loading](../guides/source-loading.md).

## Video search

```python
def search(query: str = "", *, tags: list[str] | None = None,
           sort: Sort | str = Sort.TRENDING, pages=1, start_page=1,
           count=40, verified=False, iterator_config=None): ...
```

Returns `ScrapeStream[Video]`. Accepts `trending`, `latest`, or `top`. A blank query is
allowed for a tag/general listing; no client-side substring matching is imposed.
`verified=True` sends the site's verified filter. Verified-only trending may be empty
even when latest/top returns verified items. Do not substitute sorts silently.

## Image and creator search

```python
def search_images(query="", *, tags=None, pages=1, start_page=1,
                  count=40, iterator_config=None): ...
def search_users(query="", *, pages=1, start_page=1, count=40,
                 verified=False, iterator_config=None): ...
```

`search_images()` returns `ScrapeStream[Image]` with latest ordering; it has no sort or
verified argument. `search_users()` returns `ScrapeStream[User]`; it has no tag/sort
argument. Creators, studios and models use the site's User resource and flags.

## Directories

```python
def get_niches(*, pages=1, start_page=1, count=40, iterator_config=None): ...
async def get_tags(*, trending: bool = False) -> list[Tag]: ...
```

Niches are streamed as typed objects. Their detail loader fetches description/cover
because directory cards omit those values. Tags are an awaited in-memory list of typed
`Tag(name, count)` records, not `ScrapeResult` values.

## Listing defaults

`pages` is a positive integer or `"all"`; `start_page` is a positive, one-based index;
`count` is an integer from 1 to 100. Streams fetch page 1 for live page metadata before
applying the requested range. Valid beyond-last ranges yield nothing; invalid resources
still raise. Default results are API-loaded, in original page/card order, with terminal
page/item errors raised. An explicit `IteratorConfig` is honored. Discovery/authentication
failures propagate directly. See [iteration](../guides/iteration-and-results.md).
