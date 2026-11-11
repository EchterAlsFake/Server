---
title: "Client \u2014 YouJizz API"
summary: "Client getters, listings, directories, filters and core ownership."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Client \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "reference", "client"]
---

# Client — YouJizz API

`Client(core: BaseCore | None = None)` supports `async with` and `await client.close()`.

```python
async def get_video(url: str, load_html=False, load_api=True) -> Video: ...
async def get_user(url: str, load_api=True) -> User: ...
def get_category(url: str) -> Category: ...
async def pornstars(letter="A") -> list[Pornstar]: ...
async def categories() -> list[Category]: ...
def videos(listing=Listing.POPULAR, pages=1, *, start_page=1, iterator_config=None): ...
def random_videos(iterator_config=None): ...
def search_videos(query, pages=1, *, start_page=1, sort=Sort.RELEVANCE,
                  duration=Duration.ANY, phrase=Phrase.ALL, title_only=False,
                  date_from=None, date_to=None, iterator_config=None): ...
```

Video getters accept numeric IDs, video URLs and embed links. `get_category` is
synchronous and accepts a tag/category listing URL. `pornstars` requires A–Z.
Listings and search return asynchronous streams of ScrapeResult objects; use
`result.unwrap()` to obtain a Video. No account/login API is provided.
