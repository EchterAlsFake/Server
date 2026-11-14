---
title: "Searching and filtering — Pornhat API"
summary: "Hyphenated keyword search, catalog sorts, model/channel alphabet directories, categories and supported page options."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "Searching and filtering — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "searching-and-filtering"
---

# Searching and filtering — Pornhat API

`Client.search(query, *, pages=1, start_page=1, iterator_config=None)` returns a lazy video
stream. Whitespace becomes hyphens before percent encoding, matching the site's form.
Do not manually construct `%20` search routes: the observed site rejects those paths.
Only a nonblank query and page/iterator options are accepted; there are no search sort,
upload date, duration, quality, country, gender or language filter arguments.
Select a verified locale origin with `Client(base_url="https://de.pornhat.com")`.

```python
from base_api import make_iterator_config
from pornhat_api.modules.sorting import ProfileSort, Sort

async def browse(client):
    lazy = make_iterator_config(load_specific_sources=())
    async with client.search("Armani Black", pages=2, iterator_config=lazy) as results:
        async for result in results:
            print(result.unwrap().video_id)
    async with client.get_videos(sort=Sort.TRENDING, iterator_config=lazy) as results:
        first = (await anext(results)).unwrap()
        print(first.url)
    async with client.get_models(sort=ProfileSort.ABC, letter="A", iterator_config=lazy) as results:
        first_model = (await anext(results)).unwrap()
        print(first_model.url)
```

Profile directory sorting supports rank, video count, updated and alphabet groups. Models
accept A–Z or All; channels also accept `other`. The [sorting reference](../reference/sorting-enums.md)
contains exact enum members and values.

```python
async def browse_tag(client):
    categories = await client.get_categories()
    tag = next(category for category in categories if category.url.endswith("/tags/blowjob/"))
    await tag.load_sources("html")
    async with tag.videos(pages=1) as results:
        async for result in results:
            print(result.unwrap().title)
```

Categories are deferred by default. `get_categories(load_html=True)` loads every tag detail
sequentially, so load selected categories when possible. Use `get_category` for a known tag URL.
A `Site` collection uses `/paysite/<slug>/`; grouped channels use `/sites/<slug>/`.

The tested `lesbian` search repeats four cards across its first/second page boundary.
Streams preserve the site's rendered sequences, including genuine repeated entries.
Profile reconciliation found no such duplicates. See [iteration](iteration-and-results.md).
