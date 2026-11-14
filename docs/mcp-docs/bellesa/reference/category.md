---
title: "Category — Bellesa API"
summary: "Category metadata, awaited get_categories list, category URLs, and 24-item filtered video streams. Symbols: url core category_id name description Category.videos. Alias: Category.get_videos."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Category — Bellesa API", "Bellesa category"]
keywords: ["Bellesa", "bellesa_api", "Category", "get_category", "get_categories", "videos", "categories"]
---

# Category — Bellesa API

`Category(url=..., core=...)` is a keyword-only `BaseMedia` dataclass for
`https://www.bellesa.co/videos/categories/{handle}`. Use `await client.get_category(url)`.
Metadata uses `api` only; `load_api=False` creates a deferred category.

| Field | Type | Meaning |
|---|---|---|
| `url`, `core` | `str`, `BaseCore` | Identity/backend |
| `category_id` | `str` or `None` | Category ID as text |
| `name`, `description` | `str` or `None` | Name and plain description |

The loader finds the exact handle in the public category directory. Unknown handles
raise `NotFound` through the shared media loader error wrapper. The observed directory
contained 19 categories; catalog contents may change.

## videos / get_videos

```python
def videos(*, sort=Sort.RECENT, pages=1, start_page=1,
           iterator_config=None) -> ScrapeStream[Video]: ...
```

`get_videos` aliases `videos`; it delegates to `Client.get_videos(categories=[handle])`.
Pages contain up to 24 items and support recent, popular and longest ordering.

```python
from bellesa_api import Client

async def list_categories():
    async with Client() as client:
        categories = await client.get_categories()  # list[Category], not ScrapeResult
        for category in categories:
            print(category.category_id, category.name)
        sensual = await client.get_category(
            "https://www.bellesa.co/videos/categories/sensual"
        )
        async with sensual.videos() as stream:
            async for result in stream:
                print(result.unwrap().title)
```

See [Client](client.md) and [searching and filtering](../guides/searching-and-filtering.md).
