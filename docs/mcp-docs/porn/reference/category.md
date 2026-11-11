---
title: "Category — Porn.com API"
summary: "Category metadata, client.categories streams, category videos and gay/trans orientation directory roots."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Category — Porn.com API", "Category Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "Category", "get_category", "categories", "is_directory", "gay", "trans"]
---

# Category — Porn.com API

`Category(Collection)` represents an actual `single-category` page, such as
`https://www.porn.com/yoga-porn`. `await client.get_category(url)` loads metadata
by default; `client.categories()` streams summaries from the A–Z directory.
The full field table and video signature are in [Collection](collection.md).

```python
from contextlib import aclosing
from porn_api import Client, Filters

async def browse_category():
    async with Client() as client:
        category = await client.get_category("https://www.porn.com/yoga-porn")
        async with aclosing(category.videos(
            pages=1, filters=Filters(source="xVideos", min_minutes=20),
        )) as stream:
            async for result in stream:
                print(result.unwrap().title)
```

## Orientation directory roots

The straight category directory can link `/gay` and `/trans`. These are category
directory roots, not direct video grids. `category.is_directory` identifies
them; `.videos(...)` raises `ValueError` with instructions to browse categories.

```python
async def browse_orientation(client):
    root = await client.get_category("https://www.porn.com/gay")
    if root.is_directory:
        async for result in root.categories():
            print(result.unwrap().url)
```

`Category.categories(*, iterator_config=None)` is only supported on these two
roots. `Client(orientation="gay")` or `"trans"` selects the corresponding
directory/search prefix. Individual category URLs such as `/gay/twink-porn`
and `/trans/tgirl-porn` are accepted. No guessed category ID or image is derived
from a related video thumbnail.
