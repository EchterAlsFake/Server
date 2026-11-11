---
title: "Pornstar — Porn.com API"
summary: "Pornstar performer profiles, real profile routes, localized biography/statistics and inherited video streams."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Pornstar — Porn.com API", "Pornstar Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "Pornstar", "performer", "get_pornstar", "pornstars"]
---

# Pornstar — Porn.com API

`Pornstar(Collection)` represents a real performer page whose HTML body declares
`single-pornstar`. Its lazy fields and `.videos(...)` signature are documented
under [Collection](collection.md). There is no separate `Model` class.

```python
from contextlib import aclosing
from porn_api import Client

async def inspect_performer():
    async with Client() as client:
        star = await client.get_pornstar("https://www.porn.com/azumi-mizushima")
        print(star.name, star.video_count, star.info)
        async with aclosing(star.videos(pages="all")) as stream:
            async for result in stream:
                print(result.unwrap().video_id)
```

English examples expose gender, birthday, birthplace, ethnicity, height, hair
and eye color, rank, total videos, and video views in `info` where supplied.
Values remain the site's strings. Missing profile fields are not guessed from
other pages or from a performer's name.

`client.pornstars(...)` enumerates the performer directory as typed result
summaries. `await video.get_pornstars()` resolves only actual scene links.
The verified one-video profile returns ID `205464990`; the larger Mia Khalifa
profile requires continuing numeric pages beyond its disabled Next link.
See [profile reconciliation](../guides/live-validation.md).
