---
title: "Channel — Porn.com API"
summary: "Channel studio profiles, client.channels directory, get_channel and complete paginated studio video grids."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Channel — Porn.com API", "Channel Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "Channel", "get_channel", "channels", "studio"]
---

# Channel — Porn.com API

`Channel(Collection)` represents a studio/channel page with HTML body type
`single-channel`. A source website such as XNXX is a distinct [Source](source.md).
Use actual links instead of deriving channel URLs from a video title.

```python
from contextlib import aclosing
from porn_api import Client

async def inspect_channel():
    async with Client() as client:
        channel = await client.get_channel("https://www.porn.com/bratty-sis")
        print(channel.name, channel.description, channel.info)
        async with aclosing(channel.videos(pages="all")) as stream:
            async for result in stream:
                video = result.unwrap()
                print(video.video_id, video.title, video.source_name)
```

All fields and `.videos(...)` arguments come from [Collection](collection.md).
An official-site link, rank, advertised total, and video views remain in native
`info`/`social_links` where supplied. `client.channels(...)` enumerates `/sites`
as `ScrapeResult[Channel]` summaries; it is not an awaited list.

The initial complete comparisons matched four visible Bratty Sis video entries
plus two native ads, and 1,618 Brazzers entries plus 42 ads. Brazzers has one
repeated ID on separate pages; iteration preserves both live occurrences.
See [live validation](../guides/live-validation.md).
