---
title: "Channel — Bellesa API"
summary: "Channel provider metadata, API-only loading, public channel redirect semantics, and 24-item videos streams. Symbols: url core profile_id name description thumbnail_url logo_url website_url Channel.videos. Alias: Channel.get_videos."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Channel — Bellesa API", "Bellesa channel"]
keywords: ["Bellesa", "bellesa_api", "Channel", "get_channel", "videos", "get_videos", "author_link", "provider"]
---

# Channel — Bellesa API

`Channel(url=..., core=...)` is a keyword-only `BaseMedia` dataclass for
`https://www.bellesa.co/channels/{handle}`. Use `await client.get_channel(url, load_api=True)`.
Only the `api` source exists for channel metadata; `load_api=False` defers it.

| Field | Type | Meaning |
|---|---|---|
| `url`, `core` | `str`, `BaseCore` | Channel identity/backend |
| `profile_id` | `str` or `None` | Provider ID as text |
| `name`, `description` | `str` or `None` | Channel name and plain description |
| `thumbnail_url`, `logo_url` | `str` or `None` | Channel image/logo |
| `website_url` | `str` or `None` | Optional external website |

## videos / get_videos

```python
def videos(*, sort=Sort.RECENT, pages=1, start_page=1,
           iterator_config=None) -> ScrapeStream[Video]: ...
```

`get_videos` aliases `videos`. Streams use the actual provider-filtered public video
endpoint with 24 items per page. `pages="all"` uses listing totals and handles partial
and exact full-page boundaries. Recent, popular and longest sorts are supported.

The website redirects `/channels/{handle}` to `/videos?providers={handle}` and can drop
a channel URL's page query. The API paginates the actual listing directly, preserving
the provider filter. Channel profiles have no invented video count or HTML loader.

```python
from bellesa_api import Client

async def list_channel():
    async with Client() as client:
        channel = await client.get_channel("https://www.bellesa.co/channels/zero-to-hero")
        print(channel.name)
        async with channel.videos(pages="all") as stream:
            async for result in stream:
                print(result.unwrap().video_id)
```

Use `Video.get_author()` to follow the first provider relationship,
`Client.search(query, kind="channel")` for channel search, or
`Client.get_videos(channels=["zero-to-hero"])` for filters.
See [iteration](../guides/iteration-and-results.md).
