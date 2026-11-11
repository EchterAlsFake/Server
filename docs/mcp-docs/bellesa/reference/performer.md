---
title: "Performer — Bellesa API"
summary: "Performer API/HTML metadata, source flags, cross-site video_count semantics, and 9-item paginated videos streams. Symbols: url core profile_id name description thumbnail_url logo_url gender hero_url video_count Performer.videos. Alias: Performer.get_videos."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Performer — Bellesa API", "Bellesa performer"]
keywords: ["Bellesa", "bellesa_api", "Performer", "get_performer", "video_count", "videos", "get_videos", "gender"]
---

# Performer — Bellesa API

`Performer(url=..., core=...)` is a keyword-only `BaseMedia` dataclass for
`https://www.bellesa.co/performers/{handle}`. Use `await client.get_performer(url)`.
Both `api` and `html` sources are available, with API precedence; API loads by default.
Setting both source flags false creates a deferred profile.

| Field | Type | Meaning |
|---|---|---|
| `url`, `core` | `str`, `BaseCore` | Identity/backend |
| `profile_id` | `str` or `None` | Stable numeric performer ID as text |
| `name`, `description` | `str` or `None` | Display name and plain biography |
| `thumbnail_url`, `hero_url` | `str` or `None` | Images when supplied |
| `logo_url` | `str` or `None` | Usually absent on performers |
| `gender` | `str` or `None` | Site-supplied gender |
| `video_count` | `int` or `None` | Profile count; may span more than the free listing |

## videos / get_videos

```python
def videos(*, sort=Sort.RECENT, pages=1, start_page=1,
           iterator_config=None) -> ScrapeStream[Video]: ...
```

`get_videos` is an alias of `videos`. The free catalog listing uses 9 items per page;
recent, longest and popular ordering are supported. The profile can be deferred because
the listing filter uses its handle. Use `pages="all"` to follow the listing's actual
pagination total, not `video_count`.

Lily Starfire's profile reported 7 videos while the free listing exposed 3; Kenna James's
free listing exposed 57 over seven pages. The library preserves these distinct count
semantics instead of including recommendations or premium-only entries.

```python
from bellesa_api import Client

async def list_performer():
    async with Client() as client:
        performer = await client.get_performer(
            "https://www.bellesa.co/performers/kenna-james"
        )
        async with performer.videos(pages="all") as stream:
            async for result in stream:
                video = result.unwrap()
                print(video.video_id, video.title)
```

The directory is `Client.get_performers(...)`; performer search is
`Client.search(query, kind="performer")`. There is no separate Model/Pornstar subtype.
See [Client](client.md) and [iteration](../guides/iteration-and-results.md).
