---
title: "Channel — XVideos API"
summary: "Documents Channel behavior, signatures, fields, constraints, and examples for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Channel"
keywords:
  - "XVideos"
  - "Channel"
  - "videos"
  - "worked_for_with"
  - "url"
  - "name"
  - "thumbnail_url"
  - "total_videos"
  - "per_page"
  - "total_pages"
  - "profile_hits"
  - "subscribers"
  - "total_videos_views"
  - "signed_up"
  - "last_activity"
  - "worked_for_with_links"
---

# Channel — XVideos API

Documents Channel behavior, signatures, fields, constraints, and examples for the XVideos API.

dataclass Inherits from `BaseChannelPornstar` → `BaseMedia`. Represents a channel profile.

## Attributes

## url

Type: str; Description: Channel profile URL

## name

Type: str | None; Description: Channel name

## thumbnail_url

Type: str | None; Description: Profile picture URL

## total_videos

Type: int | None; Description: Number of uploaded videos

## per_page

Type: int | None; Description: Number of videos returned per listing page

## total_pages

Type: int | None; Description: Calculated number of video pages

## profile_hits

Type: str | None; Description: Total profile views

## subscribers

Type: str | None; Description: Subscriber count

## total_videos_views

Type: str | None; Description: Total views across all videos

## signed_up

Type: str | None; Description: Registration date

## last_activity

Type: str | None; Description: Last activity date

## worked_for_with_links

Type: list | None; Description: Links to associated studios/channels

## Methods

## videos

Iterates over the channel's uploaded videos. Set `pages=0` (default) to fetch _all_ pages.

```python
async for result in channel.videos(
    pages: int = 0,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Maximum pages; `0` uses the profile's full page count.
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default eagerly loads each video's `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## worked_for_with

Returns a list of channels/studios this entity has worked for/with.

```python
await channel.worked_for_with(
    load_html: bool = True
) -> list[Channel]
```

### Returns

→ list[Channel]

## Related MCP documents

- [XVideos API getting started](../getting-started.md)
- [Errors and troubleshooting — XVideos API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
