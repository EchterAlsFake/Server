---
title: "Channel — PornHub API"
summary: "Documents Channel behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Channel"
keywords:
  - "PornHub"
  - "Channel"
  - "get_videos"
  - "get_user"
  - "url"
  - "name"
  - "is_award_winner"
  - "video_views"
  - "subscribers"
  - "total_videos"
  - "rank"
  - "description"
  - "join_date"
  - "website"
  - "user_link"
---

# Channel — PornHub API

Documents Channel behavior, signatures, fields, constraints, and examples for the PornHub API.

dataclass Inherits from `BaseMedia`. Represents a production channel with studio-level metadata.

## Attributes

## url

Type: str; Description: The channel page URL

## name

Type: str | None; Description: Channel display name

## is_award_winner

Type: bool | None; Description: Whether the channel has won awards

## video_views

Type: str | None; Description: Total video views across the channel

## subscribers

Type: str | None; Description: Subscriber count

## total_videos

Type: str | None; Description: Total number of videos

## rank

Type: str | None; Description: Channel rank

## description

Type: str | None; Description: Channel description text

## join_date

Type: str | None; Description: When the channel joined

## website

Type: str | None; Description: External website URL

## user_link

Type: str | None; Description: Associated user profile URL

## Methods

## get_videos

Iterates over videos published by the channel.

```python
async for result in channel.get_videos(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of channel pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default constructs results without eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_user

Returns the `User` object associated with this channel.

```python
await channel.get_user(
    load_html: bool = True
) -> User
```

### Returns

→ User

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
