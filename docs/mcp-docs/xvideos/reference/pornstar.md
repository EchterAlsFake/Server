---
title: "Pornstar — XVideos API"
summary: "Documents Pornstar behavior, signatures, fields, constraints, and examples for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Pornstar"
keywords:
  - "XVideos"
  - "Pornstar"
  - "videos"
  - "worked_for_with"
  - "gender"
  - "age"
  - "video_tags"
---

# Pornstar — XVideos API

Documents Pornstar behavior, signatures, fields, constraints, and examples for the XVideos API.

dataclass Inherits from `BaseChannelPornstar`. Represents a performer profile. Has all Channel attributes **plus** :

## gender

Type: str | None; Description: Gender

## age

Type: str | None; Description: Age

## video_tags

Type: str | None; Description: Most common tags

## Methods

## videos

Iterates over the pornstar's uploaded videos. Set `pages=0` (default) to fetch _all_ pages.

```python
async for result in pornstar.videos(
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

Returns a list of channels/studios this performer has worked for/with.

```python
await pornstar.worked_for_with(
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
