---
title: "Account — xHamster API"
summary: "Documents Account behavior, signatures, fields, constraints, and examples for the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster Account"
keywords:
  - "xHamster"
  - "Account"
  - "get_liked_videos"
  - "get_account_playlist"
---

# Account — xHamster API

Documents Account behavior, signatures, fields, constraints, and examples for the xHamster API.

Provides authenticated scraper operations inside logged-in sessions.

## Methods

## get_liked_videos

Yields videos marked as liked inside the user account.

```python
async for result in account.get_liked_videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to load
- iterator_config IteratorConfig | None — Complete iterator policy. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_account_playlist

Yields videos from a specific playlist URL.

```python
async for result in account.get_account_playlist(
    url: str,
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- url str — xHamster playlist URL (e.g. `https://xhamster.com/my/playlists/...`)
- pages int — Pages to load
- iterator_config IteratorConfig | None — Complete iterator policy. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [xHamster API getting started](../getting-started.md)
- [Errors and troubleshooting — xHamster API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
