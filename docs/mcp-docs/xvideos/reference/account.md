---
title: "Account — XVideos API"
summary: "Documents Account behavior, signatures, fields, constraints, and examples for the XVideos API."
public_url: "https://docs.echteralsfake.me/xvideos/"
aliases:
  - "XVideos Account"
keywords:
  - "XVideos"
  - "Account"
  - "get_liked_videos"
  - "get_recommended_videos"
  - "get_watch_later_videos"
---

# Account — XVideos API

Documents Account behavior, signatures, fields, constraints, and examples for the XVideos API.

Provides access to **authenticated** endpoints. Requires login cookies.

```python
# Provide cookies from your browser session
my_cookies = {
    "session_token": "<your_token>",
    "session_token_auth": "<your_auth_token>",
}

account = client.get_account(cookies=my_cookies)

# Get your liked videos
async for result in account.get_liked_videos(pages=3):
    if result.succeeded:
        print(result.unwrap().title)
```

These authenticated listing endpoints make the required page requests with `POST` internally. Callers pass only the public `IteratorConfig` controls and should not set private request-method fields.

## Methods

## get_liked_videos

Fetches your liked videos page by page; the required account-page `POST` request is handled internally.

```python
async for result in account.get_liked_videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of authenticated listing pages.
- iterator_config IteratorConfig | None — Optional public v4 iterator policy; account transport details remain internal.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_recommended_videos

Fetches your recommended feed videos page by page; the required account-page `POST` request is handled internally.

```python
async for result in account.get_recommended_videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of authenticated listing pages.
- iterator_config IteratorConfig | None — Optional public v4 iterator policy; account transport details remain internal.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_watch_later_videos

Fetches your watch later videos page by page; the required account-page `POST` request is handled internally.

```python
async for result in account.get_watch_later_videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of authenticated listing pages.
- iterator_config IteratorConfig | None — Optional public v4 iterator policy; account transport details remain internal.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [XVideos API getting started](../getting-started.md)
- [Errors and troubleshooting — XVideos API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xvideos/](https://docs.echteralsfake.me/xvideos/)
