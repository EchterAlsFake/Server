---
title: "Account — PornHub API"
summary: "Documents Account behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Account"
keywords:
  - "PornHub"
  - "Account"
  - "get_recommended"
  - "get_history"
  - "get_favorites"
  - "get_feed"
  - "get_subscriptions"
  - "name"
  - "avatar"
  - "is_premium"
  - "user"
---

# Account — PornHub API

Documents Account behavior, signatures, fields, constraints, and examples for the PornHub API.

Represents the authenticated user account. Access via `client.account` after calling `client.login()`. Provides methods for recommendations, history, favorites, feed, and subscriptions.

## Attributes

## name

Type: str | None; Description: Account username

## avatar

Type: str | None; Description: Avatar image URL

## is_premium

Type: bool; Description: Whether the account has premium status

## user

Type: User | None; Description: Associated User object for the account profile

```python
from pornhub_api import Client

client = Client(email="user@example.com", password="password")
await client.login()

print(client.account.name)        # Username
print(client.account.is_premium)   # True/False

# Get recommended videos
async for result in client.account.get_recommended():
    if result.succeeded:
        video = result.unwrap()
        await video.load_sources("html")
        print(video.title)
```

## Methods

## get_recommended

Gets recommended videos for the logged-in account. Automatically fixes recommendation cookies before fetching.

```python
async for result in account.get_recommended(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of recommendation pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default performs no eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_history

Gets the watch history for the logged-in account. Requires authentication.

```python
async for result in account.get_history(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of history pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default performs no eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_favorites

Gets favorite/liked videos for the logged-in account. Requires authentication.

```python
async for result in account.get_favorites(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of favorites pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default performs no eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_feed

Gets the subscription feed for the logged-in account. Filterable by section type.

```python
async for result in account.get_feed(
    section: str = "videos",
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- section str — Section to filter: `"videos"`, `"photos"`, `"posts"`, etc.
- pages int — Number of feed pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default performs no eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_subscriptions

Gets all subscribed users/creators for the logged-in account.

```python
async for result in account.get_subscriptions(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[User], None]
```

### Parameters
- pages int — Number of subscription pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default performs no eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[User], None]

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
