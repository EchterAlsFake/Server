---
title: "Client — PornHub API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Client"
keywords:
  - "PornHub"
  - "Client"
  - "get_video"
  - "get_pornstar"
  - "get_model"
  - "get_user"
  - "get_channel"
  - "get_playlist"
  - "get_album"
  - "get_gif"
  - "get_short"
  - "search_videos"
  - "search_gifs"
  - "search_hubtraffic"
  - "create"
  - "login"
---

# Client — PornHub API

Documents Client behavior, signatures, fields, constraints, and examples for the PornHub API.

The `Client` class is your **entry point** for all interactions. It manages the session, headers, cookies, and authentication — providing methods to fetch individual resources, search, and access account features.

```python
from pornhub_api import Client
from base_api import BaseCore

# Basic initialization
client = Client()

# Construct without logging in
client = Client(
    core=BaseCore(),
    email="user@example.com",
    password="password",
)
await client.login()

# Or await the factory for construction plus completed login
client = await Client.create(
    core=BaseCore(),
    email="user@example.com",
    password="password",
    login=True,
)
```

## Constructor Parameters
- core BaseCore — Networking core instance. The source default is one module-created `BaseCore()` shared by callers that omit this argument; pass an explicit core for independent configuration and lifecycle.
- email str | None — Account email for login
- password str | None — Account password for login

## Methods

## get_video

Fetches a video page and returns a populated `Video` object. By default, loads metadata via the Webmaster API; set `load_html=True` for full HTML-scraped data including categories, tags, and author information.

```python
await client.get_video(
    url: str,
    load_html: bool = False,
    load_api: bool = True
) -> Video
```

### Parameters
- url str — The full Pornhub video URL
- load_html bool — If `True`, fetches and parses the full HTML page for extended metadata (categories, tags, author info, m3u8 URLs)
- load_api bool — If `True` (default), fetches metadata via the Webmaster API for faster loading

### Returns

→ Video

## get_pornstar

Fetches a pornstar profile page and returns a populated `Pornstar` object with bio, about, and info fields.

```python
await client.get_pornstar(
    url: str,
    load_html: bool = True
) -> Pornstar
```

### Parameters
- url str — The full Pornhub pornstar profile URL
- load_html bool — If `True` (default), parses the HTML profile page for metadata

### Returns

→ Pornstar

## get_model

Fetches a model profile page and returns a populated `Model` object.

```python
await client.get_model(
    url: str,
    load_html: bool = True
) -> Model
```

### Parameters
- url str — The full Pornhub model profile URL
- load_html bool — If `True` (default), parses the HTML profile page

### Returns

→ Model

## get_user

Fetches a regular user profile page and returns a populated `User` object.

```python
await client.get_user(
    url: str,
    load_html: bool = True
) -> User
```

### Parameters
- url str — The full Pornhub user profile URL
- load_html bool — If `True` (default), parses the HTML profile page

### Returns

→ User

## get_channel

Fetches a channel page and returns a populated `Channel` object with name, stats, and metadata.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Parameters
- url str — The full Pornhub channel URL
- load_html bool — If `True` (default), parses the HTML page

### Returns

→ Channel

## get_playlist

Fetches a playlist page and returns a populated `Playlist` object with title, description, tags, and video counts.

```python
await client.get_playlist(
    url: str,
    load_html: bool = True
) -> Playlist
```

### Parameters
- url str — The full Pornhub playlist URL
- load_html bool — If `True` (default), parses the HTML page for metadata

### Returns

→ Playlist

## get_album

Fetches a photo album page and returns a populated `Album` object with rating, views, tags, and author information.

```python
await client.get_album(
    url: str,
    load_html: bool = True
) -> Album
```

### Parameters
- url str — The full Pornhub album URL
- load_html bool — If `True` (default), parses the HTML page

### Returns

→ Album

## get_gif

Fetches a GIF page and returns a populated `GIF` object with title, votes, views, tags, and direct download URL.

```python
await client.get_gif(
    url: str,
    load_html: bool = True
) -> GIF
```

### Parameters
- url str — The full Pornhub GIF URL
- load_html bool — If `True` (default), parses the HTML page

### Returns

→ GIF

## get_short

Fetches a short video page and returns a populated `Short` object with title, likes, and streaming URLs.

```python
await client.get_short(
    url: str,
    load_html: bool = True
) -> Short
```

### Parameters
- url str — The full Pornhub short URL
- load_html bool — If `True` (default), parses the HTML page

### Returns

→ Short

## search_videos

Searches for videos matching the query text. Supports filtering by production type, sort order, and duration range. See [Search & Filtering](../guides/searching-and-filtering.md) for details.

```python
async for result in client.search_videos(
    query: str,
    production_type: Literal["professional", "homemade"] | None = None,
    sort_by: Literal["mr", "mv", "tr"] | None = None,
    duration_min: Literal["10", "20", "30"] | None = None,
    duration_max: Literal["10", "20", "30"] | None = None,
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search keywords
- production_type str | None — Filter by `"professional"` or `"homemade"`
- sort_by str | None — `"mr"` (Most Recent), `"mv"` (Most Viewed), `"tr"` (Top Rated)
- duration_min str | None — Minimum duration in minutes: `"10"`, `"20"`, or `"30"`
- duration_max str | None — Maximum duration in minutes: `"10"`, `"20"`, or `"30"`
- pages int — Number of result pages to iterate (default: `5`)
- iterator_config IteratorConfig | None — Optional v4 concurrency, ordering, eager-source, retry, and error-handling policy. By default, no media source is loaded eagerly.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## search_gifs

Searches for GIFs matching the query. Supports category and sort filtering.

```python
async for result in client.search_gifs(
    query: str,
    category: Literal["gay", "transgender"] | None = None,
    search_filter: Literal["mr", "mv", "tr"] | None = None,
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[GIF], None]
```

### Parameters
- query str — Search keywords
- category str | None — Category filter: `"gay"` or `"transgender"` (default: straight)
- search_filter str | None — `"mr"` (Most Recent), `"mv"` (Most Viewed), `"tr"` (Top Rated)
- pages int — Number of result pages (default: `5`)
- iterator_config IteratorConfig | None — Optional v4 iterator policy. By default, no media source is loaded eagerly.

### Returns

→ AsyncGenerator[ScrapeResult[GIF], None]

## search_hubtraffic

Searches for videos using the HubTraffic (Webmaster) API. Faster and provides pre-parsed metadata without HTML scraping.

```python
async for result in client.search_hubtraffic(
    query: str,
    category: str | None = None,
    sort_by: Literal["newest", "mostviewed", "rating"] | None = None,
    period: Literal["weekly", "monthly", "alltime"] | None = None,
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search keywords
- category str | None — Category filter string
- sort_by str | None — `"newest"`, `"mostviewed"`, or `"rating"`
- period str | None — Time period: `"weekly"`, `"monthly"`, or `"alltime"`
- pages int — Number of result pages (default: `5`)
- iterator_config IteratorConfig | None — Optional v4 iterator policy. The default uses higher page/item concurrency for HubTraffic but still performs no eager media-source load.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## create

Constructs a client and, when requested with credentials, waits for login to complete before returning it. Use this factory when initialization must include authentication.

```python
client = await Client.create(
    core: BaseCore = BaseCore(),
    email: str | None = None,
    password: str | None = None,
    login: bool = False
) -> Client
```

### Returns

→ Client

## login

Authenticates the client with email/password credentials. On success, populates `client.account` with user data and enables access to account-specific methods (recommended, history, favorites, feed, subscriptions).

```python
await client.login(
    force: bool = False,
    throw: bool = True
) -> bool
```

### Parameters
- force bool — If `True`, re-login even if already logged in
- throw bool — If `True` (default), raises `LoginFailed` on failure; if `False`, returns `False` instead

### Returns

→ bool

### Raises
- LoginFailed — If credentials are invalid or login request fails
- ClientAlreadyLogged — If already logged in and `force=False`

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
