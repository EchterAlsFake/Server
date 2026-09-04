---
title: "Client — xHamster API"
summary: "Documents Client behavior, signatures, fields, constraints, and examples for the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster Client"
keywords:
  - "xHamster"
  - "Client"
  - "get_video"
  - "get_pornstar"
  - "get_creator"
  - "get_channel"
  - "get_short"
  - "search_videos"
  - "login"
---

# Client — xHamster API

Documents Client behavior, signatures, fields, constraints, and examples for the xHamster API.

The entry point for retrieving all resources from xHamster.

```python
from xhamster_api import Client
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig

client = Client()
client_custom = Client(core=BaseCore(RuntimeConfig()))
```

## Constructor Parameters
- core BaseCore — Networking core instance (default: `BaseCore(RuntimeConfig())`)

## Methods

## get_video

Fetches a video profile page and returns a populated `Video` object.

```python
await client.get_video(
    url: str,
    load_html: bool = True
) -> Video
```

### Parameters
- url str — xHamster video page URL
- load_html bool — If `True`, pre-fetches and extracts page metadata immediately

### Returns

→ Video

## get_pornstar

Loads a pornstar biography and information metadata profile.

```python
await client.get_pornstar(
    url: str,
    load_html: bool = True
) -> Pornstar
```

### Parameters
- url str — The pornstar profile page URL
- load_html bool — Pre-load parsed properties

### Returns

→ Pornstar

## get_creator

Loads a content creator profile page and returns a populated `Creator` object.

```python
await client.get_creator(
    url: str,
    load_html: bool = True
) -> Creator
```

### Parameters
- url str — The content creator profile page URL
- load_html bool — Pre-load parsed properties

### Returns

→ Creator

## get_channel

Loads a studio or publisher channel profile page.

```python
await client.get_channel(
    url: str,
    load_html: bool = True
) -> Channel
```

### Parameters
- url str — The channel page URL
- load_html bool — Pre-load parsed properties

### Returns

→ Channel

## get_short

Fetches a mobile "Short" video page and returns a populated `Short` object.

```python
await client.get_short(
    url: str,
    load_html: bool = True
) -> Short
```

### Parameters
- url str — The xHamster shorts URL
- load_html bool — Pre-load parsed properties

### Returns

→ Short

## search_videos

Runs a query through search filters and yields video scrape results.

```python
async for result in client.search_videos(
    query: str,
    minimum_quality: Literal["720p", "1080p", "2160p"] = "720p",
    sort_by: Literal["views", "newest", "best", "longest"] | None = None,
    category: Literal["german", "amateur", "18-year-old", "granny", "anal", "old-young", "mature", "mom", "milf", "big-tits", "big-natural-tits", "lesbian", "teen", "cum-in-mouth", "bdsm", "porn-for-women", "russian", "vintage", "hairy", "brutal-sex"] | list[str] | None = None,
    vr: bool = False,
    full_length_only: bool = False,
    min_duration: Literal["2", "5", "10", "30", "40"] | None = None,
    date: Literal["latest", "weekly", "monthly", "yearly"] | None = None,
    production: Literal["studios", "creators"] | None = None,
    fps: Literal["30", "60"] | None = None,
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- query str — Search query words
- minimum_quality str — Minimum resolution limit (default: `"720p"`)
- sort_by str — Sort criteria
- category str | list[str] — Category filters
- vr bool — Filter for VR videos
- full_length_only bool — Only include full-length movies
- min_duration str — Minimum duration limit in minutes
- date str — Upload age filter (e.g. `"weekly"`)
- production str — Filter studio or creator-made uploads
- fps str — Framerate filter
- pages int — Number of search result index pages to scrape
- iterator_config IteratorConfig | None — Concurrency, ordering, source loading, retry, and terminal-error policy. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## login

Performs authentication and yields an active `Account` instance. Supports cookie injection fallback.

```python
await client.login(
    username: str,
    password: str,
    cookies: dict | None = None
) -> Account
```

### Parameters
- username str — Account username or email
- password str — Account password
- cookies dict | None — Dict of session cookies to bypass authorization steps

### Returns

→ Account

## Related MCP documents

- [xHamster API getting started](../getting-started.md)
- [Errors and troubleshooting — xHamster API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
