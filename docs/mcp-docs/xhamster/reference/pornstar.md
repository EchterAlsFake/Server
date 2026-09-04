---
title: "Pornstar / Creator / Channel — xHamster API"
summary: "Documents Pornstar / Creator / Channel behavior, signatures, fields, constraints, and examples for the xHamster API."
public_url: "https://docs.echteralsfake.me/xhamster/"
aliases:
  - "xHamster Pornstar / Creator / Channel"
keywords:
  - "xHamster"
  - "Pornstar / Creator / Channel"
  - "videos"
  - "get_shorts"
  - "url"
  - "name"
  - "subscribers_count"
  - "videos_count"
  - "total_views_count"
  - "avatar_url"
  - "pornstar_information"
---

# Pornstar / Creator / Channel — xHamster API

Documents Pornstar / Creator / Channel behavior, signatures, fields, constraints, and examples for the xHamster API.

Profiles representing models, creator users, and publisher studios share a common metadata hierarchy.

## Attributes

## url

Type: str; Description: Profile URL

## name

Type: str | None; Description: Display name

## subscribers_count

Type: str | None; Description: Number of subscribers

## videos_count

Type: str | None; Description: Total uploaded videos

## total_views_count

Type: str | None; Description: Sum of views across all videos

## avatar_url

Type: str | None; Description: Avatar profile image URL

## pornstar_information

Type: dict | None; Description: Biography sidebar parameters (only parsed for Pornstar and Creator models)

## Methods

## videos

Yields videos uploaded to this profile page.

```python
async for result in profile.videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to fetch
- iterator_config IteratorConfig | None — Complete iterator policy. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## get_shorts

Yields mobile shorts for a `Pornstar` or `Creator`. This method is not available on `Channel` or the shared `Something` base class.

```python
async for result in pornstar.get_shorts(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Short], None]
```

### Parameters
- pages int — Pages to fetch
- iterator_config IteratorConfig | None — Complete iterator policy for page and `Short` items.

### Returns

→ AsyncGenerator[ScrapeResult[Short], None]

## Related MCP documents

- [xHamster API getting started](../getting-started.md)
- [Errors and troubleshooting — xHamster API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/xhamster/](https://docs.echteralsfake.me/xhamster/)
