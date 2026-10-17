---
title: "Profile — TNAFlix API"
summary: "Documents Profile behavior, signatures, fields, constraints, and examples for the TNAFlix API."
public_url: "https://docs.echteralsfake.me/tnaflix/"
aliases:
  - "TNAFlix Profile"
keywords:
  - "TNAFlix"
  - "Profile"
  - "videos"
  - "url"
  - "username"
  - "slug"
  - "display_name"
  - "avatar_url"
  - "cover_url"
  - "bio"
  - "rank"
  - "profile_views"
  - "subscribers_count"
  - "video_views"
  - "total_videos_count"
  - "gender"
  - "interested_in"
  - "location"
  - "age"
  - "relationship_status"
---

# Profile — TNAFlix API

Documents Profile behavior, signatures, fields, constraints, and examples for the TNAFlix API.

dataclass Inherits from `BaseMedia`. Represents a TNAFlix user profile page containing uploader statistics and community profile information.

## Attributes

## url

Type: str; Description: Profile page URL

## username

Type: str | None; Description: Profile username

## slug

Type: str | None; Description: Profile URL slug identifier

## display_name

Type: str | None; Description: Display name or page title

## avatar_url

Type: str | None; Description: Profile avatar image URL

## cover_url

Type: str | None; Description: Profile header cover banner URL

## bio

Type: str | None; Description: Biography or description text

## rank

Type: str | None; Description: Site ranking position

## profile_views

Type: str | None; Description: Total profile views count

## subscribers_count

Type: str | None; Description: Total subscriber count

## video_views

Type: str | None; Description: Cumulative views across all uploaded videos

## total_videos_count

Type: str | None; Description: Total uploaded videos count

## gender

Type: str | None; Description: Stated gender identity

## interested_in

Type: str | None; Description: Sexual orientation preference

## location

Type: str | None; Description: Geographical location

## age

Type: str | None; Description: Age of the user

## relationship_status

Type: str | None; Description: Relationship status

## is_pornstar

Type: bool; Description: Whether this profile represents a recognized adult performer

## Methods

## videos

Asynchronously yields video scrape results uploaded by this user profile across listing pages.

```python
async for result in profile.videos(
    pages: int | str = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int | str — Number of pages to iterate (default: `2`) or `"all"`
- iterator_config IteratorConfig | None — Per-iterator concurrency, source loading, ordering, retry, error-mode, and custom-handler settings.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [TNAFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — TNAFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tnaflix/](https://docs.echteralsfake.me/tnaflix/)
