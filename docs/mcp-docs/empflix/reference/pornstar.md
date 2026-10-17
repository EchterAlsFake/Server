---
title: "Pornstar — EMPFlix API"
summary: "Documents Pornstar behavior, signatures, fields, constraints, and examples for the EMPFlix API."
public_url: "https://docs.echteralsfake.me/empflix/"
aliases:
  - "EMPFlix Pornstar"
keywords:
  - "EMPFlix"
  - "Pornstar"
  - "videos"
  - "url"
  - "display_name"
  - "slug"
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
  - "is_pornstar"
---

# Pornstar — EMPFlix API

Documents Pornstar behavior, signatures, fields, constraints, and examples for the EMPFlix API.

dataclass Inherits from `Profile`. Represents a verified performer or pornstar on EMPFlix. It shares all underlying profile fields while explicitly indicating an adult model entry with `is_pornstar=True`.

## Performer Fields

## url

Type: str; Description: Pornstar profile page URL

## display_name

Type: str | None; Description: Performer stage name

## slug

Type: str | None; Description: Performer URL slug identifier

## avatar_url

Type: str | None; Description: Performer portrait avatar picture URL

## cover_url

Type: str | None; Description: Performer cover banner image URL

## bio

Type: str | None; Description: Biography or introduction text

## rank

Type: str | None; Description: Site ranking position among pornstars

## profile_views

Type: str | None; Description: Accumulated views on this pornstar profile

## subscribers_count

Type: str | None; Description: Total followers and subscribers count

## video_views

Type: str | None; Description: Cumulative video views across all starring videos

## total_videos_count

Type: str | None; Description: Total count of videos featuring this performer

## gender

Type: str | None; Description: Performer gender

## interested_in

Type: str | None; Description: Sexual orientation preference

## location

Type: str | None; Description: Country or city of origin

## age

Type: str | None; Description: Age of the performer

## relationship_status

Type: str | None; Description: Relationship status indicator

## is_pornstar

Type: bool; Description: Always True for Pornstar instances

## Methods

## videos

Asynchronously yields video scrape results featuring or uploaded by this performer.

```python
async for result in pornstar.videos(
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

- [EMPFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — EMPFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/empflix/](https://docs.echteralsfake.me/empflix/)
