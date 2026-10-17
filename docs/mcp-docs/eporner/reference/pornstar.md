---
title: "Pornstar — Eporner API"
summary: "Documents Pornstar behavior, signatures, fields, constraints, and examples for the Eporner API."
public_url: "https://docs.echteralsfake.me/eporner/"
aliases:
  - "Eporner Pornstar"
keywords:
  - "Eporner"
  - "Pornstar"
  - "videos"
  - "url"
  - "name"
  - "subscribers"
  - "picture"
  - "video_amount"
  - "total_pages"
  - "video_views"
  - "websites"
  - "pornstar_id"
  - "photos_amount"
  - "pornstar_rank"
  - "profile_views"
  - "photo_views"
  - "country"
  - "age"
  - "ethnicity"
  - "eye_color"
---

# Pornstar — Eporner API

Documents Pornstar behavior, signatures, fields, constraints, and examples for the Eporner API.

dataclass Inherits from `BaseProfile` → `BaseMedia`. Represents an Eporner model profile with parsed statistics, bio, and video streams.

## Attributes

## url

Type: str; Description: Profile URL

## name

Type: str | None; Description: Name of the pornstar (from BaseProfile )

## subscribers

Type: str | None; Description: Number of subscribers (from BaseProfile )

## picture

Type: str | None; Description: Cover avatar picture URL (from BaseProfile )

## video_amount

Type: str | None; Description: Number of uploaded/starring videos (from BaseProfile )

## total_pages

Type: int | None; Description: Page count discovered from HTML pagination links (from BaseProfile )

## video_views

Type: str | None; Description: Accumulated views on videos (from BaseProfile )

## websites

Type: dict[str, str] | None; Description: External links and social pages (from BaseProfile )

## pornstar_id

Type: str | None; Description: Unique numeric pornstar ID

## photos_amount

Type: str | None; Description: Number of photos

## pornstar_rank

Type: str | None; Description: Eporner site rank

## profile_views

Type: str | None; Description: Total views of this profile

## photo_views

Type: str | None; Description: Accumulated views on photos

## country

Type: str | None; Description: Country of origin

## age

Type: str | None; Description: Pornstar age

## ethnicity

Type: str | None; Description: Ethnicity metadata

## eye_color

Type: str | None; Description: Eye color

## hair_color

Type: str | None; Description: Hair color

## height

Type: str | None; Description: Height details

## weight

Type: str | None; Description: Weight details

## cup

Type: str | None; Description: Bra cup size

## measurements

Type: str | None; Description: Body measurements string (e.g. 34-24-34 )

## biography

Type: str | None; Description: Biography paragraph description

## aliases

Type: list[str] | None; Description: List of alternate names

## Methods

## videos

Yields video scrape results associated with this pornstar. Inherited from `BaseProfile`.

```python
async for result in pornstar.videos(
    pages: int = 0,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to load (if `0`, uses `total_pages` discovered from HTML pagination links)
- iterator_config IteratorConfig | None — Concurrency, source loading, ordering, retry, and error policy

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Eporner API getting started](../getting-started.md)
- [Errors and troubleshooting — Eporner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
