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
  - "subscribers"
  - "picture"
  - "name"
  - "photos_amount"
  - "video_amount"
  - "pornstar_rank"
  - "profile_views"
  - "video_views"
  - "photo_views"
  - "country"
  - "age"
  - "ethnicity"
  - "eye_color"
  - "hair_color"
  - "height"
  - "weight"
---

# Pornstar — Eporner API

Documents Pornstar behavior, signatures, fields, constraints, and examples for the Eporner API.

dataclass Inherits from `BaseMedia`. Represents an Eporner model profile with parsed statistics and biography properties.

## Attributes

## url

Type: str; Description: Profile URL

## subscribers

Type: str | None; Description: Number of subscribers

## picture

Type: str | None; Description: Cover avatar picture URL

## name

Type: str | None; Description: Name of the pornstar

## photos_amount

Type: str | None; Description: Number of photos

## video_amount

Type: str | None; Description: Number of uploaded/starring videos

## pornstar_rank

Type: str | None; Description: Eporner site rank

## profile_views

Type: str | None; Description: Total views of this profile

## video_views

Type: str | None; Description: Accumulated views on videos

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

Type: list | None; Description: List of alternate names

## Methods

## videos

Yields video scrape results associated with this pornstar.

```python
async for result in pornstar.videos(
    pages: int = 0,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to load (if `0`, automatically calculates pages based on total `video_amount`)
- iterator_config IteratorConfig | None — Concurrency, source loading, ordering, retry, and error policy; defaults to Eporner's API+HTML configuration

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Eporner API getting started](../getting-started.md)
- [Errors and troubleshooting — Eporner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/eporner/](https://docs.echteralsfake.me/eporner/)
