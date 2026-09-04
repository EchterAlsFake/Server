---
title: "Model — Porntrex API"
summary: "Documents Model behavior, signatures, fields, constraints, and examples for the Porntrex API."
public_url: "https://docs.echteralsfake.me/porntrex/"
aliases:
  - "Porntrex Model"
keywords:
  - "Porntrex"
  - "Model"
  - "videos"
  - "url"
  - "name"
  - "information"
  - "thumbnail"
---

# Model — Porntrex API

Documents Model behavior, signatures, fields, constraints, and examples for the Porntrex API.

dataclass Inherits from `BaseMedia` via `ChannelModelHelper`. Represents a model profile page.

## Attributes

## url

Type: str; Description: Model profile page URL

## name

Type: str | None; Description: Name of the model

## information

Type: dict | None; Description: Key-value parameters extracted from the sidebar info container (e.g. age, views)

## thumbnail

Type: str | None; Description: Profile picture URL

## Methods

## videos

Iterates over the videos uploaded/featuring this model.

```python
async for result in model.videos(
    pages: int = 2,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Pages to parse (default: `2`)
- iterator_config IteratorConfig | None — Per-iterator concurrency, source loading, ordering, retry, error-mode, and custom-handler settings. The package default loads the `html` source.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [Porntrex API getting started](../getting-started.md)
- [Errors and troubleshooting — Porntrex API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/porntrex/](https://docs.echteralsfake.me/porntrex/)
