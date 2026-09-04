---
title: "Model — PornHub API"
summary: "Documents Model behavior, signatures, fields, constraints, and examples for the PornHub API."
public_url: "https://docs.echteralsfake.me/pornhub/"
aliases:
  - "PornHub Model"
keywords:
  - "PornHub"
  - "Model"
  - "get_videos"
---

# Model — PornHub API

Documents Model behavior, signatures, fields, constraints, and examples for the PornHub API.

dataclass Inherits from `UserHelper` → `BaseMedia`. Represents a model profile and inherits `get_videos()` from `UserHelper`.

## Attributes

Same as [Pornstar](pornstar.md): `url`, `name`, `bio`, `about`, `info`.

## Methods

## get_videos

Iterates over videos on the model's profile. Inherited from `UserHelper`.

```python
async for result in model.get_videos(
    pages: int = 5,
    iterator_config: IteratorConfig | None = None
) -> AsyncGenerator[ScrapeResult[Video], None]
```

### Parameters
- pages int — Number of profile pages.
- iterator_config IteratorConfig | None — Optional v4 iterator policy; the default constructs results without eager source loading.

### Returns

→ AsyncGenerator[ScrapeResult[Video], None]

## Related MCP documents

- [PornHub API getting started](../getting-started.md)
- [Errors and troubleshooting — PornHub API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/pornhub/](https://docs.echteralsfake.me/pornhub/)
