---
title: "Search and filtering — HQPorner API"
summary: "Explains the documented search, filtering, sorting, and result behavior for the HQPorner API."
public_url: "https://docs.echteralsfake.me/hqporner/"
aliases:
  - "HQPorner Search and filtering"
keywords:
  - "HQPorner"
  - "Search and filtering"
---

# Search and filtering — HQPorner API

Explains the documented search, filtering, sorting, and result behavior for the HQPorner API.

Perform searches or sort categories using these helper Enums:

```python
from base_api import ResultOrder
from base_api.modules.config import IteratorConfig
from hqporner_api import Category, Sort

async for result in client.get_videos_by_category(
    category=Category.QUALITY_4K,
    pages=3,
    iterator_config=IteratorConfig(
        load_specific_sources=("html",),
        order=ResultOrder.ORIGINAL,
    ),
):
    if result.succeeded:
        print(result.unwrap().title)
```

## Sorting Enums

### Sort (Top Lists)

Enum Value| Description
---|---
`Sort.ALL_TIME`| All time top videos
`Sort.WEEK`| Weekly top videos
`Sort.MONTH`| Monthly top videos

### Category (Slugs)

A partial list of available categories within the `Category` StrEnum (refer to `hqporner_api.modules.locals` for the full list):

Enum Member| Slug Value
---|---
`Category.QUALITY_HD`| "1080p-porn"
`Category.QUALITY_4K`| "4k-porn"
`Category.FPS_60`| "60fps-porn"
`Category.MILF`| "milf"
`Category.LESBIAN`| "lesbian"
`Category.POV`| "pov"
`Category.ASIAN`| "asian"
`Category.AMATEUR`| "amateur"

## Related MCP documents

- [HQPorner API getting started](../getting-started.md)
- [Errors and troubleshooting — HQPorner API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/hqporner/](https://docs.echteralsfake.me/hqporner/)
