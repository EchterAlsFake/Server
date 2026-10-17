---
title: "Search and filtering — TNAFlix API"
summary: "Explains the documented search, filtering, sorting, and result behavior for the TNAFlix API."
public_url: "https://docs.echteralsfake.me/tnaflix/"
aliases:
  - "TNAFlix Search and filtering"
keywords:
  - "TNAFlix"
  - "Search and filtering"
---

# Search and filtering — TNAFlix API

Explains the documented search, filtering, sorting, and result behavior for the TNAFlix API.

Perform advanced video searches on TNAFlix using the `client.search()` generator combined with sorting criteria:

```python
from tnaflix_api import Client
from tnaflix_api.modules.sorting import Sort, SortDate

client = Client()

# Search for top-rated videos from the past month
async for result in client.search(
    query="blonde",
    sorting_sort=Sort.TOP_RATED,
    sorting_date=SortDate.THIS_MONTH,
    pages=3
):
    if result.succeeded:
        video = result.unwrap()
        print(video.title, video.url, video.length)
    else:
        print(f"Error: {result.error}")
```

## Related MCP documents

- [TNAFlix API getting started](../getting-started.md)
- [Errors and troubleshooting — TNAFlix API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tnaflix/](https://docs.echteralsfake.me/tnaflix/)
