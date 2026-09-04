---
title: "Search and iteration — MissAV API"
summary: "Explains the documented search, filtering, sorting, and result behavior for the MissAV API."
public_url: "https://docs.echteralsfake.me/missav/"
aliases:
  - "MissAV Search and iteration"
keywords:
  - "MissAV"
  - "Search and iteration"
  - "succeeded"
  - "unwrap"
  - "item"
  - "error"
  - "stage"
---

# Search and iteration — MissAV API

Explains the documented search, filtering, sorting, and result behavior for the MissAV API.

MissAV uses a **Recombee** recommendation engine for its search functionality. The API wrapper replicates the browser's HMAC-SHA1 signed POST requests to the Recombee client API.

**How it works**

  1. Generates an anonymous user ID (`anon_<hex>`)
  2. Signs the API path with HMAC-SHA1 using the public token
  3. Sends a POST request with the search query and count
  4. Parses recommendation results into video URLs
  5. Concurrently fetches full video metadata for each result

```python
# Search for JAV content by code or keyword
async for result in client.search("SSIS", video_count=25):
    if result.succeeded:
        video = result.unwrap()
        print(f"{video.title} — {video.publish_date}")
    else:
        print(f"{result.stage} failed: {result.error}")
```

## Iterator results

Every search iteration yields a `ScrapeResult[Video]`. Test `succeeded` before reading the value, use `unwrap()` when failure should raise, or inspect the fields directly.

## succeeded

Description: True when the item was scraped successfully.

## unwrap

Description: Returns the Video , or raises the stored error.

## item

Description: The optional Video value.

## error

Description: The optional exception for a failed result.

## stage

Description: The failing iterator stage, such as page or item.

## Related MCP documents

- [MissAV API getting started](../getting-started.md)
- [Errors and troubleshooting — MissAV API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/missav/](https://docs.echteralsfake.me/missav/)
