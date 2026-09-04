---
title: "User — YouPorn API"
summary: "Documents User behavior, signatures, fields, constraints, and examples for the YouPorn API."
public_url: "https://docs.echteralsfake.me/youporn/"
aliases:
  - "YouPorn User"
keywords:
  - "YouPorn"
  - "User"
  - "get_collections"
  - "url"
  - "name"
  - "collection_urls"
---

# User — YouPorn API

Documents User behavior, signatures, fields, constraints, and examples for the YouPorn API.

dataclass Inherits from `BaseMedia`. Represents a registered user account profile page.

## Attributes

## url

Type: str; Description: Profile page URL

## name

Type: str | None; Description: Username display name

## collection_urls

Type: list[str] | None; Description: List of relative collection paths created by the user

## Methods

## get_collections

Yields playlist collections created by this user.

```python
async for collection in user.get_collections(
    load_html: bool = True
) -> AsyncGenerator[Collection, None]
```

### Parameters
- load_html bool — Pre-load full collection metadata (default: `True`)

### Returns

→ AsyncGenerator[Collection, None]

## Related MCP documents

- [YouPorn API getting started](../getting-started.md)
- [Errors and troubleshooting — YouPorn API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/youporn/](https://docs.echteralsfake.me/youporn/)
