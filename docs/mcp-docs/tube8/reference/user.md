---
title: "User — Tube8 API"
summary: "Documents User behavior, signatures, fields, constraints, and examples for the Tube8 API."
public_url: "https://docs.echteralsfake.me/tube8/"
aliases:
  - "Tube8 User"
keywords:
  - "Tube8"
  - "User"
---

# User — Tube8 API

Documents User behavior, signatures, fields, constraints, and examples for the Tube8 API.

`Client.get_user(url, load_html=True)` returns a public User object when the site supplies a usable profile identity. `User.get_videos(pages=2, iterator_config=None)` streams public videos.

## Behavior and edge cases

Empty public User pages raise a media-loading error with `Profile identity not found`; generic session names are not treated as a profile identity. A working public User video feed remains unverified. Channel, pornstar and amateur feeds have live coverage.

## Related MCP documents

- [Tube8 API getting started](../getting-started.md)
- [Errors and troubleshooting — Tube8 API](../troubleshooting/errors.md)
- [Overview — eaf_base_api](../../eaf-base-api/overview.md)
- [Legal disclaimer for EAF API wrappers](../../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/tube8/](https://docs.echteralsfake.me/tube8/)
