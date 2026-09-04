---
title: "BaseMedia — eaf_base_api"
summary: "Documents BaseMedia behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API BaseMedia"
  - "eaf base BaseMedia"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "BaseMedia"
---

# BaseMedia — eaf_base_api

Documents BaseMedia behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

Remote fields are declared with `media_field()`. The first source has highest precedence. A loader is async, returns a complete mapping, and never mutates the object directly; results are validated and committed atomically.

```python
from dataclasses import dataclass
from typing import ClassVar
from base_api import BaseMedia, media_field

@dataclass(kw_only=True, slots=True)
class Video(BaseMedia):
    title: str | None = media_field("html", "api")
    duration: int | None = media_field("api")

    loader_methods: ClassVar[dict[str, str]] = {
        "html": "_load_html",
        "api": "_load_api",
    }

    async def _load_html(self) -> dict[str, object]:
        data = await fetch_html(self.url)
        return {"title": data.get("title")}

    async def _load_api(self) -> dict[str, object]:
        data = await fetch_api(self.url)
        return {"title": data.get("title"), "duration": data.get("duration")}
```

Operation| Meaning
---|---
`await media.load_sources("html", "api")`| Load named sources concurrently; repeated calls are idempotent
`await media.load_fields("title")`| Select the smallest useful source set for unresolved fields
`await media.get_field("title")`| Load one field if necessary and return it
`media.loaded_sources`| Immutable set of successful source names
`media.source_state("html")`| `NOT_LOADED`, `LOADING`, `LOADED`, or `FAILED`
`media.source_errors`| Copy of the latest failure per source
`media.is_field_loaded(name)`| True even when a loader deliberately returned `None`
`media.unloaded_fields()`| Names still holding the private unloaded marker
`media.to_dict()`| Serialize loaded public fields without triggering lazy-field errors

Direct access to an unresolved field raises `DataNotLoadedError`. Use `retry_failed=False` with a load method when a previously failed source should not be attempted again.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
