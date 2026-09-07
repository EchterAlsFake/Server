---
title: "Scraper Utilities — eaf_base_api"
summary: "Documents the centralized parsing, DOM extraction, playlist generation, and exception helper functions in eaf_base_api."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Scraper Utilities"
  - "eaf base utils"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "get_text_safe"
  - "get_attr_safe"
  - "parse_duration"
  - "parse_count"
  - "build_m3u8_master"
  - "str_to_bool"
  - "is_resource_gone"
  - "contains_resource_gone"
---

# Scraper Utilities — eaf_base_api

Documents centralized parsing, DOM extraction, playlist generation, and exception helper functions in `eaf_base_api`.

These functions are exported from `base_api` and `base_api.modules.static_functions` for consistent behavior across all scrapers.

## DOM Extraction

### get_text_safe

```python
def get_text_safe(node: Any, selector: str | None = None) -> str | None
```

Safely extracts and strips text from a Selectolax/Lexbor HTML node or matching CSS sub-selector. Returns `None` if the node is missing, the selector matches nothing, or the stripped text is empty.

### get_attr_safe

```python
def get_attr_safe(node: Any, attr: str, selector: str | None = None) -> str | None
```

Safely extracts an HTML attribute string from a node or matching CSS sub-selector. Returns `None` if the node is missing, the attribute does not exist, or the value is empty.

## Data Parsing

### parse_duration

```python
def parse_duration(text: str | None) -> int | None
```

Parses diverse human-readable duration strings into integer total seconds. Supports formats:
- Colon notation: `"12:34"` (754s), `"1:23:45"` (5025s), `"0:45"` (45s)
- Unit suffixes: `"1h 23m 45s"`, `"12m"`, `"45s"`
- Returns `None` if input is empty or unparseable.

### parse_count

```python
def parse_count(text: str | int | float | None) -> int | None
```

Parses view counts, like counts, and subscriber numbers with human-readable suffixes into integers:
- Suffixes: `K` (thousand), `M` (million), `B` (billion) — e.g. `"1.5M"` -> `1500000`, `"250K"` -> `250000`
- Thousands separators: `"1,234,567"` or `"1.234.567"` -> `1234567`
- Numeric types: passed through as `int(text)`

### str_to_bool

```python
def str_to_bool(value: Any) -> bool
```

Coerces common string boolean representations into boolean:
- Truthy: `"true"`, `"1"`, `"yes"`, `"y"`, `True`, `1`
- Falsy: `"false"`, `"0"`, `"no"`, `"n"`, `False`, `0`, `None`, `""`

## Playlists

### build_m3u8_master

```python
def build_m3u8_master(streams: list[dict[str, Any]] | dict[str, str]) -> str
```

Constructs a standard HLS master playlist string (`#EXTM3U`) containing `#EXT-X-STREAM-INF` tags from stream definitions. Used by scrapers to generate local master playlists from fragmented video sources or quality maps.

## Exception Helpers

### is_resource_gone

```python
def is_resource_gone(exc: BaseException) -> bool
```

Checks if an exception represents a permanently unavailable resource (HTTP 404 Not Found, HTTP 410 Gone, or `ResourceGone`). Unwraps nested causes.

### contains_resource_gone

```python
def contains_resource_gone(exc: BaseException) -> bool
```

Recursively inspects aggregate exceptions (such as `MediaLoadErrors`) to check if any contained error is resource gone.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [BaseMedia — eaf_base_api](base-media.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
