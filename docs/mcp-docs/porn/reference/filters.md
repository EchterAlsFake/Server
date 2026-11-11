---
title: "Filters — Porn.com API"
summary: "Frozen Filters dataclass, added_days source hd min_minutes max_minutes units, validation and apply URL behavior."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Filters — Porn.com API", "Filters Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "Filters", "added_days", "source", "hd", "min_minutes", "max_minutes", "apply"]
---

# Filters — Porn.com API

`Filters` is a frozen, slotted dataclass exported by `porn_api`:

```python
Filters(added_days: Literal[1, 7, 30, 90, 365] | None = None,
        source: str | None = None, hd: bool = False,
        min_minutes: int | None = None, max_minutes: int | None = None)
```

| Field | Website parameter | Meaning |
|---|---|---|
| `added_days` | `ad` | Today, week, month, three months, or year; None leaves the period unrestricted. |
| `source` | `so` | Actual source label such as `xVideos` or `XNXX`. |
| `hd` | `qu=hd` | Request the site's HD filter. |
| `min_minutes` | `ll` | Nonnegative integer minimum, in minutes. |
| `max_minutes` | `lh` | Nonnegative integer maximum, in minutes. |

`filters.apply(url)` returns the URL with these named filter parameters
replaced; `None`/false settings remove their corresponding keys. Other query
keys are preserved. Supplying a Filters object therefore replaces existing
values for these filter keys; omitting it preserves an existing URL's filters.

Unsupported added periods, negative/non-integer duration bounds, or an inverted
minimum/maximum raise `ValueError`. The implementation performs duration
validation when `apply()` is called. There is no separate sorting enum or sort
parameter. Listing filter behavior follows the website, including injected
cards that can fall outside a requested filter.

See [searching](../guides/searching-and-filtering.md).
