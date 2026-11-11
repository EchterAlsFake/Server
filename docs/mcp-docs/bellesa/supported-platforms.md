---
title: "Supported platforms and hosts — Bellesa API"
summary: "Verified Linux/Python environment, bellesa.co and www.bellesa.co URL routes, English-only locale and separate service boundaries."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Supported platforms and hosts — Bellesa API", "Bellesa supported platforms"]
keywords: ["Bellesa", "bellesa_api", "hosts", "bellesa.co", "www.bellesa.co", "locale", "Linux", "Python"]
---

# Supported platforms and hosts — Bellesa API

The implementation was validated on Linux x86_64 with Python 3.15 and FFmpeg/ffprobe.
Python 3.12+ is required. Other operating systems were not verified in that run.

Accepted page hosts are exactly `bellesa.co` and `www.bellesa.co`, using HTTP/HTTPS input
and normalized HTTPS model URLs. Bare-host HTML redirects to www; model URLs retain the
supplied accepted host. Video IDs and handle identity are checked before loaded data
is accepted. Arbitrary lookalike hosts, unrelated subdomains, and nonstandard ports are
not accepted. Public media uses `s.bellesa.co`.

| Object | Accepted path |
|---|---|
| Video | `/videos/{positive-numeric-id}` or `/videos/{id}/{title-slug}` |
| Performer | `/performers/{handle}` |
| Channel | `/channels/{handle}` |
| Category | `/videos/categories/{handle}` |

Object getters require complete URLs. Query/fragment data is removed from object
identity. There is no `base_url` argument, bare-ID convenience getter, arbitrary CDN URL
input, locale selector or mirror-host pattern.

Observed locale: **English**. No language subdomain or alternate/proxy host was verified.
Bellesa Plus, BBoutique, BellesaCams and non-video story/article resources are separate
services outside these public provider objects. No authenticated account, saved playlist,
Model/Pornstar subtype separate from Performer, or user-upload profile was verified.

See [getting started](getting-started.md) and [validation](guides/live-validation.md).
