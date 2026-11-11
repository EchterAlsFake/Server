---
title: "Supported platforms and hosts — RedGIFs API"
summary: "Verified Linux/Python environment, accepted page/CDN hosts, watch/embed/user/niche routes and lowercase identity rules."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Supported platforms and hosts — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "hosts"
  - "platforms"
  - "media.redgifs.com"
  - "ifr"
  - "watch"
---

# Supported platforms and hosts — RedGIFs API

Requires Python 3.12+. Live checks ran on Linux with CPython 3.15.2 and local
`eaf-base-api` 4.2.6, curl-cffi 0.17.0 and selectolax 1.0.2. Other platforms and Python
versions were not live-verified. ffprobe is needed for live file validation, not for
normal transfers. There is no runtime FFmpeg requirement for direct MP4/JPG downloads.

## Accepted hosts and routes

| Input | Behavior |
| --- | --- |
| `redgifs.com`, `www.redgifs.com` | Verified first-party page hosts; canonical objects use https://www.redgifs.com |
| `/watch/<id>`, `/ifr/<id>` on those hosts | Video/image identity; HTML/API loaders validate the requested media type |
| `media.redgifs.com` MP4/JPG media URLs | Identity input resolves through the API; actual source URLs retain casing and queries |
| `/users/<username>` on a page host | User getter; plain username also accepted |
| `/niches/<id>` on a page host | Niche getter; plain niche ID also accepted |
| `api.redgifs.com` | Internal public API origin, not a page-host input alias |

CDN suffixes such as `-mobile`, `-silent`, `-poster`, `-small`, `-medium`, `-large`
and `-timeline` normalize to the stable media ID. HLS fMP4 identities use `.m4s`;
this acceptance does not implement HLS downloading. Parsed IDs normalize to lowercase;
returned CDN paths are not lowercased or stripped of signatures.

No language/proxy variants, arbitrary subdomains, legacy thumbnail hosts or lookalike
domains are accepted. The client exposes no base_url/locale route option. HTTP(S) input
is normalized to the canonical HTTPS object identity. Each getter still requires the
proper resource route; a directory is not an individual media object.

Publication and current hosted documentation/CI status are not asserted by local
validation. The latest suite has 38 passing and 12 rate-limited failures; see
[validation](guides/live-validation.md) for actual capability coverage.
