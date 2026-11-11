---
title: "Supported platforms — Porn.com API"
summary: "Verified Linux/Python environment, twelve accepted porn.com hosts and response locales, orientations and unsupported mirrors or capabilities."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Supported platforms — Porn.com API", "Supported platforms Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "hosts", "locales", "Linux", "Python", "porn.com", "orientation"]
---

# Supported platforms — Porn.com API

The package requires Python **3.12+**. Initial live validation used **Linux with
CPython 3.15.2**, `eaf-base-api` 4.2.6, FFmpeg, and ffprobe. Other platforms or
Python versions have not been validated for this provider.

## Verified hosts and locales

| Host | Response locale |
|---|---|
| `porn.com` (redirects to `www.porn.com`) | `en-US` |
| `www.porn.com` | `en-US` |
| `de.porn.com` | `de-DE` |
| `es.porn.com` | `es-ES` |
| `fr.porn.com` | `fr-FR` |
| `it.porn.com` | `it-IT` |
| `jp.porn.com` | `ja-JP` |
| `ru.porn.com` | `ru-RU` |
| `nl.porn.com` | `nl-NL` |
| `pt.porn.com` | `pt-BR` |
| `pl.porn.com` | `pl-PL` |
| `se.porn.com` | `sv-SE` |

These hosts were discovered from real hreflang links and checked using scene
`208327863`, its 606-second duration, HLS master/variant, and a corresponding
performer profile/listing. `url` retains the input host; `resolved_url` records
the actual response where the shared helper supplies it. HTTP input normalizes
to HTTPS. Userinfo, unexpected ports, and unrelated/arbitrary hosts are rejected.
No alternate numbered domains, proxy hosts, or third-party mirrors are allowlisted.

Straight routes and `/gay`/`/trans` category/search/directory prefixes are
implemented. Orientation root entries are category directories, not video
grids. Sampled gay/trans grids had external referrals rather than native HLS.

## Boundaries

Only legitimately public native unencrypted HLS is downloaded. External source
websites are represented as source indexes/referrals, not crawled for media.
No account, playlist, separate Model/User type, full-video direct MP4, or
independent JSON video API was verified. The REST root returned 401 and `/pics`
returned 403. These inaccessible capabilities are not advertised as working.
Unobserved layouts and future site changes remain unverified.

See [recorded live evidence](guides/live-validation.md) and
[getting started](getting-started.md).
