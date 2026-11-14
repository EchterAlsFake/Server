---
title: "Errors and troubleshooting — Porn.com API"
summary: "Provider ParseError, VideoUnavailable referrals, shared MediaLoadError and PageFetchError cause chains, invalid URLs and expired HLS sources."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["Errors and troubleshooting — Porn.com API", "Errors and troubleshooting Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "errors", "ParseError", "MediaLoadError", "PageFetchError", "VideoUnavailable", "DownloadFailed"]
---

# Errors and troubleshooting — Porn.com API

Provider error imports are available through `porn_api.errors`:

| Exception | Meaning |
|---|---|
| `ParseError` | Unrecognized/mismatched target layout, unexpected redirect, missing listing region, or repeated pagination. |
| `NotFound` | Missing resource translated by the shared request helper. |
| `NetworkError` | Shared request/network failure translated by the helper. |
| `BotDetection` | Bot-protection failure detected by the shared backend. |
| `ProxyError` | Proxy/SSL configuration failure translated by the helper. |
| `UnknownNetworkError` | Shared unknown transport error. |
| `VideoUnavailable` | No native public HLS source, an external referral, or protected media. |
| `DownloadFailed` | Download failure wrapped with resource/API context. |
| `ScraperException` | Shared provider exception base. |

Errors inside a lazy metadata loader are normally wrapped in shared
`MediaLoadError`; several source failures can use `MediaLoadErrors`. Inspect
`original_error`/the exception cause instead of expecting a bare provider error
from every Client getter. `Video.download` preserves `VideoUnavailable` and
shared cancellation while wrapping other download errors with `DownloadFailed`.

Shared `DataNotLoadedError` means a declared lazy field has not been loaded.
Load the `html` source or the required fields. Unsupported sources such as `api`
or `media` raise loader configuration errors. They are not substitutes for an
actual network source on this site.

Listing failures use `PageFetchError`, `ItemFetchError`, or configured yielded
`ScrapeResult.error` values. Always unwrap yielded results. A speculative terminal
404 after a confirmed listing page ends iteration; an initial explicit missing
page still raises. Other errors are not converted into successful empty videos.

| Symptom | Check |
|---|---|
| `ValueError` on a URL | Supply an absolute verified host and real `/scene/<numeric-id>[/<slug>]` route, not `/out/...` or a guessed mirror. |
| Referral is not downloadable | Load HTML and inspect `is_playable`/`unavailable_reason`; metadata does not imply Porn.com hosts the stream. |
| HTML says the wrong profile type | Use the corresponding real Pornstar/Channel/Source/Category getter. |
| Old HLS source fails | Keep normal `refresh=True` download behavior; signatures expire and can vary by session. |
| No exact requested resolution | Inspect `get_qualities()`; nearest-tier fallback is intentional. |
| MPEG-TS data in a `.mp4` filename | Enable `remux=True` with FFmpeg for an MP4 container. |
| Counts differ from yielded unique IDs | Account for native ad replacements and visible duplicate occurrences before assuming missing videos. |
| Next is disabled despite more entries | Use `pages="all"`; this provider probes the established numeric route to its real end. |

The REST metadata root (401), `/pics` (403), encrypted/protected streams, and
authenticated-only features are outside this integration. Do not treat access
denial as a valid empty model. See [source loading](../guides/source-loading.md)
and [iteration](../guides/iteration-and-results.md).
