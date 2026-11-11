---
title: "EAF Python API documentation overview"
summary: "Introduces the EAF asynchronous Python API ecosystem, its shared base engine, wrapper packages, and common capabilities."
public_url: "https://docs.echteralsfake.me/"
aliases:
  - "EchterAlsFake API docs"
  - "EAF API wrappers"
keywords:
  - "EAF"
  - "Python API"
  - "async"
  - "eaf_base_api"
  - "API wrappers"
---

# EAF Python API documentation overview

Introduces the EAF asynchronous Python API ecosystem, its shared base engine, wrapper packages, and common capabilities.

## Core engine

The shared request, media-loading, iteration, caching, and download runtime used by every wrapper.

### [Base API](eaf-base-api/overview.md)

v4.2.5

The version 4 asynchronous networking and media-loading engine for EchterAlsFake API wrappers. It provides explicit request APIs, bounded retries, byte-limited TTL caches, source-aware media models, structured scrape streams, and HLS/RAW downloads.

## API wrappers

Site-specific packages with a consistent async interface and typed media objects.

### [Beeg API](beeg/getting-started.md)

v1.7.4

A fully asynchronous Python API wrapper and scraper for Beeg. Fetch video metadata by parsing external API endpoints, and download streams via HLS. Powered by the eaf_base_api networking engine.

### [Bellesa API](bellesa/getting-started.md)

v1.0.0

An asynchronous Python wrapper for Bellesa videos, performers, channels and categories. Includes typed search, filtered listings, independent API/HTML metadata, actual-quality media inspection, and HLS/MP4 downloads through eaf_base_api.

### [EMPFlix API](empflix/getting-started.md)

v1.0.1

A fully asynchronous Python API wrapper and scraper for empflix.com. Extract full video metadata, user profiles, and pornstars, run search queries, and download high-definition progressive MP4 media. Powered by the eaf_base_api networking engine.

### [Eporner API](eporner/getting-started.md)

v2.5.3

A fully asynchronous Python API wrapper and scraper for Eporner. Fetch video details via API and HTML endpoints, download files directly with multi-threaded range requests, and retrieve pornstar biographies. Powered by the eaf_base_api networking engine.

### [HQPorner API](hqporner/getting-started.md)

v2.5.2

A fully asynchronous Python API wrapper and scraper for HQPorner. Fetch videos, metadata, search, get videos by actress or category, and download content — all powered by the eaf_base_api networking engine.

### [MissAV API](missav/getting-started.md)

v2.6.2

A fully asynchronous Python API wrapper and scraper for MissAV. Fetch JAV video metadata and download streams via HLS. Features Recombee-powered search with HMAC-signed API requests. Powered by the eaf_base_api networking engine.

### [Porn.com API](porn/getting-started.md)

v0.1.0

An asynchronous Python wrapper for Porn.com scenes, performers, channels, categories and source indexes. Includes lazy HTML metadata, filtered search, complete profile pagination, verified language hosts and public HLS downloads through eaf_base_api. Install the local checkout before publication.

### [Pornhat API](pornhat/getting-started.md)

v0.1.0

An asynchronous Python wrapper for Pornhat videos, model/channel profiles, tags and paysite collections, with lazy HTML/media sources, search, sortable directories and HLS downloads through eaf_base_api.

### [PornHub API](pornhub/getting-started.md)

v5.4.6

A fully asynchronous Python API wrapper and scraper for Pornhub. Fetch videos, GIFs, shorts, albums, playlists, pornstars, models, channels, and user profiles — with full account login support. Powered by the eaf_base_api networking engine.

### [Porndoe API](porndoe/getting-started.md)

v1.0.1

An asynchronous Python wrapper for the Porndoe public video catalog. Includes rich video metadata, playable sources, search, categories, pornstar and channel profiles, paginated listings and downloads through eaf_base_api.

### [Porntrex API](porntrex/getting-started.md)

v1.8.3

A fully asynchronous Python API wrapper and scraper for Porntrex. Fetch video metadata, channel information, and model profiles, run search queries, and download media via direct CDN links. Powered by the eaf_base_api networking engine.

### [RedGIFs API](redgifs/getting-started.md)

v0.1.0

An asynchronous Python wrapper for RedGIFs videos, images, creators, tags, niches and public collections. Includes independent API/HTML metadata, typed result streams and direct MP4/JPG downloads through eaf_base_api. Live validation remains incomplete because of rate limits and upstream pagination omissions.

### [Redtube API](redtube/getting-started.md)

v1.4.4

A fully asynchronous Python API wrapper and scraper for Redtube. Fetch video details, custom playlists, publishers channels, users, and pornstars. Stream downloads via HLS. Powered by the eaf_base_api networking engine.

### [SpankBang API](spankbang/getting-started.md)

v2.4.4

A fully asynchronous Python API wrapper and scraper for SpankBang. Fetch videos, metadata, search, and iterate over channels, creators, or pornstars. Download content using HLS or direct RAW MP4 downloads. Powered by the eaf_base_api networking engine.

### [Thumbzilla API](thumbzilla/getting-started.md)

v1.4.3

A fully asynchronous Python API wrapper and scraper for Thumbzilla. Fetch video metadata, playlists, pornstar biographies, amateur profiles, and studio channels. Stream downloads via HLS with auto-constructed master playlists. Powered by the eaf_base_api networking engine.

### [TNAFlix API](tnaflix/getting-started.md)

v1.0.1

A fully asynchronous Python API wrapper and scraper for tnaflix.com. Extract full video metadata, publisher channels, user profiles, and pornstars, run search queries, and download high-definition progressive MP4 media. Powered by the eaf_base_api networking engine.

### [Tube8 API](tube8/getting-started.md)

v1.3.3

A fully asynchronous Python API wrapper and scraper for Tube8. Fetch video metadata, pornstar biographies, amateur profiles, and studio channels. Stream downloads via HLS with auto-constructed master playlists. Powered by the eaf_base_api networking engine.

### [XFreeHD API](xfreehd/getting-started.md)

v1.7.4

A fully asynchronous Python API wrapper and scraper for XFreeHD. Fetch video metadata, photo albums, execute search queries, and download media files directly from CDNs. Powered by the eaf_base_api networking engine.

### [xHamster API](xhamster/getting-started.md)

v2.6.5

A fully asynchronous Python API wrapper and scraper for xHamster. Fetch video details, shorts, channel information, pornstar metadata, or log into user accounts. Stream downloads via HLS. Powered by the eaf_base_api networking engine.

### [XNXX API](xnxx/getting-started.md)

v2.4.4

A fully asynchronous Python API wrapper and scraper for XNXX. Fetch videos, metadata, search with complex filters, and iterate over user uploads — all powered by the eaf_base_api networking engine.

### [XVideos API](xvideos/getting-started.md)

v2.5.3

A fully asynchronous Python API wrapper and scraper for XVideos. Fetch videos, metadata, pornstar profiles, channels, playlists, and download content — all powered by the eaf_base_api networking engine.

### [YouPorn API](youporn/getting-started.md)

v1.8.3

A fully asynchronous high-speed Python API wrapper and scraper for YouPorn. Fetch video details, custom collections, publisher channels, user uploads, and pornstar metadata. Supports dual streaming modes (HLS and raw MP4). Powered by the eaf_base_api networking engine.

### [YouJizz API](youjizz/getting-started.md)

v0.1.0

An asynchronous API for public video metadata, user uploads, pornstar and tag directories, search, lazy API/HTML/comments sources and MP4/HLS downloads. Powered by eaf_base_api.

## Shared capabilities

### Async by default

Built around `asyncio` with bounded page and item concurrency.

### Typed lazy models

Load only the media sources and fields required by your workflow.

### Explicit networking

Configure retries, proxies, TLS impersonation, caching, and request limits per core.

### HLS and RAW downloads

Quality selection, bounded workers, cancellation, resume state, and optional remuxing.

### Structured results

Typed scrape outcomes expose stage, attempts, source URL, item, and error context.

### Unified policies

One iterator configuration controls ordering, retries, loading, and error behavior.

## Related MCP documents

- [Legal disclaimer for EAF API wrappers](legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/](https://docs.echteralsfake.me/)
