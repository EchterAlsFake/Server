# Documentation System — Brain Context for Resume

## Project Overview
This is a plug-and-play documentation website system for **EchterAlsFake's Porn API** ecosystem.
The author (Johannes Habel) maintains **15 Python API wrappers/scrapers**, all sharing:
- A common base dependency: **eaf_base_api** (v4.0.0; wrappers require `eaf-base-api>=4.0.0`)
- A consistent architecture: `Client → Video / Pornstar / Channel` objects
- Async-first design using `asyncio` + `curl_cffi`

## Architecture Decisions

### Template System
- `template.html` — The master layout with all CSS/JS/fonts baked in. Uses `<!-- SLOT:xxx -->` comment markers that each API doc replaces.
- Each API gets its own `{api_name}.html` file that defines content blocks that get injected into template slots.
- Since the final deployment is static HTML on `https://echteralsfake.me/docs/{api_name}`, we use a simple Python build script (`build.py`) that reads the template and each API's content file, replaces the slots, and writes final HTML.

### Shared Content & Generalization
- **eaf_base_api** has been stripped into its own dedicated documentation (`eaf_base_api.html`).
- All other specific API docs (e.g. `xvideos.html`) **do not duplicate** base networking or configuration documentation. Instead, they provide a simple `Client` initialization example that points to the `eaf_base_api` documentation.
- All documentation files include a standardized `Intro Section` containing a Legal Disclaimer, Support/Commercial Licensing info (with NowPayments crypto embed button, PayPal, and Ko-Fi links), and a quick feature summary.
- **Local Assets**: All external resources (like fonts or donation buttons) are downloaded to an `assets/` directory and copied to `dist/assets/` during build to ensure the website is completely self-contained.

### Design Philosophy
- Modern dark-themed documentation with a premium feel
- Collapsible sidebar navigation for Core Objects (e.g. `Client`, `Video`), automatically expanding the current section when scrolling or toggling on click.
- High-readability typography layout scaled for larger monitors:
  - Base body font size is `21px`.
  - H2 headers are `52px` (with `48px` custom icons).
  - H3 headers are `38px` and H4 headers are `30px`.
  - `.method-title` is `34px` and `.method-section-title` is `22px`.
  - `.method-signature` text is `16px`.
- Method Cards structured for rapid scanning:
  - Header & tag (e.g., `Fetch Video get_video()` + `async`) at the top.
  - Descriptive summary/what it does immediately below the header.
  - Formatted multi-line syntax highlighted signature block (styled using `token-` classes and `white-space: pre-wrap;` preserving indents with one parameter per line).
  - Parameters and returns detailed at the bottom.
- Roboto font (embedded locally via woff2 files to avoid external requests)
- Glassmorphism cards, smooth transitions, accent gradients
- Adjusted text accent colors to Sky Blue (`#38bdf8`) for better readability against the dark background, while keeping violet for accents/borders.

### Key Slots in Template
- `SLOT:TITLE` — The API name
- `SLOT:HERO_TITLE` — Hero section title
- `SLOT:HERO_SUBTITLE` — Subtitle/description
- `SLOT:SIDEBAR_NAV` — Sidebar navigation links  
- `SLOT:MAIN_CONTENT` — The full docs body
- `SLOT:VERSION` — Version string
- `SLOT:GITHUB_URL` — Link to GitHub repo
- `SLOT:PYPI_PACKAGE` — pip install name

## Completed APIs

The core documentation and all **15 wrapper APIs** are present and complete:

1. **eaf_base_api** — shared core documentation
2. **beeg**
3. **eporner**
4. **hqporner**
5. **missav**
6. **pornhub**
7. **porntrex**
8. **redtube**
9. **spankbang**
10. **thumbzilla**
11. **tube8**
12. **xfreehd**
13. **xhamster**
14. **xnxx**
15. **xvideos**
16. **youporn**

There are no pending wrapper pages. Each source file builds to `dist/{api_name}/index.html`.

## File Structure
```
/home/asuna/PycharmProjects/Server/docs/
├── BRAIN_CONTEXT.md          # This file - resume context
├── template.html             # Master HTML template
├── index_template.html       # Central API portal template
├── build.py                  # Build script: template + content → final HTML
├── transparency.html         # Source for the AI transparency page
├── assets/                   # Local fonts and donation artwork
├── content/                  # eaf_base_api.html + all 15 wrapper sources
└── dist/                     # Generated output; never hand-edit
    ├── index.html
    ├── assets/
    ├── transparency/index.html
    └── {api_name}/index.html
```

## eaf_base_api v4 Summary (Key for All Docs)

- **RuntimeConfig**: 26 configuration attributes. These cover separate byte-bounded response/segment cache sizes and TTLs; bounded request retries (`request_attempts`, initial/max delay, multiplier, and jitter); delay/timeout/bandwidth; singular `proxy`; HTTP version, DoH, impersonation/JA3, proxy auth, TLS/environment/cookies/locale; download workers; iterator page/item concurrency; and interface binding. `request_multiplier` is both the exponential base for `BaseCore` request backoff and the multiplier used when `IteratorConfig.resolve()` derives Helper stage policies.
- **CachePolicy and caches**: requests use explicit cache policy with separate byte-bounded TTL caches for text responses and media segments. The old item-count/FIFO description is obsolete.
- **BaseCore**: lazy async session lifecycle and context-manager support; `initialize_session()` is idempotent, configured cookies are applied when each new session is created, and `close()` clears the session so a later request can recreate it from the current configuration. The core also provides generic `request()` plus `fetch_text()` and `fetch_bytes()`, retry/backoff, cache policy, HLS and raw downloads, quality selection, resume/cancel/report support, and optional remuxing.
- **BaseMedia**: source-aware lazy fields declared with `media_field("source")`. Models register `loader_methods`, then use `load_sources()`, `load_fields()`, and `get_field()`. Loader results are mapped strictly and unresolved access raises typed media-field errors.
- **Helper / iteration**: `Helper.iterator(..., iterator_config=IteratorConfig(...))` returns a `ScrapeStream` async context manager. Wrapper methods accept one `IteratorConfig` and yield immutable `ScrapeResult[T]` values with `stage`, `url`, `page_index`, `item_index`, `attempts`, `item`, `error`, `succeeded`, and `unwrap()`.
- **Iterator policy**: `IteratorConfig` centralizes page/item concurrency, pending-item limits, extraction threading, `ResultOrder`, `ErrorMode`, `RetryPolicy`, page/item handlers, and specific source/field loading. A wrapper-supplied default is replaced—not merged—when callers pass their own config, so preserve required sources such as `("html",)` and error behavior. Every current wrapper iterator default uses `page_error_mode=ErrorMode.SKIP`; a bare caller-created `IteratorConfig` uses `ErrorMode.YIELD`.
- **Retry and custom errors**: `RetryPolicy.max_attempts` includes the first call and provides bounded exponential delay, jitter, and exception filtering. Independent page/item handlers receive `ScrapeErrorContext` only for their own stage and return `ErrorAction.RETRY`, `RAISE`, `YIELD`, or `SKIP`; either handler can be omitted without affecting the other stage.
- **DownloadConfigHLS / DownloadConfigRAW**: HLS supports quality/path, remux, resume state, stop/callbacks, cleanup, segment persistence, and reports. `BaseCore.download()` uses that core's current `RuntimeConfig.timeout` and `max_workers_download` when dispatching HLS work. RAW supports direct/multipart downloads, workers, timeouts, chunks, and retries.
- **Errors**: expanded typed networking, HTTP/proxy/bot, media-load, scrape-operation, cache/download, and configuration error hierarchy.

## XVideos API Summary
- **Client**: Entry point. `get_video()`, `search()`, `get_playlist()`, `get_pornstar()`, `get_channel()`, `get_account()`
- **Video(BaseMedia)**: 19 attributes (title, description, tags, views, likes, m3u8, etc.). `download(config)`, `get_author`, `get_pornstars`
- **BaseChannelPornstar(BaseMedia)**: Shared base for Channel/Pornstar. `videos()`, `worked_for_with()`
- **Channel(BaseChannelPornstar)**: URL sanitization for /channels/ paths
- **Pornstar(BaseChannelPornstar)**: Extra: gender, age, video_tags
- **Account**: Auth'd actions. `get_recommended_videos()`, `get_liked_videos()`, `get_watch_later_videos()`
- **Sorting Enums**: Sort, SortDate, SortVideoTime, SortQuality (all StrEnum)
- **Custom Errors**: NotFound, NetworkError, BotDetection, ProxyError, UnknownNetworkError, DownloadFailed, NoLoginCookies

## How to Resume
When the user says "resume", read this file to understand the full context, then:
1. Work from `/home/asuna/PycharmProjects/Server/docs` and treat `content/*.html` as the source of truth. Never edit `dist/` by hand.
2. Inspect each package's `pyproject.toml`, current public code, `git status`, and the requested `git log`/`git diff` window before editing. Update the `SLOT:VERSION`, dependency requirement, signatures, model types, configuration examples, and a dated commit-based changelog from that evidence.
3. Keep wrapper pages concise about shared internals: link to the eaf core page, but document the wrapper's exact `IteratorConfig` parameter name, required `load_specific_sources`, package retry defaults, and `ScrapeResult[T]` behavior.
4. Structuring Method Cards & Sidebar:
   - Restructure signatures to use one parameter per line, using the token CSS formatting classes (e.g. `token-keyword`, `token-builtin`, `token-class`, etc.) for syntax highlighting.
   - Design each method card with description and tag at the top, signature code block in the middle, and detailed parameters/returns at the bottom.
   - Nest all client and object methods under collapsible `nav-collapsible` divs in the sidebar to maintain screen clean-lines.
5. Preserve the common Intro block (Disclaimer + Donations) in `MAIN_CONTENT`. Do not duplicate the full base reference in every wrapper; a focused v4 configuration/iteration example and link are sufficient.
6. Run `python build.py` from `/home/asuna/PycharmProjects/Server/docs`. This rebuilds every API page and the portal, copies `assets/`, and copies `transparency.html` to `dist/transparency/index.html`.
7. Validate slot markers, sidebar anchors, stale v3 tokens (`proxies`, iterator callback/concurrency arguments, `result.is_success`, `result.video`, `await for`), current versions, and a clean source-to-dist rebuild diff.
