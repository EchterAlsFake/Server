# Documentation System — Brain Context for Resume

## Project Overview
This is a plug-and-play documentation website system for **EchterAlsFake's Porn API** ecosystem.
The author (Johannes Habel) maintains **15+ Python API wrappers/scrapers** for adult sites, all sharing:
- A common base dependency: **eaf_base_api** (v3.3.3)
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
1. **eaf_base_api** — General networking library docs (eaf_base_api.html → builds to docs/dist/eaf_base_api/index.html)
2. **xvideos** — Full documentation done (xvideos.html → builds to docs/dist/xvideos/index.html)
3. **hqporner** — Full documentation done (hqporner.html → builds to docs/dist/hqporner/index.html)
4. **pornhub** — Full documentation done (pornhub.html → builds to docs/dist/pornhub/index.html)
5. **spankbang** — Full documentation done (spankbang.html → builds to docs/dist/spankbang/index.html)
6. **xnxx** — Full documentation done (xnxx.html → builds to docs/dist/xnxx/index.html)
7. **beeg** — Full documentation done (beeg.html → builds to docs/dist/beeg/index.html)
8. **porntrex** — Full documentation done (porntrex.html → builds to docs/dist/porntrex/index.html)
9. **xfreehd** — Full documentation done (xfreehd.html → builds to docs/dist/xfreehd/index.html)
10. **xhamster** — Full documentation done (xhamster.html → builds to docs/dist/xhamster/index.html)
11. **eporner** — Full documentation done (eporner.html → builds to docs/dist/eporner/index.html)
12. **redtube** — Full documentation done (redtube.html → builds to docs/dist/redtube/index.html)
13. **youporn** — Full documentation done (youporn.html → builds to docs/dist/youporn/index.html)

## Pending APIs (to tackle later)
- tube8, thumbzilla, missav

## File Structure
```
/home/asuna/PycharmProjects/docs/
├── BRAIN_CONTEXT.md          # This file - resume context
├── template.html             # Master HTML template
├── build.py                  # Build script: template + content → final HTML
├── rewrite_content.py        # Helper script that generated xvideos & eaf_base_api HTML correctly
├── fix_html.py               # Previous helper script
├── content/
├── eaf_base_api.html     # Base API docs
├── hqporner.html         # HQPorner API docs
└── xvideos.html          # XVideos API docs
└── dist/
    ├── eaf_base_api/
    │   └── index.html
    ├── hqporner/
    │   └── index.html
    └── xvideos/
        └── index.html
```

## eaf_base_api Summary (Key for All Docs)
- **RuntimeConfig**: 17 configurable attributes (proxies, http_version, impersonation, ja3, timeout, retry, bandwidth limit, dns_over_https, etc.)
- **BaseCore**: Session management, fetch with retry (tenacity), caching, m3u8 quality resolution, HLS threaded download with resume/cancel, legacy download with multipart, TS→MP4 remux via PyAV
- **BaseMedia**: Lazy-loading dataclass base with `load(api=, html=, anything=)`, auto `DataNotLoadedError`
- **Helper**: Concurrent scraping orchestrator using producer/consumer asyncio queues
- **DownloadConfigHLS**: Quality, path, m3u8 url, remux, resume state, stop event, callbacks
- **DownloadConfigRAW**: For direct file downloads, multipart range support
- **Error Hierarchy**: ~20 custom exceptions under BaseScraperError

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
1. Check which APIs still need documentation.
2. Follow the established template/content/build pattern.
3. Create a new `content/{api_name}.html` for each new API.
4. Structuring Method Cards & Sidebar:
   - Restructure signatures to use one parameter per line, using the token CSS formatting classes (e.g. `token-keyword`, `token-builtin`, `token-class`, etc.) for syntax highlighting.
   - Design each method card with description and tag at the top, signature code block in the middle, and detailed parameters/returns at the bottom.
   - Nest all client and object methods under collapsible `nav-collapsible` divs in the sidebar to maintain screen clean-lines.
5. Inject the common Intro block (Disclaimer + Donations) into `MAIN_CONTENT`. Do NOT re-explain RuntimeConfig or eaf_base_api details; link to it instead.
6. Run `python build.py` to generate final HTML.
