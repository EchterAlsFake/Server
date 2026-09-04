# Public HTML documentation inventory

Inventory date: 2026-09-04

The supplied `HTML_SOURCE_DIR` is the repository root. Repository context identifies
`content/*.html` as editorial fragments and `dist/` as the generated public site.
This conversion therefore treats the 18 `dist/**/index.html` pages as the public
HTML inputs. Editorial fragments, templates, assets, third-party API snapshots,
and internal engineering notes are not public-page inputs.

All public URLs below returned HTTP 200 on 2026-09-04.

| Source page | HTML title | Public URL | Proposed Markdown destinations | Status / notes |
|---|---|---|---|---|
| `dist/index.html` | EAF Python API Documentation | `https://docs.echteralsfake.me/` | `overview.md` | Portal cards are condensed into a corpus overview; donation and licensing promotion is omitted. |
| `dist/eaf_base_api/index.html` | Base API — Documentation | `https://docs.echteralsfake.me/eaf_base_api/` | `eaf-base-api/overview.md`; `eaf-base-api/installation.md`; one focused file for each remaining major reference topic; `eaf-base-api/changelog.md` | Shared base reference; major HTML sections are already topic-focused. |
| `dist/beeg/index.html` | Beeg API — Documentation | `https://docs.echteralsfake.me/beeg/` | `legal/disclaimer.md`; `beeg/getting-started.md`; `beeg/reference/client.md`; `beeg/reference/video.md`; `beeg/guides/downloading.md`; `beeg/troubleshooting/errors.md`; `beeg/supported-platforms.md`; `beeg/changelog.md` | The shared detailed legal warning is retained once; donation/support promotion is excluded. |
| `dist/eporner/index.html` | Eporner API — Documentation | `https://docs.echteralsfake.me/eporner/` | `eporner/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Sorting enums remain a dedicated reference topic. |
| `dist/hqporner/index.html` | HQPorner API — Documentation | `https://docs.echteralsfake.me/hqporner/` | `hqporner/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | CLI remains a dedicated reference topic. |
| `dist/missav/index.html` | MissAV API — Documentation | `https://docs.echteralsfake.me/missav/` | `missav/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Search engine remains a dedicated guide. |
| `dist/pornhub/index.html` | PornHub API — Documentation | `https://docs.echteralsfake.me/pornhub/` | `pornhub/getting-started.md`; one file per API object; focused search, download, iteration, error, CLI, platform, and changelog files | Large combined page is split most aggressively. |
| `dist/porntrex/index.html` | Porntrex API — Documentation | `https://docs.echteralsfake.me/porntrex/` | `porntrex/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Repeated legal/support block excluded. |
| `dist/redtube/index.html` | Redtube API — Documentation | `https://docs.echteralsfake.me/redtube/` | `redtube/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Combined profile types remain together where the source documents shared behavior. |
| `dist/spankbang/index.html` | SpankBang API — Documentation | `https://docs.echteralsfake.me/spankbang/` | `spankbang/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Combined profile types remain together where the source documents shared behavior. |
| `dist/thumbzilla/index.html` | Thumbzilla API — Documentation | `https://docs.echteralsfake.me/thumbzilla/` | `thumbzilla/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Repeated legal/support block excluded. |
| `dist/tube8/index.html` | Tube8 API — Documentation | `https://docs.echteralsfake.me/tube8/` | `tube8/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Repeated legal/support block excluded. |
| `dist/xfreehd/index.html` | XFreeHD API — Documentation | `https://docs.echteralsfake.me/xfreehd/` | `xfreehd/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Album remains a dedicated reference topic. |
| `dist/xhamster/index.html` | xHamster API — Documentation | `https://docs.echteralsfake.me/xhamster/` | `xhamster/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Account and short references remain dedicated topics. |
| `dist/xnxx/index.html` | XNXX API — Documentation | `https://docs.echteralsfake.me/xnxx/` | `xnxx/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | CLI remains a dedicated reference topic. |
| `dist/xvideos/index.html` | XVideos API — Documentation | `https://docs.echteralsfake.me/xvideos/` | `xvideos/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Account, channel, and pornstar references remain dedicated topics. |
| `dist/youporn/index.html` | YouPorn API — Documentation | `https://docs.echteralsfake.me/youporn/` | `youporn/getting-started.md`; focused `reference/`, `guides/`, `troubleshooting/`, platform, and changelog files | Combined profile types remain together where the source documents shared behavior. |
| `dist/transparency/index.html` | AI Transparency Statement — EAF Ecosystem | `https://docs.echteralsfake.me/transparency/` | `project/ai-transparency.md` | Kept as one focused policy document. |

## Duplicate and presentation-only content excluded

- The identical detailed legal disclaimer embedded in each wrapper page is
  represented once in `legal/disclaimer.md` using the Beeg public page as its
  traceable source.
- Repeated donation buttons, payment-provider links, contact solicitation, and
  commercial-licensing promotion are unrelated marketing for MCP retrieval and are
  omitted.
- Navigation, breadcrumbs, header/footer controls, search UI, copy buttons, emoji
  section icons, scripts, styles, fonts, and layout containers are omitted.
- Shared base networking and download details are not copied into wrapper files
  where the wrapper page only links to the base reference.

## Pilot set

| Role | Source material | Pilot destination |
|---|---|---|
| Introductory | Portal overview | `overview.md` |
| Procedural | Beeg installation, quick start, and configuration | `beeg/getting-started.md` |
| Reference/API | Beeg `Client` section | `beeg/reference/client.md` |
| Troubleshooting | Beeg error handling section | `beeg/troubleshooting/errors.md` |

## Ambiguous mappings

- `HTML_SOURCE_DIR="./"` includes both editorial fragments and generated public
  pages. The mapping is resolved in favor of `dist/**/index.html` because those
  files correspond one-to-one with the supplied public base URL. See
  `AMBIGUITIES.md` for the live/local content caveat.
