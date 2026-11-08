# Porn Fetch feature tour

A silent, looping **40-second, 1920 × 1080, 60fps** Remotion advertisement.
Composition: `MyComp`, 2400 frames. Interface controls and editorial text remain
editable React / SVG layers reconstructed from the supplied screenshots.

## Preview and export

```sh
npm run dev
npm run lint
npm run render
npm run poster
```

Exports: `out/porn-fetch-tour-40s.mp4` and `out/porn-fetch-tour-40s-poster.png`.
The earlier 10-second and 25-second files are preserved. To use an existing Chrome,
append `-- --browser-executable=/absolute/path/to/chrome` to the render or poster command.

The camera renders a single app window with brief transition blur. There is no
multi-copy blur wrapper, no experimental Chrome flag requirement and no audio.

## Feature chapters

| Time        | Chapter                                                                           |
| ----------- | --------------------------------------------------------------------------------- |
| 0–5.5s      | Type a video URL, fetch it, download to 100%                                      |
| 5.5–11s     | Fetch a model collection, Select All, download together                           |
| 11–17s      | PornHub, XHamster, XVideos: two seconds per tab, with the central account message |
| 17–22s      | Duration / regex / quality / date filters; filename template                      |
| 22–33.5s    | Privacy controls with synchronized explanations and reading holds                 |
| 33.5–36.5s  | HTTP version, browser identity, custom JA3 and interface binding                  |
| 36.5–39.65s | Workers, parallel downloads, speed limit and concurrency                          |
| 39.65–40s   | Restore the opening state for the loop                                            |

The account scene clicks only provider tabs. The centered overlay reads:
“Download your account history, liked videos, and playlists from supported websites”.

Privacy clicks and captions share one timing source in `src/tourContent.ts`:

- 22.4–26.5s, Anonymous Mode: “Conceal sensitive details on your screen when other people are nearby”.
- 26.5–29s, Tor Integration: “Route supported connections through Tor”.
- 29–33.5s, SNI Obfuscation: “Configure SNI fragmentation for supported connections*”.
  The smaller note below reads: “* Support depends on your platform and network. Destination IP addresses may remain visible.”.

Video URLs and titles are fictional. The filename template uses supported tokens:
`$author - ${publish_dt:%Y-%m-%d} - $title`. All interaction is simulated locally.

## Editing

- `src/Composition.tsx`: registration and video metadata.
- `src/Promo.tsx`: scene durations, playback rates, editorial and camera.
- `src/FetchInterface.tsx`: shared app shell and download workflows.
- `src/AdvancedConfiguration.tsx`: filters, scroll and filename typing.
- `src/Accounts.tsx`: provider pages, two-second holds and tab-only cursor clicks.
- `src/Settings.tsx`: privacy, system and performance scenes.
- `src/tourContent.ts`: privacy click times, explanations and exact SNI footnote.
- `src/FeatureOverlays.tsx`: centered account message and privacy explanation panels.
- `src/FeaturePrimitives.tsx`: editable fields, checkboxes, spinners and cursors.

## Validate the actual export

```sh
npm run review
npm run verify-export
```

`review` renders 16 representative frames to `out/checks/`. Set
`REMOTION_BROWSER_EXECUTABLE` to use an installed Chrome. A comma-separated frame
list is supported: `npm run review -- 1020,1140,1260,1440,1680,1890,2399`.

`verify-export` requires FFmpeg and FFprobe. It decodes the MP4, validates its
metadata and absence of audio, and compares 11 encoded frames with the reviewed
stills, including all three account tabs and each privacy explanation.
Decoded PNGs remain in `out/encoded/`.

For a website hero, use the MP4 in a `<video autoPlay muted loop playsInline>`
element with the exported poster.

The homepage opens with the single-video workflow (poster frame 108). Accounts
precede advanced configuration; homepage chapter controls jump to 0, 5.5 and 17
seconds. Keep those controls aligned when changing chapter timings.

For the website copy, encode the reviewed master with H.264 CRF 22, yuv420p,
no audio and `-movflags +faststart`. Verify that copy with
`node scripts/verify-export.mjs ../static/media/porn-fetch-promo.mp4`.
The WebP poster is made from reviewed frame 108.
