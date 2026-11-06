# Beginner and advanced-user refinement

The existing visual system is retained. This pass changes content hierarchy,
tour order, licensing explanations, checkout readability and sticky navigation.

- The hero uses one short supporting sentence. Free limits remain in the comparison.
- The compact “Simple by default. Powerful by design.” section uses three editorial
  columns rather than a new collection of cards. Details remain expandable.
- A shared Premium summary explains first activation, covered releases, continued
  eligibility, renewal, validation and installation limits. Offline grace details
  remain available on both the homepage and checkout.
- Checkout retains every field, consent label, requirement and payment action.
  Only headings and presentation change in its form.
- The legal utility row stays directly accessible at the top and in the footer.
  Only the primary navigation remains sticky, with an opaque background. Anchor
  targets clear the header (93 px desktop, approximately 82 px mobile).
- The tour opens with a single-video download and uses a matching poster. Account
  workflows precede advanced configuration, which starts at 17 seconds. Chapter
  buttons allow users to revisit the simple workflow or explore advanced controls.

## Capability evidence

Claims were checked against the adjacent Porn_Fetch application checkout:

- `src/frontend/UI/SettingsPage.qml`: HTTP version, custom JA3, tracking toggle and
  configurable PocketBase data folder.
- `src/cli/flows/settings.py` and `src/cli/settings.py`: networking configuration.
- `src/cli/flows/statistics.py`: local tracking enable/disable and database path.
- `docs/CHANGELOG.md` and `BACKEND.md`: asynchronous networking, proxies, encrypted
  DNS, interface binding and TLS fingerprints.
- `CONTEXT.md`: desktop PocketBase tracking; Android history/statistics unavailable.

“Database writing” means controlling local desktop history tracking and its data
folder. The site does not claim arbitrary external database or schema support.

## Validation

Playwright MCP reviewed 1440 × 900 desktop and 390 × 844 mobile:

- Premium anchors clear the opaque header; legal links do not remain in it.
- Tour chapter selection seeks correctly, including under reduced motion without
  autoplay. Native media controls and the no-JavaScript watch link remain.
- Advanced disclosure, compatibility, free download, platform selection, Windows
  architecture, Help, and the Patreon instructions/Cancel workflow remain usable.
- Checkout Escape restores focus after the native dialog close event.
- No page-wide horizontal overflow on the reviewed pages.
- No-JavaScript capability and licensing content remains readable.

105 relevant Python tests passed; promo ESLint and TypeScript checks passed.
The rebuilt video is checked for dimensions, duration, frame rate and similarity
to reviewed Remotion stills. No production changes or external payments were made.
The local preview's deployment-only visit counter still returns its pre-existing 404.

## Comparisons

| View | Before | After |
| --- | --- | --- |
| Desktop homepage | [Before](refine-before-home-desktop.png) | [After](refine-after-home-desktop.png) |
| Mobile homepage | [Before](refine-before-home-mobile.png) | [After](refine-after-home-mobile.png) |
| Desktop checkout | [Before](refine-before-checkout-desktop.png) | [After](refine-after-checkout-desktop.png) |
| Mobile checkout | [Before](refine-before-checkout-mobile.png) | [After](refine-after-checkout-mobile.png) |
| Desktop sticky navigation | [Before](refine-before-sticky-desktop.png) | [After](refine-after-sticky-desktop.png) |
| Mobile sticky navigation | [Before](refine-before-sticky-mobile.png) | [After](refine-after-sticky-mobile.png) |

Advanced overview: [Desktop](refine-power-desktop.png) · [Mobile](refine-power-mobile.png).
