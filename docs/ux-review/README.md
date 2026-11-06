# UX simplification review

The homepage now leads with a free download, a simple workflow, compatibility,
and Free/Premium differences. Advanced settings remain accessible through native
disclosures. The existing palette, type, app imagery, media controls and legal
requirements are preserved.

## Validation

Reviewed locally at 1440 × 900 and 390 × 844 using Playwright MCP. The preview
used disposable application data, sandbox payments, and a copy of the public
release catalog. Production was not modified. Actual external transfers and
payments were not initiated.

- Passed at both sizes: free-download discovery, platform switching, Windows x64
  selection, Back navigation, compatibility selection, full comparison table,
  Premium entry, age confirmation, retained purchase form, and Help navigation.
- No page-wide horizontal overflow on homepage, Windows/Android downloads, or
  purchase entry. Full compatibility table retains its own horizontal scroller.
- Keyboard: skip link, menu Enter/Escape, disclosure Enter, visible focus.
- Reduced-motion preference pauses the product tour.
- Without JavaScript: all 15 website summaries are readable and explicit
  platform download links remain available in advanced downloads.
- Relevant regression suites: 68 tests passed (marketing, application, contract
  confirmations, website releases, and new UX coverage).
- Local visit-counter endpoint returns 404 in this preview; this pre-existing
  deployment-only script does not affect the verified journeys.

## Screenshot pairs

Full-page images show the same local pages before and after the changes. Mobile
uses the requested viewport size; these are browser viewport checks rather than
physical-device tests. Menu images show the expanded menu on mobile.

| Page | Desktop before / after | Mobile before / after |
| --- | --- | --- |
| Homepage | [Before](before-home-desktop.png) · [After](after-home-desktop.png) | [Before](before-home-mobile.png) · [After](after-home-mobile.png) |
| Windows downloads | [Before](before-downloads-desktop.png) · [After](after-downloads-desktop.png) | [Before](before-downloads-mobile.png) · [After](after-downloads-mobile.png) |
| Android downloads | [Before](before-android-desktop.png) · [After](after-android-desktop.png) | [Before](before-android-mobile.png) · [After](after-android-mobile.png) |
| Age gate | [Before](before-gate-desktop.png) · [After](after-gate-desktop.png) | [Before](before-gate-mobile.png) · [After](after-gate-mobile.png) |
| Navigation | [Before](before-menu-desktop.png) · [After](after-menu-desktop.png) | [Before](before-menu-mobile.png) · [After](after-menu-mobile.png) |

[Desktop compatibility](after-compatibility-desktop.png) and
[mobile compatibility](after-compatibility-mobile.png) show the selected website
and expanded technical comparison.

## Review notes

The preview's template cache initially produced stale screenshots; those after
images were discarded and recaptured. The Android preview screenshot is now
optional, preventing it from pushing platform switching far down the page.
Contract wording, consent fields, backend routes, payment processing, release
selection rules, licensing and download fallback logic were not changed.
