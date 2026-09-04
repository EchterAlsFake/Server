# Conversion ambiguities and review notes

## Public input boundary

The input directory is the repository root rather than `./dist`. It contains
editorial fragments, templates, internal notes, and vendor snapshots as well as
the generated public site. Repository context says `dist/` is generated and
`content/*.html` is editorial source, while the mission asks to convert the
existing *public HTML documentation*. The conversion uses the 18 built
`dist/**/index.html` pages because they map exactly to public routes. No content
from internal notes or `provider_api/` is copied.

## Resolved: live deployment differs from the local build

On 2026-09-04, all 18 mapped public URLs returned HTTP 200. The live portal's
reported `Content-Length` was 77,691 bytes, while local `dist/index.html` is
44,295 bytes. On 2026-09-04, the user explicitly confirmed that the local HTML
snapshot is the intended conversion authority and that the live deployment is
not yet up to date. This difference is therefore not a review or indexing
blocker; only URL existence was checked remotely.

## Source phrasing retained

Technical claims, signatures, version labels, warnings, and examples are derived
without attempting to reconcile them with package repositories. Any inconsistency
already present in the HTML is intentionally preserved for human review rather
than silently corrected.
