# Local commit grouping

The user explicitly authorized local `.git` writes on 2026-09-04. Remote
operations, deployment, and indexing remain out of scope.

The output is grouped into these reviewable commits:

1. Conversion inventory, generator, validator, source map, ambiguity/omission
   reports, URL checks, and retrieval cases (`conversion/`).
2. Corpus overview, legal disclaimer, transparency statement, and shared base API
   reference (`mcp-docs/overview.md`, `mcp-docs/legal/`, `mcp-docs/project/`, and
   `mcp-docs/eaf-base-api/`).
3. Site-wrapper installation, guides, references, troubleshooting, platform, and
   changelog documents (the remaining package directories under `mcp-docs/`).

Do not index or deploy merely as a side effect of creating these commits.
