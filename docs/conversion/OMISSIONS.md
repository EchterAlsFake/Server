# Information omitted from the MCP corpus

The conversion intentionally omits only material excluded by the mission:

- Global navigation, breadcrumbs, search controls, right-rail tables of contents,
  copy buttons, headers, footers, and responsive layout containers.
- CSS, JavaScript, fonts, decorative card initials, decorative emoji icons, and
  donation artwork.
- Cookie/tracking presentation code and other generated markup. No analytics code
  or identifiers were copied.
- Repeated donation buttons, payment-provider links, donation solicitation,
  commercial-licensing promotion, social links, and contact marketing.
- Fifteen duplicate copies of the same detailed legal disclaimer. One copy is
  preserved in `mcp-docs/legal/disclaimer.md` and traced to the Beeg public page.
- Generic `IteratorConfig`, retry-handler, and scrape-result boilerplate repeated
  verbatim among wrapper pages. The canonical explanations are retained in the
  focused `eaf-base-api/` documents; wrapper-specific defaults, constraints,
  signatures, and examples remain in their package documents.
- Repository-internal notes (`BRAIN_CONTEXT.md`, hardening/compliance notes), HTML
  templates, build code, and third-party provider snapshots because they are not
  pages in the public documentation site represented by `dist/`.

No technical claim was corrected from external package source, and no unpublished
or secret material was added.
