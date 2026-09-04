# Human review queue

## Recommended content review

The user confirmed on 2026-09-04 that local `dist/` is the correct conversion
snapshot; the older live deployment is not the corpus authority.

1. Review `mcp-docs/overview.md` and the package versions retained from that
   confirmed local snapshot.
2. Review all `mcp-docs/*/changelog.md` files for the desired historical cutoff.
   The conversion preserves the HTML's dates and commit references without
   checking package repositories.
3. Review authentication examples in `mcp-docs/pornhub/reference/account.md`,
   `mcp-docs/xhamster/reference/account.md`, and
   `mcp-docs/xvideos/reference/account.md`. Only placeholders were retained, but
   these examples describe handling session cookies.
4. Review error/troubleshooting files if exact runtime exception messages are
   required. The source pages mainly document typed exception classes; strings
   shown under “Example diagnostic messages” are explicitly labeled as output
   printed by examples, not library-raised messages.

No blocker remains for review or indexing. No issue was found in Markdown
structure, metadata, relative links, sizes, exact identifier headings, UTF-8
encoding, or secret scanning.
