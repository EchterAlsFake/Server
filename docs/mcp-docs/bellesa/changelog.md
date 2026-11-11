---
title: "Changelog — Bellesa API"
summary: "Current 1.0.0 source capabilities and verification scope for the Bellesa provider."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["Changelog — Bellesa API", "Bellesa changelog"]
keywords: ["Bellesa", "bellesa_api", "1.0.0", "changelog", "version"]
---

# Changelog — Bellesa API

## 1.0.0 — current source

The current checkout declares version 1.0.0. This entry describes its interface; it does
not assert a package publication date or remote CI status.

- Typed Client, Video, Performer, Channel and Category objects using `eaf-base-api`.
- Independent API/HTML video and performer metadata with deferred source/field loading.
- Lazy live-master media inspection and actual-quality direct-source mappings.
- Public video, performer and channel search; category, performer and filtered video listings.
- Header-bounded pagination, explicit iterator configuration and complete profile reconciliation.
- HLS/MP4 downloads, CLI, refreshed media objects, shared reports/callbacks and resource cleanup.
- Measured quality handling for labels that differ from actual dimensions, including 4:3 encodes.
- Documentation for both public HTML and the MCP Markdown catalog.

See [live validation](guides/live-validation.md) for the recorded test history and limits.
