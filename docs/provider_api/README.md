# Provider API documentation snapshots

These files are local, unmodified snapshots of the canonical API documentation
used for the webhook audit on 2026-09-01. They are reference material; the
providers remain the authoritative source and may update their live documents.

| Provider | Local snapshot | Canonical source | SHA-256 |
| --- | --- | --- | --- |
| Patreon | `patreon-api-reference.html` | `https://docs.patreon.com/` | `94d1ae12940d568dfe4a073aeb6141a415f59f6dc16770547b709d28f758a15f` |
| NOWPayments | `nowpayments-api.postman_collection.json` | `https://documenter.gw.postman.com/api/collections/7907941/2s93JusNJt?segregateAuth=true&versionTag=latest` | `f3187585e0dbbd50b3c72ad34a32937cee6a1cfe3618c47fe092c0b0548c263f` |

The NOWPayments help page at `https://nowpayments.io/help/api` links to the
provider's published Postman document at
`https://documenter.getpostman.com/view/7907941/2s93JusNJt`. The JSON file here
is the raw Postman collection behind that publication, not a third-party guide.

To refresh the snapshots deliberately:

```bash
curl --fail --location https://docs.patreon.com/ \
  --output docs/provider_api/patreon-api-reference.html
curl --fail --location \
  'https://documenter.gw.postman.com/api/collections/7907941/2s93JusNJt?segregateAuth=true&versionTag=latest' \
  --output docs/provider_api/nowpayments-api.postman_collection.json
sha256sum docs/provider_api/patreon-api-reference.html \
  docs/provider_api/nowpayments-api.postman_collection.json
```

After refreshing, review the diff and repeat the webhook audit. Do not assume
that a checksum change is only presentational: callback fields, statuses,
signature rules, or retry behavior may have changed.

See `docs/WEBHOOK_AND_LOGGING_HARDENING.md` for the findings and their mapping
to the implementation.
