---
title: "Provider Helpers (4.2.0) — eaf_base_api"
summary: "Documents Provider Helpers (4.2.0) behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Provider Helpers (4.2.0)"
  - "eaf base Provider Helpers (4.2.0)"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Provider Helpers (4.2.0)"
---

# Provider Helpers (4.2.0) — eaf_base_api

Documents Provider Helpers (4.2.0) behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

`base_api.modules.provider` centralizes common request and download handling across all 15 site packages, eliminating boilerplate while enforcing uniform exception translation and contextual logging:

Function| Signature| Description
---|---|---
`fetch_content`| `async (core, url, *, logger, owner=None, get_json=False, error_types=errors, not_found_error=None, access_denied_error=None) -> str | dict`| Fetches text or JSON and translates transport failures (HTTP 404, bot blocks, proxy errors, network errors) into provider exceptions, chaining the cause. Attaches `class_name` and `url` context.
`download_errors`| `(error_type=errors.DownloadFailed) -> decorator`| Decorator giving media download methods uniform logging, contextual tracing, and cancellation semantics. Raises `DownloadFailed` (with URL, class_name, and API) on failure, while propagating `DownloadCancelled` and `asyncio.CancelledError` cleanly.
`prepare_download_config`| `(configuration, title: str | None) -> configuration`| Shallow-copies download configuration and appends sanitized title with `.mp4` when `no_title=False`, keeping callbacks and stop events shared.
`download_hls`| `async (media, configuration) -> bool | DownloadReport`| Loads `title` and `m3u8_base_url`, prepares the configuration, and delegates to `media.core.download(configuration=config)`.

```python
from base_api.modules.provider import fetch_content, download_errors, download_hls
from base_api.modules.logger import get_logger
from my_api.modules.errors import DownloadFailed

logger = get_logger(__name__)

async def get_html_content(core, url, *, owner=None):
    return await fetch_content(core, url, logger=logger, owner=owner)

@download_errors(DownloadFailed)
async def download(self, configuration):
    return await download_hls(self, configuration)
```

## Behavior and edge cases

`prepare_download_config()` sanitizes automatically generated title filenames and falls back to `video.mp4` when no title is available. The caller’s configuration remains unchanged.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
