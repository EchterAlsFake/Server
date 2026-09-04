---
title: "Client lifecycle — eaf_base_api"
summary: "Documents Client lifecycle behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Client lifecycle"
  - "eaf base Client lifecycle"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Client lifecycle"
---

# Client lifecycle — eaf_base_api

Documents Client lifecycle behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

```python
from base_api import BaseCore
from base_api.modules.config import RuntimeConfig
from xvideos_api import Client

runtime = RuntimeConfig()
runtime.timeout = 60
runtime.request_attempts = 5
runtime.request_multiplier = 2.0
runtime.proxy = "socks5://127.0.0.1:9050"
runtime.interface = None  # Or a local interface IP
runtime.cookies = {"session": "value"}

core = BaseCore(configuration=runtime)
client = Client(core=core)

try:
    video = await client.get_video("https://www.xvideos.com/video...")
finally:
    await core.close()
```

`BaseCore` starts without an HTTP session. Context-manager entry, the first request, or an explicit `initialize_session()` creates it lazily; further initialization calls are no-ops while that session remains live. Prefer `async with BaseCore(configuration=runtime) as core:` for direct use. `await core.close()` closes and clears the current session, and a later request safely recreates it from the core's current configuration.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
