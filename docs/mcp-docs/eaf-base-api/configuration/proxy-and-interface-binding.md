---
title: "Proxy and interface binding — eaf_base_api"
summary: "Documents Proxy and interface binding behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Proxy and interface binding"
  - "eaf base Proxy and interface binding"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Proxy and interface binding"
---

# Proxy and interface binding — eaf_base_api

Documents Proxy and interface binding behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

```python
from base_api.modules.config import RuntimeConfig

runtime = RuntimeConfig()
runtime.proxy = "socks5://127.0.0.1:9050"
runtime.proxy_auth = "username:password"
runtime.interface = "192.0.2.10"
runtime.ip_resolve = 1  # 1 for IPv4, 2 for IPv6, None for dual-stack

# Only disable verification for a proxy you control and trust.
runtime.verify_ssl = False
```

The old `proxies` mapping was replaced by the singular `proxy` URL. `interface` is passed to `curl_cffi.AsyncSession` and must be a local interface IP address. `ip_resolve` allows restricting DNS resolution to IPv4 (`1`) or IPv6 (`2`) when dual-stack connectivity issues arise; it also respects the `CURL_IPRESOLVE` environment variable (e.g. `CURL_IPRESOLVE=1` or `4` for IPv4, `2` or `6` for IPv6).

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
