---
title: "Logging and cleanup — eaf_base_api"
summary: "Documents Logging and cleanup behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Logging and cleanup"
  - "eaf base Logging and cleanup"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Logging and cleanup"
---

# Logging and cleanup — eaf_base_api

Documents Logging and cleanup behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

```python
import logging

core.enable_logging(level=logging.DEBUG)
core.enable_logging(log_file="api.log", level=logging.INFO)
core.enable_logging(
    log_ip="192.168.1.100",
    log_port=8080,
    level=logging.DEBUG,
)

# Always release the curl_cffi connection pool.
await core.close()
```

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
