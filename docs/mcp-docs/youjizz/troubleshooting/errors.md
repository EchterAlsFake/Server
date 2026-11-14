---
title: "Errors \u2014 YouJizz API"
summary: "Unloaded metadata, invalid routes, expired media and access failures."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Errors \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "troubleshooting", "errors"]
---

# Errors — YouJizz API

DataNotLoadedError means the required source has not been loaded; use load_fields
or load_sources. A loaded None represents absent metadata. Shared MediaLoadError
can wrap provider/network errors; inspect its cause. Invalid host/path/query/directory
arguments raise validation errors. Refresh expired sources before retrying a download.
An empty or unrecognized directory raises ValueError rather than claiming success.
HTTP challenges and age verification are surfaced; do not bypass access controls.
No browser cookies are read by the live tests.
