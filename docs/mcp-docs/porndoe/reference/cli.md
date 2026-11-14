---
title: "CLI \u2014 Porndoe API"
summary: "Command line MP4 downloading with URLs, URL files, quality selection and output filenames."
public_url: "https://docs.echteralsfake.me/porndoe/"
aliases:
  - "CLI \u2014 Porndoe API"
keywords:
  - "Porndoe"
  - "porndoe_api"
  - "cli"
---

# CLI — Porndoe API

```sh
python -m porndoe_api --download https://porndoe.com/watch/pd4y7n5e2j8r --output ./ --quality best
porndoe_api --file urls.txt --output ./ --quality worst
python -m porndoe_api --download https://porndoe.com/watch/pd4y7n5e2j8r --output ./video.mp4 --no-title
```

Exactly one of `--download URL` or `--file FILE` is required. URL files contain
one URL per nonempty line. `--output` is required. `--quality` defaults to best
and accepts the same values as RAW downloads. `--no-title` treats output as the
explicit filename. Downloads run sequentially and the client closes its core.
Unsuccessful downloads raise an error and give the process a failing exit code.

See [downloading](../guides/downloading.md).
