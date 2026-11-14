---
title: "CLI \u2014 YouJizz API"
summary: "Inspect metadata or download MP4 and HLS from the command line."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["CLI \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "reference", "cli"]
---

# CLI — YouJizz API

```sh
python -m youjizz_api --download 48914471 --info
youjizz_api --download 48914471 --quality worst --format mp4 --output ./downloads
youjizz_api --download 48914471 --quality 288 --format hls --output ./downloads
```

`--download` is required. `--quality` defaults to best, `--format` to mp4 and
`--output` to ./; supported formats are mp4 and hls. `--info` prints metadata
without expiring media URLs. HLS downloads remux to MP4.
