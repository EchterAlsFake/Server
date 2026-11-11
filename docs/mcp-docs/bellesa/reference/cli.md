---
title: "CLI — Bellesa API"
summary: "bellesa_api command-line arguments, HLS/MP4 selection, actual quality presets, output directory and resource cleanup."
public_url: "https://docs.echteralsfake.me/bellesa/"
aliases: ["CLI — Bellesa API", "Bellesa cli"]
keywords: ["Bellesa", "bellesa_api", "CLI", "bellesa_api", "--quality", "--format", "--output"]
---

# CLI — Bellesa API

Run `bellesa_api -h` or `python -m bellesa_api -h`.

```sh
bellesa_api URL [--quality QUALITY] [--output OUTPUT] [--format {hls,mp4}]
```

| Argument | Default | Meaning |
|---|---|---|
| `URL` | Required | Supported public Bellesa video URL |
| `--quality` | `best` | `best`, `half`, `worst`, or an actual numeric resolution such as 720 |
| `--output` | `.` | Output directory; the sanitized title supplies the filename |
| `--format` | `hls` | `hls` uses shared HLS download with MP4 remux; `mp4` uses direct RAW |

```sh
python -m bellesa_api https://www.bellesa.co/videos/7054 --quality worst --format hls --output ./
bellesa_api https://www.bellesa.co/videos/7054 --quality 720 --format mp4 --output ./
```

The CLI owns and closes its client. It has no search, credential, browser-cookie,
proxy or JSON-export arguments. Configure a custom `BaseCore` through the Python API
when runtime customization is needed. See [downloading](../guides/downloading.md).
