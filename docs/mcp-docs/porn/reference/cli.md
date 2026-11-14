---
title: "CLI — Porn.com API"
summary: "porn_api positional scene URL, --download boolean flag, --output directory, --quality and JSON inspection."
public_url: "https://docs.echteralsfake.me/porn/"
aliases: ["CLI — Porn.com API", "CLI Porn.com reference"]
keywords: ["Porn.com", "porn_api", "unofficial-api-for-porn", "porn_api", "CLI", "--download", "--quality", "--output"]
---

# CLI — Porn.com API

Both `porn_api` and `python -m porn_api` invoke the same entry point. The scene
URL is a required positional argument; `--download` is a boolean flag, not the
argument that takes the URL.

```sh
porn_api -h
porn_api https://www.porn.com/scene/208974141
python -m porn_api https://www.porn.com/scene/208974141 --download --quality worst --output ./
```

| Option | Default | Meaning |
|---|---|---|
| `url` | Required positional value | Verified Porn.com `/scene/<id>[/<slug>]` URL. |
| `--download` | False | Download public HLS; otherwise print loaded metadata as JSON. |
| `--output` | `./` | Output directory; a title-derived MP4 filename is applied. |
| `--quality` | `best` | `best`, `half`, `worst`, or a positive resolution height/numeric string. |
| `-h`, `--help` | — | Show parser help. |

CLI downloads create `DownloadConfigHLS(..., remux=True)` and therefore require
FFmpeg. JSON inspection can contain expiring signed media URLs. The Client's
async context manager closes its core after inspection/download.

There are no `--file`, `--no-title`, or direct MP4 format flags in this provider.
Use the Python [download interface](../guides/downloading.md) for callbacks,
reports, exact output paths, metadata export, or cancellation settings.
