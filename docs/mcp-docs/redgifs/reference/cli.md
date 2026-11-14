---
title: "CLI — RedGIFs API"
summary: "redgifs_api and python -m redgifs_api download/file, output and quality flags with actual mutually exclusive requirements."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "CLI — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "CLI"
  - "--download"
  - "--file"
  - "--quality"
  - "redgifs_api"
---

# CLI — RedGIFs API

Run `redgifs_api` or `python -m redgifs_api`. Exactly one of `--download` and `--file`
is required; the URL is not a positional argument.

```sh
redgifs_api -h
redgifs_api --download https://www.redgifs.com/watch/hotpinkacrobatickitfox --quality sd --output ./
python -m redgifs_api --file urls.txt --quality worst --output ./
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-d`, `--download` | — | One supported video URL or stable ID |
| `-f`, `--file` | — | UTF-8 file with one video URL/ID per line; blank lines ignored |
| `-o`, `--output` | `./` | Output directory; unloaded titles use stable IDs as filenames |
| `-q`, `--quality` | `best` | best, half, worst, hd, sd or silent |
| `-h`, `--help` | — | Print help without network requests |

File inputs are processed sequentially. The CLI loads API metadata and uses
`DownloadConfigRAW`; it closes the owned client/core after completion or an exception.
It has no `--info`, `--no-title`, image mode, account flags, numeric resolution or HLS
switches. Use the Python API for injected RuntimeConfig, exact filenames, callbacks
and cancellation. Failed downloads propagate and give a nonzero process exit.

Both direct-argument and file-input paths completed real downloads in the final suite,
with output verified by ffprobe. The library's broader live suite is still incomplete;
see [validation](../guides/live-validation.md).
