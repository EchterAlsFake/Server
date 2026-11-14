---
title: "CLI — Pornhat API"
summary: "pornhat_api and python -m pornhat_api positional URL, info, quality and output arguments."
public_url: "https://docs.echteralsfake.me/pornhat/"
aliases:
  - "CLI — Pornhat API"
keywords:
  - "Pornhat"
  - "pornhat_api"
  - "cli"
---

# CLI — Pornhat API

Run `pornhat_api` or `python -m pornhat_api`. The URL is a positional argument;
there are no `--download`, batch-file, account, or `--no-title` options.

```sh
pornhat_api -h
python -m pornhat_api 'https://www.pornhat.com/video/armani-black-wants-her-husband-s-friend-deep-inside/' --info
pornhat_api 'https://www.pornhat.com/video/armani-black-wants-her-husband-s-friend-deep-inside/' --quality 480 --output ./downloads/
```

| Argument | Default | Meaning |
| --- | --- | --- |
| `url` | Required | Absolute public /video/ URL on a verified host |
| `-q`, `--quality` | `best` | Shared quality selector or numeric tier string |
| `-o`, `--output` | `./` | Existing output directory; filename is based on the title |
| `--info` | False | Print loaded HTML metadata as JSON; do not download |
| `-h`, `--help` | — | Show command help |

CLI downloads use `DownloadConfigHLS(..., remux=True)` and need FFmpeg. `--info` loads
HTML only and omits unresolved media fields. The CLI creates and closes its client/core.
The Python interface permits explicit core configuration, source refresh and caller deadlines;
the CLI uses backend defaults. See [downloading](../guides/downloading.md) for the observed
high-concurrency HTTP/2 limitation and verified configuration.
