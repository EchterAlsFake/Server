"""Replace the legacy browser collectors in the deployed Pixel Caddyfile."""

import re
import sys
from pathlib import Path


def routes(indent, upstream):
    text = """@retired_analytics path /__eaf/visit /__eaf/visit.js /_metrics/event
handle @retired_analytics {
    log_skip
    respond 410
}
@website_feedback path /_metrics/feedback
handle @website_feedback {
    log_skip
    request_body {
        max_size 128B
    }
    reverse_proxy UPSTREAM {
        header_up -Cookie
        header_up -Authorization
        header_up -Referer
        header_up -Forwarded
        header_up -X-Real-IP
        header_up -True-Client-IP
        header_up -CF-Connecting-IP
        header_up -X-Original-Forwarded-For
        header_up -X-Forwarded-For
        header_up -X-Forwarded-Host
        header_up -X-Forwarded-Port
        header_up -X-Forwarded-Prefix
        header_up X-Forwarded-Proto https
    }
}
""".replace("UPSTREAM", upstream)
    return "".join(indent + line + "\n" for line in text.splitlines())


def retire(text, upstream):
    if "@retired_analytics path" in text:
        return text
    match = re.search(
        r"(?m)^([ \t]+)@(?:browser_visit|legacy_visit) path [^\n]+\n"
        r"[\s\S]*?^\1@aggregate_metrics path [^\n]+\n[\s\S]*?^\1}\n",
        text,
    )
    if not match:
        raise ValueError("Expected legacy collector routes")
    return text[:match.start()] + routes(match[1], upstream) + text[match.end():]


if __name__ == "__main__":
    source, destination = map(Path, sys.argv[1:])
    destination.write_text(retire(source.read_text(), "127.0.0.1:18080"))
