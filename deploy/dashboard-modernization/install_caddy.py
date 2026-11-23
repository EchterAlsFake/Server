"""Adapt the present Pixel or Acer Caddyfile while preserving the existing routes."""
import sys
from pathlib import Path

from retire_website_collectors import retire


def configuration(text, host):
    if "import pf_dashboard_traffic" in text:
        return retire(text, "127.0.0.1:18080") if host == "pixel" else text
    snippet = "import /etc/caddy/dashboard-traffic.caddy\n\n"
    if host == "pixel":
        text = retire(text, "127.0.0.1:18080")
        text = text.replace(
            "\t\t@retired_analytics path", "\t\t@dashboard_typo path /dashbord /dashbord/\n"
            "\t\tredir @dashboard_typo /dashboard/ 308\n\t\t@retired_analytics path",
            1,
        )
        text = text.replace(
            "(security_headers) {\n\theader {",
            "(security_headers) {\n"
            "\t@protected_frame expression `!(path('/dashboard/embed/view') && host('pornfetch.to', 'www.pornfetch.to'))`\n"
            "\theader @protected_frame X-Frame-Options DENY\n\theader {",
        ).replace('\t\tX-Frame-Options "DENY"\n', "")
        text = text.replace(
            "\t\t@embed_routes path /dashboard/embed/* /dashboard/static/embed.js /dashboard/api/embed/*",
            "\t\t@embed_routes path /dashboard/embed/view",
        ).replace("\t\t\theader Access-Control-Allow-Origin *\n", "")
        text = text.replace(
            "\t\t\t\timport proxy_headers\n\t\t\t}\n\t\t}\n\t\t@dashboard path",
            "\t\t\t\timport proxy_headers\n\t\t\t\theader_down -X-Frame-Options\n\t\t\t}\n\t\t}\n\t\t@dashboard path",
        )
    # Caddy's global options must remain first. Attach one access log per
    # actual serving site block, including explicit HTTP redirects.
    split = text.index("\n}", text.index("{")) + 2
    head, sites = text[:split], text[split:]
    lines = sites.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line and not line[0].isspace() and (".pornfetch.to" in line or "pornfetch.to" in line or ".echteralsfake.me" in line or "echteralsfake.me" in line) and line.rstrip().endswith(" {"):
            lines[index] += "\timport pf_dashboard_traffic\n"
    if not any("import pf_dashboard_traffic" in line for line in lines):
        raise ValueError("No serving sites matched")
    return head + "\n\n" + snippet + "".join(lines).lstrip("\n")


if __name__ == "__main__":
    host, source, destination = sys.argv[1:]
    Path(destination).write_text(configuration(Path(source).read_text(), host))
