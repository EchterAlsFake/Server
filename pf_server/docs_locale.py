"""Localize the generated documentation while preserving its links and code samples."""

import json
import re
from functools import lru_cache
from html import escape, unescape
from html.parser import HTMLParser
from pathlib import Path

from .website_locale import LANGUAGES, language_tag, path_in_language

CATALOG_DIR = Path(__file__).resolve().parents[1] / "i18n" / "docs"
ATTRIBUTES = re.compile(r"""(?P<name>[\w:-]+)\s*=\s*(?P<quote>['"])(?P<value>.*?)(?P=quote)""", re.S)
DISPLAY_ATTRIBUTES = {"alt", "title", "aria-label", "placeholder", "data-desc"}
VERBATIM = {"code", "pre", "script", "style", "svg", "kbd", "samp"}
JS_MESSAGES = (
    "Close navigation", "Open navigation", "Copied", "Copy failed",
    "Link to %(heading)s", "%(visible)s of %(total)s packages",
)


def message_key(text):
    return " ".join(text.split())


class DocumentationHTML(HTMLParser):
    def __init__(self, translate, locale="en", path="/"):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.translate = translate
        self.locale = locale
        self.path = path
        self.verbatim = []
        self.heading = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if self.locale != "en" and tag in {"h2", "h3", "h4"} and "id" not in attributes:
            self.heading = (tag, len(self.output), [])
        self.output.append(self.tag(tag, attributes))
        if tag in VERBATIM:
            self.verbatim.append(tag)
        if tag == "body":
            self.output.append(self.language_menu())

    def handle_startendtag(self, tag, attrs):
        self.output.append(self.tag(tag, dict(attrs)))

    def tag(self, tag, attrs):
        raw = self.get_starttag_text()
        if self.verbatim:
            return raw

        def attribute(match):
            name = match["name"]
            value = unescape(match["value"])
            if tag == "html" and name == "lang":
                value = language_tag(self.locale)
            elif name in DISPLAY_ATTRIBUTES or (
                tag == "meta" and name == "content"
                and (attrs.get("name") in {"description", "twitter:title", "twitter:description"}
                     or attrs.get("property") in {"og:title", "og:description"})
            ):
                value = self.translate(message_key(value))
            elif name == "href" and value.startswith("/") and not value.startswith(("//", "/assets/")):
                if value.startswith(("/docs", "/transparency")) or value == "/":
                    value = path_in_language(value, self.locale)
            else:
                return match[0]
            return f'{name}={match["quote"]}{escape(value, quote=True)}{match["quote"]}'

        return ATTRIBUTES.sub(attribute, raw)

    def handle_endtag(self, tag):
        if self.heading and tag == self.heading[0]:
            _, index, pieces = self.heading
            heading = escape("".join(pieces), quote=True)
            self.output[index] = self.output[index][:-1] + f' data-source-heading="{heading}">'
            self.heading = None
        self.output.append(f"</{tag}>")
        if self.verbatim and self.verbatim[-1] == tag:
            self.verbatim.pop()

    def handle_data(self, data):
        if self.heading:
            self.heading[2].append(data)
        if self.verbatim and self.verbatim[-1] in {"style", "script"}:
            self.output.append(data)
            return
        key = message_key(data)
        if key and not self.verbatim and self.locale != "en":
            left = data[:len(data) - len(data.lstrip())]
            right = data[len(data.rstrip()):]
            data = left + self.translate(key) + right
        self.output.append(escape(data, quote=False))

    def handle_decl(self, decl):
        self.output.append(f"<!{decl}>")

    def handle_comment(self, data):
        self.output.append(f"<!--{data}-->")

    def language_menu(self):
        links = []
        for code, name in LANGUAGES.items():
            target = path_in_language(self.path, code)
            tag = language_tag(code)
            current = ' aria-current="page"' if code == self.locale else ""
            links.append(f'<a href="{escape(target, quote=True)}" lang="{tag}" hreflang="{tag}"{current}>{name}</a>')
        label = escape(self.translate("Website language"), quote=True)
        messages = json.dumps({key: self.translate(key) for key in JS_MESSAGES}, ensure_ascii=False)
        messages = messages.replace("<", "\\u003c")
        return (
            f'<nav class="docs-languages" aria-label="{label}">{" ".join(links)}</nav>'
            f'<script type="application/json" id="docs-messages">{messages}</script>'
        )


@lru_cache(maxsize=4)
def docs_catalog(locale):
    path = CATALOG_DIR / f"{locale}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


@lru_cache(maxsize=32)
def localized_docs(filename, locale, path):
    catalog = docs_catalog(locale)
    parser = DocumentationHTML(lambda key: catalog.get(key, key), locale, path)
    parser.feed(Path(filename).read_text(encoding="utf-8"))
    parser.close()
    return "".join(parser.output)
