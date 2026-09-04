#!/usr/bin/env python3
"""Convert the built public HTML pages into focused MCP Markdown documents."""

from __future__ import annotations

import argparse
import copy
import json
import os
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import html2text
from bs4 import BeautifulSoup, Tag


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
OUT = ROOT / "mcp-docs"
REPORT = ROOT / "conversion"
BASE_URL = "https://docs.echteralsfake.me/"

DISPLAY_NAMES = {
    "beeg": "Beeg",
    "eaf_base_api": "eaf_base_api",
    "eporner": "Eporner",
    "hqporner": "HQPorner",
    "missav": "MissAV",
    "pornhub": "PornHub",
    "porntrex": "Porntrex",
    "redtube": "Redtube",
    "spankbang": "SpankBang",
    "thumbzilla": "Thumbzilla",
    "tube8": "Tube8",
    "xfreehd": "XFreeHD",
    "xhamster": "xHamster",
    "xnxx": "XNXX",
    "xvideos": "XVideos",
    "youporn": "YouPorn",
}


@dataclass(frozen=True)
class DocSpec:
    source: str
    public_url: str
    destination: str
    title: str
    summary: str
    section_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    keywords: tuple[str, ...]
    mode: str = "sections"
    promote: bool = False


def clean_heading(text: str) -> str:
    text = re.sub(r"^[^\w`]+", "", text.strip(), flags=re.UNICODE)
    return re.sub(r"\s+", " ", text)


def slugify(text: str) -> str:
    text = clean_heading(text).lower().replace("&", " and ")
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "topic"


def source_for(package: str) -> str:
    return "dist/index.html" if package == "portal" else f"dist/{package}/index.html"


def url_for(package: str) -> str:
    return BASE_URL if package == "portal" else f"{BASE_URL}{package}/"


def section_map(package: str, section_id: str) -> str:
    stem = section_id.removesuffix("-section")
    if package == "eaf_base_api":
        mapping = {
            "overview": "eaf-base-api/overview.md",
            "installation": "eaf-base-api/installation.md",
            "runtime-config": "eaf-base-api/configuration/runtime-config.md",
            "client-integration": "eaf-base-api/reference/client-lifecycle.md",
            "request-api": "eaf-base-api/reference/request-api.md",
            "request-retries": "eaf-base-api/guides/request-retries.md",
            "proxies": "eaf-base-api/configuration/proxy-and-interface-binding.md",
            "caching": "eaf-base-api/configuration/caching.md",
            "base-media": "eaf-base-api/reference/base-media.md",
            "iterator-config": "eaf-base-api/configuration/iterator-config.md",
            "error-policy": "eaf-base-api/guides/retry-and-error-handling.md",
            "scrape-results": "eaf-base-api/reference/scrape-stream-and-result.md",
            "downloads": "eaf-base-api/configuration/downloads.md",
            "logging": "eaf-base-api/guides/logging-and-cleanup.md",
            "migration": "eaf-base-api/migration/from-3x.md",
            "base-errors": "eaf-base-api/troubleshooting/errors.md",
            "changelog": "eaf-base-api/changelog.md",
        }
        return mapping[stem]
    mapping = {
        "installation": f"{package}/getting-started.md",
        "quickstart": f"{package}/getting-started.md",
        "configuration": f"{package}/getting-started.md",
        "downloading": f"{package}/guides/downloading.md",
        "scraping-results": f"{package}/guides/iteration-and-results.md",
        "pagination": f"{package}/guides/iteration-and-results.md",
        "searching": f"{package}/guides/searching-and-filtering.md",
        "search-engine": f"{package}/guides/searching-and-filtering.md",
        "error-handling": f"{package}/troubleshooting/errors.md",
        "platforms": f"{package}/supported-platforms.md",
        "changelog": f"{package}/changelog.md",
        "cli": f"{package}/reference/cli.md",
        "sorting-enums": f"{package}/reference/sorting-enums.md",
        "something": f"{package}/reference/profile-objects.md",
        "user-helper": f"{package}/reference/profile-objects.md",
        "pornstar-helper": f"{package}/reference/profile-objects.md",
    }
    return mapping.get(stem, f"{package}/reference/{slugify(stem)}.md")


def topic_label(section_id: str, heading: str) -> str:
    stem = section_id.removesuffix("-section")
    labels = {
        "installation": "Installation",
        "runtime-config": "RuntimeConfig",
        "client-integration": "Client lifecycle",
        "request-api": "Request API",
        "request-retries": "Request retries",
        "proxies": "Proxy and interface binding",
        "base-media": "BaseMedia",
        "iterator-config": "IteratorConfig",
        "error-policy": "RetryPolicy and custom error handling",
        "scrape-results": "ScrapeStream and ScrapeResult",
        "downloads": "Download configuration",
        "logging": "Logging and cleanup",
        "migration": "Migration from 3.x",
        "base-errors": "Error reference",
        "error-handling": "Errors and troubleshooting",
        "scraping-results": "Iteration and ScrapeResult",
        "pagination": "Pagination, iteration, and ScrapeResult",
        "searching": "Search and filtering",
        "search-engine": "Search and iteration",
        "downloading": "Downloading",
        "platforms": "Supported platforms",
        "cli": "CLI",
        "sorting-enums": "Sorting enums",
        "something": "Profile objects",
        "user-helper": "Profile objects",
        "pornstar-helper": "Profile objects",
    }
    return labels.get(stem, clean_heading(heading))


def summary_for(package: str, label: str) -> str:
    display = DISPLAY_NAMES.get(package, package)
    lower = label.lower()
    if lower == "installation":
        return f"Explains how to install the {display} shared base package and its optional download dependency."
    if "error" in lower or "troubleshoot" in lower:
        return f"Identifies documented {display} API errors, their meanings, and the safe handling behavior."
    if "download" in lower:
        return f"Explains the documented download configuration and download procedure for the {display} API."
    if "search" in lower:
        return f"Explains the documented search, filtering, sorting, and result behavior for the {display} API."
    if "changelog" in lower:
        return f"Records the versions and documented changes for the {display} API."
    if "platform" in lower:
        return f"Lists the operating systems and Python versions documented for the {display} API."
    if lower == "cli":
        return f"Documents the command-line interface, arguments, and examples for the {display} API."
    return f"Documents {label} behavior, signatures, fields, constraints, and examples for the {display} API."


def wrapper_specs(package: str) -> list[DocSpec]:
    path = DIST / package / "index.html"
    soup = BeautifulSoup(path.read_text(encoding="utf-8"), "html.parser")
    article = soup.select_one("article.content-area")
    assert article is not None
    sections = [s for s in article.find_all("div", class_="section", recursive=False)]
    sections = [s for s in sections if s.get("id") != "intro-section"]
    grouped: dict[str, list[Tag]] = {}
    for section in sections:
        grouped.setdefault(section_map(package, section["id"]), []).append(section)

    specs: list[DocSpec] = []
    display = DISPLAY_NAMES[package]
    for destination, group in grouped.items():
        ids = tuple(s["id"] for s in group)
        headings = [clean_heading((s.find(["h1", "h2", "h3"]) or s).get_text(" ", strip=True)) for s in group]
        if destination.endswith("getting-started.md"):
            label = "installation, quick start, and configuration"
            title = f"{display} API getting started"
            summary = f"Explains how to install, configure, and make a first asynchronous request with the {display} API."
            aliases = (f"{display} setup", f"install {display} API")
            keywords = (display, "pip install", "asyncio", "RuntimeConfig", "BaseCore")
            promote = False
        else:
            label = topic_label(group[0]["id"], headings[0])
            title = f"{label} — {display} API"
            summary = summary_for(package, label)
            aliases = (f"{display} {label}",)
            keywords = (display, label, *extract_heading_identifiers(group))
            promote = len(group) == 1
        specs.append(DocSpec(
            source=source_for(package), public_url=url_for(package), destination=destination,
            title=title, summary=summary, section_ids=ids, aliases=aliases,
            keywords=unique_terms(keywords), promote=promote,
        ))
    return specs


def eaf_specs() -> list[DocSpec]:
    package = "eaf_base_api"
    soup = BeautifulSoup((DIST / package / "index.html").read_text(encoding="utf-8"), "html.parser")
    article = soup.select_one("article.content-area")
    assert article is not None
    specs = []
    for section in article.find_all("div", class_="section", recursive=False):
        sid = section["id"]
        heading = clean_heading(section.find(["h1", "h2", "h3"]).get_text(" ", strip=True))
        label = "Overview" if sid == "overview-section" else "Changelog" if sid == "changelog-section" else topic_label(sid, heading)
        title = f"{label} — eaf_base_api"
        specs.append(DocSpec(
            source=source_for(package), public_url=url_for(package), destination=section_map(package, sid),
            title=title, summary=summary_for(package, label), section_ids=(sid,),
            aliases=(f"base API {label}", f"eaf base {label}"),
            keywords=unique_terms(("eaf_base_api", "base_api", label, *extract_heading_identifiers([section]))),
            promote=True,
        ))
    return specs


def portal_specs() -> list[DocSpec]:
    return [
        DocSpec(
            source="dist/index.html", public_url=BASE_URL, destination="overview.md",
            title="EAF Python API documentation overview",
            summary="Introduces the EAF asynchronous Python API ecosystem, its shared base engine, wrapper packages, and common capabilities.",
            section_ids=("core-networking-section", "scrapers-section", "shared-features-section"),
            aliases=("EchterAlsFake API docs", "EAF API wrappers"),
            keywords=("EAF", "Python API", "async", "eaf_base_api", "API wrappers"),
        ),
        DocSpec(
            source="dist/beeg/index.html", public_url=f"{BASE_URL}beeg/", destination="legal/disclaimer.md",
            title="Legal disclaimer for EAF API wrappers",
            summary="States the affiliation, warranty, responsibility, and acceptable-use disclaimer that applies to the documented wrappers.",
            section_ids=("intro-section",), aliases=("legal notice", "use at your own risk"),
            keywords=("unofficial", "not affiliated", "terms of service", "legal disclaimer"), promote=True,
        ),
    ]


def transparency_spec() -> DocSpec:
    return DocSpec(
        source="dist/transparency/index.html", public_url=f"{BASE_URL}transparency/",
        destination="project/ai-transparency.md", title="AI transparency statement",
        summary="Explains where AI assistance is used in the EAF ecosystem and the engineering principles governing its use.",
        section_ids=("philosophy-section", "usage-section", "principles-section", "distribution-section"),
        aliases=("AI usage disclosure", "artificial intelligence transparency"),
        keywords=("AI assistance", "documentation", "engineering review", "tool distribution"),
    )


def all_specs() -> list[DocSpec]:
    specs = portal_specs() + eaf_specs()
    for package in DISPLAY_NAMES:
        if package != "eaf_base_api":
            specs.extend(wrapper_specs(package))
    specs.append(transparency_spec())
    return specs


def extract_heading_identifiers(sections: list[Tag]) -> tuple[str, ...]:
    values: list[str] = []
    for section in sections:
        for heading in section.find_all(["h2", "h3", "h4"]):
            code = heading.find("code")
            if code:
                value = code.get_text(strip=True).removesuffix("()")
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
                    values.append(value)
            else:
                text = clean_heading(heading.get_text(" ", strip=True))
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
                    values.append(text)
    return unique_terms(values)[:12]


def unique_terms(values) -> tuple[str, ...]:
    generic = {
        "attribute", "attributes", "method", "methods", "parameter", "parameters",
        "return", "returns", "example", "examples", "overview", "installation",
        "configuration", "properties", "options",
    }
    seen = set()
    result = []
    for value in values:
        value = str(value).strip()
        key = value.casefold()
        if value and key not in seen and key not in generic:
            seen.add(key)
            result.append(value)
    return tuple(result)


def prepare_fragment(node: Tag, code_blocks: dict[str, tuple[str, str]]) -> Tag:
    node = copy.deepcopy(node)
    for removable in node.select(
        "button, script, style, .section-anchor, .section-icon, .method-tags, "
        ".card-logo, .card-actions, .empty-state, [aria-hidden='true']"
    ):
        removable.decompose()

    for heading in node.find_all(["h2", "h3", "h4", "h5", "h6"]):
        code = heading.find("code")
        if code:
            identifier = code.get_text(strip=True).removesuffix("()")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier):
                heading.clear()
                heading.append(f"MCP_EXACT_SYMBOL_{identifier}")
                heading["data-exact-symbol"] = "true"

    for table in list(node.find_all("table")):
        headers = [clean_heading(x.get_text(" ", strip=True)) for x in table.find_all("th")]
        identifier_headers = {
            "Attribute", "Extra Attribute", "Field", "ScrapeResult field", "Class", "Exception",
            "Error", "Setting", "Option", "Configuration key", "Parameter", "Member", "Enum Member",
            "Enum Value", "Method",
        }
        if not headers or headers[0] not in identifier_headers | {"Family"}:
            continue
        replacement = BeautifulSoup("<div></div>", "html.parser").div
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if not cells:
                continue
            if headers[0] == "Family":
                identifiers = [
                    code.get_text(" ", strip=True) for code in cells[1].find_all("code")
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", code.get_text(" ", strip=True))
                ]
                descriptions = [f"Family: {cells[0].get_text(' ', strip=True)}"] * len(identifiers)
            else:
                first = cells[0].get_text(" ", strip=True).removesuffix("()")
                identifier = first if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", first) else ""
                if headers[0] == "Method" and not identifier:
                    found = re.findall(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", first)
                    identifier = found[-1] if found else ""
                identifiers = [identifier] if identifier else []
                parts = []
                for index, cell in enumerate(cells[1:], start=1):
                    label = headers[index] if index < len(headers) else f"Value {index}"
                    parts.append(f"{label}: {cell.get_text(' ', strip=True)}")
                descriptions = ["; ".join(parts)] * len(identifiers)
            for identifier, description in zip(identifiers, descriptions):
                h = BeautifulSoup("<h2></h2>", "html.parser").h2
                h.string = f"MCP_EXACT_SYMBOL_{identifier}"
                h["data-exact-symbol"] = "true"
                replacement.append(h)
                p = BeautifulSoup("<p></p>", "html.parser").p
                p.string = description
                replacement.append(p)
        if replacement.contents:
            table.replace_with(replacement)

    for pre in list(node.find_all("pre")):
        parent = pre.parent
        language = "text"
        if isinstance(parent, Tag) and "code-window" in (parent.get("class") or []):
            header = parent.select_one(".code-header span")
            if header:
                language = header.get_text(strip=True).lower()
        if "method-signature" in (pre.get("class") or []):
            language = "python"
        code = pre.get_text("", strip=False).strip("\n")
        token = f"MCP_CODE_BLOCK_{len(code_blocks):04d}"
        code_blocks[token] = (language, code)
        marker = BeautifulSoup(f"<p>{token}</p>", "html.parser").p
        if isinstance(parent, Tag) and "code-window" in (parent.get("class") or []):
            parent.replace_with(marker)
        else:
            pre.replace_with(marker)

    for signature in list(node.select("div.method-signature")):
        code = signature.get_text("", strip=False).strip()
        token = f"MCP_CODE_BLOCK_{len(code_blocks):04d}"
        code_blocks[token] = ("python", code)
        signature.replace_with(BeautifulSoup(f"<p>{token}</p>", "html.parser").p)

    for header in node.select(".code-header"):
        header.decompose()
    for title in node.select(".info-box-title"):
        title.name = "strong"
        title.insert_after(BeautifulSoup("<br>", "html.parser").br)
    return node


def html_to_markdown(nodes: list[Tag], promote: bool, current_dest: str, specs: list[DocSpec]) -> str:
    code_blocks: dict[str, tuple[str, str]] = {}
    wrapper = BeautifulSoup("<div></div>", "html.parser").div
    for source_node in nodes:
        node = prepare_fragment(source_node, code_blocks)
        if promote:
            first = node.find(["h1", "h2", "h3"])
            if first:
                first.decompose()
            for heading in node.find_all(re.compile(r"^h[3-6]$")):
                heading.name = f"h{max(2, int(heading.name[1]) - 1)}"
        rewrite_links(node, current_dest, specs)
        wrapper.append(node)

    converter = html2text.HTML2Text()
    converter.body_width = 0
    converter.ignore_images = True
    converter.ignore_links = False
    converter.ignore_emphasis = False
    converter.protect_links = False
    converter.unicode_snob = True
    converter.pad_tables = False
    markdown = converter.handle(str(wrapper))
    for token, (language, code) in code_blocks.items():
        markdown = markdown.replace(token, f"```{language}\n{code}\n```")
    markdown = re.sub(r"^(#{2,6})\s+(.+)$", clean_markdown_heading, markdown, flags=re.MULTILINE)
    markdown = re.sub(r"^\s+\*\s+", "- ", markdown, flags=re.MULTILINE)
    markdown = re.sub(r"\n{3,}", "\n\n", markdown)
    markdown = re.sub(r"[ \t]+$", "", markdown, flags=re.MULTILINE)
    return markdown.strip()


def clean_markdown_heading(match: re.Match[str]) -> str:
    marks, text = match.groups()
    text = text.replace("\\_", "_").strip()
    marker = re.fullmatch(r"MCP_EXACT_SYMBOL_([A-Za-z_][A-Za-z0-9_]*)", text)
    if marker:
        return f"## {marker.group(1)}"
    text = re.sub(r"^[^\w`\[]+", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", " ", text)
    return f"{marks} {text}"


def rewrite_links(node: Tag, current_dest: str, specs: list[DocSpec]) -> None:
    source_lookup: dict[tuple[str, str], str] = {}
    for spec in specs:
        package = "portal" if spec.source == "dist/index.html" else Path(spec.source).parent.name
        for sid in spec.section_ids:
            source_lookup[(package, sid.removesuffix("-section"))] = spec.destination

    current_package = "portal" if current_dest in {"overview.md", "legal/disclaimer.md"} else None
    if current_package is None:
        for spec in specs:
            if spec.destination == current_dest:
                current_package = Path(spec.source).parent.name
                break

    for anchor in node.find_all("a", href=True):
        href = anchor["href"].strip()
        if href.startswith("#"):
            target_id = href[1:].removesuffix("-section")
            target = source_lookup.get((current_package, target_id))
            if target:
                anchor["href"] = relative_link(current_dest, target)
            else:
                anchor.unwrap()
        elif "eaf_base_api/index.html" in href:
            anchor["href"] = relative_link(current_dest, "eaf-base-api/overview.md")
        elif re.fullmatch(r"\./[a-z0-9_]+/?", href):
            package = href.removeprefix("./").strip("/")
            target = "eaf-base-api/overview.md" if package == "eaf_base_api" else f"{package}/getting-started.md"
            if any(spec.destination == target for spec in specs):
                anchor["href"] = relative_link(current_dest, target)
        elif urlparse(href).scheme in {"http", "https", "mailto"}:
            parsed = urlparse(href)
            if parsed.query:
                anchor["href"] = parsed._replace(query="", fragment="").geturl()


def relative_link(current: str, target: str) -> str:
    return posixpath.relpath(target, posixpath.dirname(current) or ".")


def yaml_block(spec: DocSpec, keywords: tuple[str, ...]) -> str:
    lines = [
        "---",
        f"title: {json.dumps(spec.title, ensure_ascii=False)}",
        f"summary: {json.dumps(spec.summary, ensure_ascii=False)}",
        f"public_url: {json.dumps(spec.public_url)}",
        "aliases:",
    ]
    lines.extend(f"  - {json.dumps(value, ensure_ascii=False)}" for value in spec.aliases)
    lines.append("keywords:")
    lines.extend(f"  - {json.dumps(value, ensure_ascii=False)}" for value in keywords)
    lines.append("---")
    return "\n".join(lines)


def related_section(spec: DocSpec, specs: list[DocSpec]) -> str:
    related: list[tuple[str, str]] = []
    package = Path(spec.source).parent.name if spec.source != "dist/index.html" else "portal"
    candidates = []
    if package not in {"portal", "transparency"}:
        candidates.extend([f"{package.replace('_', '-')}/overview.md" if package == "eaf_base_api" else f"{package}/getting-started.md"])
    if package not in {"portal", "eaf_base_api", "transparency"}:
        if spec.destination.endswith("getting-started.md"):
            candidates.extend([
                "eaf-base-api/configuration/runtime-config.md",
                "eaf-base-api/configuration/iterator-config.md",
            ])
        if spec.destination.endswith("guides/iteration-and-results.md"):
            candidates.extend([
                "eaf-base-api/configuration/iterator-config.md",
                "eaf-base-api/reference/scrape-stream-and-result.md",
                "eaf-base-api/guides/retry-and-error-handling.md",
            ])
        if spec.destination.endswith("guides/downloading.md"):
            candidates.append("eaf-base-api/configuration/downloads.md")
        if spec.destination.endswith("troubleshooting/errors.md"):
            candidates.append("eaf-base-api/troubleshooting/errors.md")
        candidates.extend([f"{package}/troubleshooting/errors.md", "eaf-base-api/overview.md", "legal/disclaimer.md"])
    elif package == "eaf_base_api":
        candidates.extend(["eaf-base-api/troubleshooting/errors.md", "overview.md"])
    else:
        candidates.extend(["overview.md", "legal/disclaimer.md"])
    by_dest = {item.destination: item for item in specs}
    for destination in candidates:
        if destination != spec.destination and destination in by_dest and destination not in {x[0] for x in related}:
            related.append((destination, by_dest[destination].title))
    lines = ["## Related MCP documents", ""]
    for destination, title in related:
        lines.append(f"- [{title}]({relative_link(spec.destination, destination)})")
    lines.extend(["", "## Original public page", "", f"- [{spec.public_url}]({spec.public_url})"])
    return "\n".join(lines)


def render(spec: DocSpec, specs: list[DocSpec]) -> str:
    soup = BeautifulSoup((ROOT / spec.source).read_text(encoding="utf-8"), "html.parser")
    nodes = []
    for sid in spec.section_ids:
        node = soup.find(id=sid)
        if node is None:
            raise RuntimeError(f"Missing section {sid} in {spec.source}")
        nodes.append(node)
    if spec.destination == "legal/disclaimer.md":
        nodes = [copy.deepcopy(node) for node in nodes]
        for node in nodes:
            for promotional in node.select(".info-box.success"):
                promotional.decompose()
    body = html_to_markdown(nodes, spec.promote, spec.destination, specs)
    body = remove_shared_boilerplate(body, spec)
    body = normalize_ambiguous_references(body)
    supplemental = supplemental_symbol_headings(spec, nodes)
    if supplemental:
        body = f"{supplemental}\n\n{body}"
    diagnostic = supplemental_diagnostic_messages(body, spec)
    if diagnostic:
        body = f"{body}\n\n{diagnostic}"
    dynamic = extract_identifiers_from_markdown(body)
    messages = tuple(message for _, message in diagnostic_messages(body))
    keywords = unique_terms((*spec.keywords, *dynamic, *messages))[:20]
    return f"{yaml_block(spec, keywords)}\n\n# {spec.title}\n\n{spec.summary}\n\n{body}\n\n{related_section(spec, specs)}\n"


def remove_shared_boilerplate(body: str, spec: DocSpec) -> str:
    """Remove generic prose duplicated verbatim across wrapper pages.

    Package-specific defaults, calls, signatures, and examples remain. The
    related-document section points to the canonical base API explanation.
    """
    if spec.source in {"dist/index.html", "dist/eaf_base_api/index.html", "dist/transparency/index.html"}:
        return body
    paragraphs = re.split(r"(\n\s*\n)", body)
    prefixes = (
        "`max_attempts` includes the first attempt. `page_error_handler`",
        "The core routes page-stage failures to `page_error_handler`",
        "The public configuration fields are `max_page_concurrency`",
        "Page and item handlers are routed independently. Assign the same callable",
    )
    result = []
    for part in paragraphs:
        if part.strip().startswith(prefixes):
            continue
        if part.strip() == "**Independent page and item handlers**":
            continue
        result.append(part)
    cleaned = "".join(result)
    cleaned = re.sub(
        r"\*\*Independent page and item handlers\*\*\nPage and item handlers are routed independently\..*?(?=\n\n|\Z)",
        "", cleaned, flags=re.DOTALL,
    )
    return re.sub(r"\n{3,}", "\n\n", cleaned).strip()


def normalize_ambiguous_references(body: str) -> str:
    replacements = {
        "Use the explicit interfaces documented below.":
            "Use the explicit request, media, iterator, and download interface references in this corpus.",
        "as below.": "as shown in this document.",
        "the example below": "the example in this document",
    }
    for old, new in replacements.items():
        body = body.replace(old, new)
    return body


def diagnostic_messages(body: str) -> list[tuple[str, str]]:
    pairs = []
    patterns = (
        r"(?:if|elif)\s+isinstance\([^,\n]+,\s*([A-Za-z_][A-Za-z0-9_]*)\):\s*\n\s*print\(\"([^\"]+)\"\)",
        r"except\s+([A-Za-z_][A-Za-z0-9_]*)[^:]*:\s*\n\s*print\(\"([^\"]+)\"\)",
    )
    for pattern in patterns:
        pairs.extend(re.findall(pattern, body))
    return list(dict.fromkeys(pairs))


def supplemental_diagnostic_messages(body: str, spec: DocSpec) -> str:
    if "/troubleshooting/" not in spec.destination:
        return ""
    pairs = diagnostic_messages(body)
    if not pairs:
        return ""
    lines = [
        "## Example diagnostic messages",
        "",
        "The public page presents these strings as output from its handling example, not as text raised by the library:",
        "",
    ]
    lines.extend(
        f"- `{message}` is printed when the example handles `{exception}`."
        for exception, message in pairs
    )
    lines.extend([
        "",
        "Diagnose the condition by inspecting the typed exception or `MediaLoadError.original_error` as shown. "
        "Handle the documented type and re-raise unrecognized failures; the source page does not prescribe any other automated corrective action.",
    ])
    return "\n".join(lines)


def supplemental_symbol_headings(spec: DocSpec, nodes: list[Tag]) -> str:
    symbols: list[str] = []
    if spec.destination.endswith("reference/profile-objects.md"):
        heading = nodes[0].find(["h1", "h2", "h3"])
        text = clean_heading(heading.get_text(" ", strip=True)) if heading else ""
        text = re.sub(r"^(User|Pornstar)\s*/\s*", r"\1 / ", text)
        for part in text.split("/"):
            candidate = clean_heading(part).split()[0] if clean_heading(part) else ""
            if re.fullmatch(r"[A-Z][A-Za-z0-9_]*", candidate):
                symbols.append(candidate)
    if spec.destination == "eaf-base-api/reference/scrape-stream-and-result.md":
        symbols.append("ScrapeResult")
    if spec.destination.endswith("/reference/cli.md"):
        for node in nodes:
            for pre in node.find_all("pre"):
                for line in pre.get_text("", strip=False).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    command = line.split(maxsplit=1)[0]
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", command):
                        symbols.append(command)
                        break
    symbols = [s for s in unique_terms(symbols) if not spec.title.startswith(f"{s} ")]
    if not symbols:
        return ""
    return "\n\n".join(
        f"## {symbol}\n\n`{symbol}` uses the shared behavior documented in this reference."
        for symbol in symbols
    )


def extract_identifiers_from_markdown(markdown: str) -> tuple[str, ...]:
    identifiers = []
    for match in re.finditer(r"^##\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", markdown, flags=re.MULTILINE):
        identifiers.append(match.group(1))
    return unique_terms(identifiers)


def build_source_map(specs: list[DocSpec]) -> list[dict]:
    return [
        {
            "source_html_path": spec.source,
            "source_public_url": spec.public_url,
            "destination_markdown_path": spec.destination,
            "conversion_status": "converted",
            "unresolved_issues": [],
        }
        for spec in sorted(specs, key=lambda item: (item.source, item.destination))
    ]


def pilot_specs(specs: list[DocSpec]) -> list[DocSpec]:
    destinations = {
        "overview.md", "beeg/getting-started.md", "beeg/reference/client.md",
        "beeg/troubleshooting/errors.md",
    }
    return [spec for spec in specs if spec.destination in destinations]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()
    specs = all_specs()
    selected = pilot_specs(specs) if args.pilot else specs
    for spec in selected:
        destination = OUT / spec.destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(render(spec, specs), encoding="utf-8")
    if not args.pilot:
        (REPORT / "source-map.json").write_text(
            json.dumps(build_source_map(specs), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(f"created {len(selected)} Markdown documents")


if __name__ == "__main__":
    main()
