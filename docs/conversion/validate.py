#!/usr/bin/env python3
"""Non-destructive validation for the MCP Markdown corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml
from bs4 import BeautifulSoup

from convert import ROOT, OUT, REPORT, all_specs, pilot_specs


REQUIRED_METADATA = {"title", "summary", "public_url", "aliases", "keywords"}
FORBIDDEN_TEXT = (
    "<script", "<style", "googletagmanager", "google-analytics", "gtag(",
    "datalayer", "cookie banner", "onclick=", "copycode(",
)
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "generic assigned secret": re.compile(
        r"(?im)^\s*(?:api[_-]?key|secret|password|access[_-]?token)\s*=\s*['\"][^<{][^'\"]{12,}['\"]"
    ),
}


def prose_lines(markdown: str) -> list[str]:
    lines = []
    in_fence = False
    in_frontmatter = False
    frontmatter_seen = False
    for index, line in enumerate(markdown.splitlines()):
        if index == 0 and line == "---":
            in_frontmatter = True
            frontmatter_seen = True
            continue
        if in_frontmatter and line == "---":
            in_frontmatter = False
            continue
        if in_frontmatter:
            continue
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    if not frontmatter_seen:
        return markdown.splitlines()
    return lines


def markdown_links(text: str):
    for match in re.finditer(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", text):
        yield match.group(1).split(" ", 1)[0].strip("<>")


def source_hashes() -> dict[str, str]:
    hashes = {}
    for line in (REPORT / "source-sha256-before.txt").read_text(encoding="utf-8").splitlines():
        digest, path = line.split(maxsplit=1)
        hashes[path] = digest
    return hashes


def expected_symbols(spec) -> set[str]:
    soup = BeautifulSoup((ROOT / spec.source).read_text(encoding="utf-8"), "html.parser")
    nodes = [soup.find(id=sid) for sid in spec.section_ids]
    expected: set[str] = set()
    first_title_token = spec.title.split(maxsplit=1)[0]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", first_title_token):
        expected.add(first_title_token)
    identifier_headers = {
        "Attribute", "Extra Attribute", "Field", "ScrapeResult field", "Class", "Exception",
        "Error", "Setting", "Option", "Configuration key", "Parameter", "Member", "Enum Member",
        "Enum Value", "Method",
    }
    for node in nodes:
        if node is None:
            continue
        if "/reference/" in spec.destination and spec.destination.endswith("profile-objects.md"):
            top = node.find(["h1", "h2", "h3"])
            if top:
                for part in top.get_text(" ", strip=True).split("/"):
                    words = re.findall(r"[A-Z][A-Za-z0-9_]*", part)
                    if words:
                        expected.add(words[0])
        for heading in node.find_all(["h2", "h3", "h4"]):
            code = heading.find("code")
            if code:
                identifier = code.get_text(strip=True).removesuffix("()")
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier):
                    expected.add(identifier)
        for table in node.find_all("table"):
            headers = [x.get_text(" ", strip=True) for x in table.find_all("th")]
            if not headers:
                continue
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if not cells:
                    continue
                if headers[0] == "Family":
                    for code in cells[1].find_all("code"):
                        identifier = code.get_text(" ", strip=True)
                        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier):
                            expected.add(identifier)
                elif headers[0] in identifier_headers:
                    first = cells[0].get_text(" ", strip=True).removesuffix("()")
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", first):
                        expected.add(first)
                    elif headers[0] == "Method":
                        found = re.findall(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", first)
                        if found:
                            expected.add(found[-1])
        if spec.destination.endswith("/reference/cli.md"):
            for pre in node.find_all("pre"):
                for line in pre.get_text("", strip=False).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    command = line.split(maxsplit=1)[0]
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", command):
                        expected.add(command)
                        break
    return expected


def validate(pilot: bool) -> dict:
    planned_specs = all_specs()
    selected_specs = pilot_specs(planned_specs) if pilot else planned_specs
    expected = {spec.destination for spec in selected_specs}
    planned = {spec.destination for spec in planned_specs}
    files = sorted(OUT.rglob("*.md"))
    if pilot:
        files = [path for path in files if path.relative_to(OUT).as_posix() in expected]

    errors: list[str] = []
    warnings: list[str] = []
    details = []
    document_fingerprints: dict[str, str] = {}

    symlinks = [p.relative_to(OUT).as_posix() for p in OUT.rglob("*") if p.is_symlink()]
    if symlinks:
        errors.append(f"Symlinks found: {symlinks}")

    for path in files:
        rel = path.relative_to(OUT).as_posix()
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"{rel}: invalid UTF-8: {exc}")
            continue
        if not text.startswith("---\n") or "\n---\n" not in text[4:]:
            errors.append(f"{rel}: missing YAML front matter")
            continue
        frontmatter = text.split("---", 2)[1]
        try:
            metadata = yaml.safe_load(frontmatter)
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: invalid YAML: {exc}")
            continue
        missing = REQUIRED_METADATA - set(metadata or {})
        if missing:
            errors.append(f"{rel}: missing metadata {sorted(missing)}")
        if not isinstance(metadata.get("aliases"), list) or not metadata.get("aliases"):
            errors.append(f"{rel}: aliases must be a non-empty list")
        if not isinstance(metadata.get("keywords"), list) or not metadata.get("keywords"):
            errors.append(f"{rel}: keywords must be a non-empty list")

        spec = next((item for item in planned_specs if item.destination == rel), None)
        if spec and metadata.get("public_url") != spec.public_url:
            errors.append(f"{rel}: public_url does not match mapped source page")

        prose = prose_lines(text)
        headings = [line for line in prose if re.match(r"^#{1,6}\s+", line)]
        h1s = [line for line in headings if line.startswith("# ")]
        if len(h1s) != 1:
            errors.append(f"{rel}: expected exactly one H1, found {len(h1s)}")
        if not headings or not headings[0].startswith("# "):
            errors.append(f"{rel}: first Markdown heading is not the citation H1")
        elif metadata.get("title") and headings[0] != f"# {metadata['title']}":
            errors.append(f"{rel}: citation H1 differs from metadata title")

        heading_symbols = {
            match.group(1)
            for line in headings
            if (match := re.match(r"^#{1,6}\s+`?([A-Za-z_][A-Za-z0-9_]*)\b", line))
        }
        if spec:
            missing_symbols = sorted(expected_symbols(spec) - heading_symbols)
            if missing_symbols:
                errors.append(f"{rel}: missing exact identifier headings: {missing_symbols}")

        for href in markdown_links(text):
            parsed = urlparse(href)
            if parsed.scheme or href.startswith("#"):
                continue
            target_part = href.split("#", 1)[0]
            target = (path.parent / target_part).resolve()
            try:
                target_rel = target.relative_to(OUT.resolve()).as_posix()
            except ValueError:
                errors.append(f"{rel}: relative link escapes corpus: {href}")
                continue
            if not target.exists():
                if pilot and target_rel in planned:
                    warnings.append(f"{rel}: planned post-pilot link not created yet: {href}")
                else:
                    errors.append(f"{rel}: unresolved relative link: {href}")

        lower = text.casefold()
        for forbidden in FORBIDDEN_TEXT:
            if forbidden in lower:
                errors.append(f"{rel}: forbidden presentation/tracking text: {forbidden}")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{rel}: possible {label}")

        size = len(raw)
        if size > 512 * 1024:
            errors.append(f"{rel}: exceeds 512 KiB ({size} bytes)")
        elif size > 128 * 1024:
            warnings.append(f"{rel}: exceeds 128 KiB ({size} bytes)")
        elif size > 64 * 1024:
            warnings.append(f"{rel}: exceeds 64 KiB target ({size} bytes)")

        content_region = text.split("## Related MCP documents", 1)[0]
        content_region = re.sub(r"\A---.*?---\s*", "", content_region, flags=re.DOTALL)
        content_region = re.sub(r"^# .*?$", "", content_region, count=1, flags=re.MULTILINE)
        normalized_document = re.sub(r"\s+", " ", content_region).strip().casefold()
        document_fingerprints[rel] = hashlib.sha256(normalized_document.encode()).hexdigest()

        details.append({"path": rel, "bytes": size, "headings": len(headings), "h1_count": len(h1s)})

    fingerprint_groups: dict[str, list[str]] = {}
    for path, fingerprint in document_fingerprints.items():
        fingerprint_groups.setdefault(fingerprint, []).append(path)
    duplicates = [sorted(paths) for paths in fingerprint_groups.values() if len(paths) > 1]
    if duplicates:
        errors.extend(f"Duplicated long-form content: {paths}" for paths in duplicates)

    for source, expected_hash in source_hashes().items():
        digest = hashlib.sha256((ROOT / source).read_bytes()).hexdigest()
        if digest != expected_hash:
            errors.append(f"HTML source changed: {source}")

    missing_outputs = sorted(expected - {p.relative_to(OUT).as_posix() for p in files})
    if missing_outputs:
        errors.append(f"Missing expected outputs: {missing_outputs}")

    retrieval_case_count = 0
    if not pilot:
        cases = json.loads((REPORT / "retrieval-cases.json").read_text(encoding="utf-8"))
        retrieval_case_count = len(cases)
        for index, case in enumerate(cases, start=1):
            required = {"query", "expected_markdown_path", "expected_heading", "expected_important_terms"}
            missing_case_fields = required - set(case)
            if missing_case_fields:
                errors.append(f"Retrieval case {index}: missing fields {sorted(missing_case_fields)}")
                continue
            target = OUT / case["expected_markdown_path"]
            if not target.is_file():
                errors.append(f"Retrieval case {index}: missing target {case['expected_markdown_path']}")
                continue
            target_text = target.read_text(encoding="utf-8")
            target_prose = prose_lines(target_text)
            expected_heading = case["expected_heading"]
            if not any(re.fullmatch(rf"#{{1,6}}\s+{re.escape(expected_heading)}", line) for line in target_prose):
                errors.append(f"Retrieval case {index}: heading not found: {expected_heading}")
            for term in case["expected_important_terms"]:
                if term.casefold() not in target_text.casefold():
                    errors.append(f"Retrieval case {index}: important term not found: {term}")
            symbol = case.get("expected_symbol")
            if symbol and not any(
                re.match(rf"^#{{1,6}}\s+`?{re.escape(symbol)}(?:`|\b)", line)
                for line in target_prose
            ):
                errors.append(f"Retrieval case {index}: exact symbol heading not found: {symbol}")

    return {
        "mode": "pilot" if pilot else "full",
        "status": "pass" if not errors else "fail",
        "markdown_documents_checked": len(files),
        "errors": errors,
        "warnings": sorted(set(warnings)),
        "largest_file": max(details, key=lambda item: item["bytes"]) if details else None,
        "files": details,
        "html_source_unchanged": not any(x.startswith("HTML source changed") for x in errors),
        "symlink_count": len(symlinks),
        "retrieval_cases_checked": retrieval_case_count,
    }


def write_report(result: dict) -> None:
    (REPORT / "validation-report.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# MCP Markdown validation",
        "",
        f"- Mode: {result['mode']}",
        f"- Status: {result['status']}",
        f"- Markdown documents checked: {result['markdown_documents_checked']}",
        f"- HTML source unchanged: {result['html_source_unchanged']}",
        f"- Symlinks: {result['symlink_count']}",
        f"- Retrieval cases checked: {result['retrieval_cases_checked']}",
        f"- Largest file: `{result['largest_file']['path']}` ({result['largest_file']['bytes']} bytes)" if result["largest_file"] else "- Largest file: none",
        "",
        "## Errors",
        "",
    ]
    lines.extend(f"- {item}" for item in result["errors"] or ["None."])
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {item}" for item in result["warnings"] or ["None."])
    (REPORT / "VALIDATION.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()
    result = validate(args.pilot)
    write_report(result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
