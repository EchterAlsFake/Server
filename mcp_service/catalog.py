"""Bounded, path-safe in-memory catalog for public Markdown documentation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re

MAX_DOCUMENT_BYTES = 128 * 1024
MAX_QUERY_LENGTH = 200
MAX_RESULTS = 20
FRONT_MATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
HEADING_RE = re.compile(r"(?m)^#{1,6}\s+(.+?)\s*$")


@dataclass(frozen=True, slots=True)
class Document:
    path: str
    package: str
    title: str
    summary: str
    content: str

    def metadata(self) -> dict[str, str]:
        return {
            "path": self.path,
            "package": self.package,
            "title": self.title,
            "summary": self.summary,
        }


def _front_matter(content: str) -> dict[str, str]:
    match = FRONT_MATTER_RE.match(content)
    if not match:
        return {}
    values: dict[str, str] = {}
    for line in match.group(1).splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in {"title", "summary"}:
            values[key.strip()] = value.strip().strip("\"'")
    return values


def _plain_text(content: str) -> str:
    plain = FRONT_MATTER_RE.sub("", content)
    plain = re.sub(r"[#*_>\[\]()]+", " ", plain)
    return " ".join(plain.split())


def _excerpt(content: str, position: int, length: int = 420) -> str:
    plain = _plain_text(content)
    if not plain:
        return ""
    position = min(max(position, 0), len(plain))
    start = max(0, position - length // 3)
    end = min(len(plain), start + length)
    if start:
        start = plain.find(" ", start)
        start = 0 if start < 0 else start + 1
    if end < len(plain):
        boundary = plain.rfind(" ", start, end)
        end = boundary if boundary > start else end
    return ("…" if start else "") + plain[start:end] + ("…" if end < len(plain) else "")


class DocumentationCatalog:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        documents: dict[str, Document] = {}
        for source in sorted(self.root.rglob("*.md")):
            resolved = source.resolve(strict=True)
            if source.is_symlink() or not resolved.is_relative_to(self.root):
                raise ValueError("documentation_symlink_not_allowed")
            if resolved.stat().st_size > MAX_DOCUMENT_BYTES:
                raise ValueError("documentation_file_too_large")
            content = resolved.read_text(encoding="utf-8")
            relative = resolved.relative_to(self.root).as_posix()
            values = _front_matter(content)
            heading = HEADING_RE.search(FRONT_MATTER_RE.sub("", content))
            title = values.get("title") or (heading.group(1).strip() if heading else relative)
            summary = values.get("summary", "")
            package = relative.split("/", 1)[0] if "/" in relative else "project"
            documents[relative] = Document(relative, package, title, summary, content)
        if not documents:
            raise ValueError("documentation_corpus_empty")
        self._documents = documents

    @property
    def documents(self) -> tuple[Document, ...]:
        return tuple(self._documents.values())

    @property
    def packages(self) -> tuple[str, ...]:
        return tuple(sorted({document.package for document in self._documents.values()}))

    def list(self, package: str | None = None) -> list[dict[str, str]]:
        normalized = package.strip().casefold() if package else None
        if normalized and normalized not in {value.casefold() for value in self.packages}:
            raise ValueError("unknown_package")
        return [
            document.metadata()
            for document in self._documents.values()
            if normalized is None or document.package.casefold() == normalized
        ]

    def read(self, path: str) -> str:
        if not isinstance(path, str) or len(path) > 512 or chr(0) in path or "\\" in path:
            raise ValueError("invalid_document_path")
        candidate = PurePosixPath(path.strip())
        if candidate.is_absolute() or ".." in candidate.parts or str(candidate) != path.strip():
            raise ValueError("invalid_document_path")
        document = self._documents.get(candidate.as_posix())
        if document is None:
            raise ValueError("document_not_found")
        return document.content

    def search(
        self, query: str, package: str | None = None, limit: int = 10
    ) -> list[dict[str, str | int]]:
        if not isinstance(query, str):
            raise ValueError("invalid_query")
        query = " ".join(query.split())
        if not 2 <= len(query) <= MAX_QUERY_LENGTH:
            raise ValueError("invalid_query")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("invalid_limit")
        limit = min(max(limit, 1), MAX_RESULTS)
        candidates = self.list(package)
        terms = tuple(dict.fromkeys(term.casefold() for term in query.split()))
        phrase = query.casefold()
        results: list[tuple[int, dict[str, str | int]]] = []
        for metadata in candidates:
            document = self._documents[metadata["path"]]
            title = document.title.casefold()
            summary = document.summary.casefold()
            body = _plain_text(document.content).casefold()
            if not all(term in body or term in title or term in summary for term in terms):
                continue
            score = 20 * title.count(phrase) + 10 * summary.count(phrase) + 5 * body.count(phrase)
            score += sum(6 * title.count(term) + 3 * summary.count(term) + body.count(term) for term in terms)
            first = min((body.find(term) for term in terms if term in body), default=0)
            results.append((score, {**metadata, "score": score, "excerpt": _excerpt(document.content, first)}))
        results.sort(key=lambda item: (-item[0], str(item[1]["path"])))
        return [result for _, result in results[:limit]]
