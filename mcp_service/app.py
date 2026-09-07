"""Unauthenticated, stateless Streamable HTTP server for public EAF docs."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

from .catalog import DocumentationCatalog


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = Path(os.environ.get("EAF_MCP_DOCS_DIR", PROJECT_ROOT / "docs/mcp-docs"))
catalog = DocumentationCatalog(DOCS_ROOT)

server = MCPServer(
    name="eaf-python-api-docs",
    title="EAF Python API Documentation",
    description="Public, read-only documentation for the EAF Python API ecosystem.",
    version="1.0.0",
    log_level="WARNING",
    website_url="https://docs.echteralsfake.me/",
    instructions=(
        "Use search_documentation to find relevant documents, then "
        "read_documentation or the eaf-docs resources for complete Markdown. "
        "This server performs no package operations and changes no external state."
    ),
)


@server.tool(structured_output=True)
def list_documentation(package: str | None = None) -> list[dict[str, str]]:
    """List public documents, optionally restricted to an exact package name."""
    return catalog.list(package)


@server.tool(structured_output=True)
def read_documentation(path: str) -> str:
    """Read one complete Markdown document using a path returned by list or search."""
    return catalog.read(path)


@server.tool(structured_output=True)
def search_documentation(
    query: str, package: str | None = None, limit: int = 10
) -> list[dict[str, str | int]]:
    """Search titles, summaries, and Markdown; return ranked bounded excerpts."""
    return catalog.search(query, package, limit)


def _reader(content: str):
    def read_resource() -> str:
        return content

    return read_resource


for index, document in enumerate(catalog.documents):
    server.resource(
        "eaf-docs:///" + quote(document.path, safe="/"),
        name=f"eaf_doc_{index:03d}",
        title=document.title,
        description=document.summary or f"EAF documentation: {document.path}",
        mime_type="text/markdown",
    )(_reader(document.content))


@server.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"ok": True, "documents": len(catalog.documents)})


app = server.streamable_http_app(
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    max_request_body_size=256 * 1024,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            "mcp.echteralsfake.me",
            "mcp.echteralsfake.me:443",
            "127.0.0.1:*",
            "localhost:*",
        ],
        allowed_origins=["https://mcp.echteralsfake.me"],
    ),
)
