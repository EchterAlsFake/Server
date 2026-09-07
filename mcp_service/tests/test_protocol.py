import asyncio
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


class ProtocolTests(unittest.TestCase):
    def test_public_streamable_http_tools_and_resources(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "mcp_service.app:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-access-log",
                "--log-level",
                "error",
            ]
        )
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if process.poll() is not None:
                    self.fail("MCP service exited before accepting connections")
                time.sleep(0.1)
        else:
            self.fail("MCP service did not become ready")

        async def exercise():
            url = f"http://127.0.0.1:{port}/mcp"
            async with streamable_http_client(url) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    initialized = await session.initialize()
                    self.assertEqual(initialized.server_info.name, "eaf-python-api-docs")
                    tools = await session.list_tools()
                    self.assertEqual(
                        {tool.name for tool in tools.tools},
                        {"list_documentation", "read_documentation", "search_documentation"},
                    )
                    resources = await session.list_resources()
                    docs = Path(__file__).resolve().parents[2] / "docs/mcp-docs"
                    expected = sum(1 for path in docs.rglob("*.md") if not path.is_symlink())
                    self.assertEqual(len(resources.resources), expected)
                    result = await session.call_tool(
                        "search_documentation",
                        {"query": "HTTP retries", "limit": 3},
                    )
                    self.assertFalse(result.is_error)
                    self.assertLessEqual(len(result.structured_content["result"]), 3)
                    resource = await session.read_resource(str(resources.resources[0].uri))
                    self.assertTrue(resource.contents)

        try:
            asyncio.run(exercise())
        finally:
            process.terminate()
            process.wait(timeout=10)
