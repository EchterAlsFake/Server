from pathlib import Path
import tempfile
import unittest

from mcp_service.catalog import DocumentationCatalog


DOCS = Path(__file__).resolve().parents[2] / "docs/mcp-docs"


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = DocumentationCatalog(DOCS)

    def test_all_public_markdown_is_catalogued(self):
        expected = sum(1 for path in DOCS.rglob("*.md") if not path.is_symlink())
        self.assertEqual(len(self.catalog.documents), expected)
        self.assertIn("pornhub", self.catalog.packages)

    def test_list_can_filter_exact_package(self):
        results = self.catalog.list("pornhub")
        self.assertGreater(len(results), 5)
        self.assertTrue(all(item["package"] == "pornhub" for item in results))
        with self.assertRaisesRegex(ValueError, "unknown_package"):
            self.catalog.list("porn")

    def test_read_rejects_traversal_and_unknown_paths(self):
        self.assertIn("# EAF Python API", self.catalog.read("overview.md"))
        for path in ("../README.md", "/etc/passwd", "pornhub/../../README.md", "missing.md"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.catalog.read(path)

    def test_search_is_ranked_bounded_and_filtered(self):
        results = self.catalog.search("download HLS", package="pornhub", limit=2)
        self.assertLessEqual(len(results), 2)
        self.assertTrue(results)
        self.assertTrue(all(item["package"] == "pornhub" for item in results))
        self.assertTrue(all(len(str(item["excerpt"])) <= 422 for item in results))

    def test_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root.parent / "private-mcp-test.md"
            outside.write_text("secret")
            try:
                (root / "link.md").symlink_to(outside)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    DocumentationCatalog(root)
            finally:
                outside.unlink()
