import html
import re
import unittest

from docs.build import highlight_python_blocks


class DocsHighlightTests(unittest.TestCase):
    def test_highlighting_preserves_code_and_escapes_html(self):
        source = 'import asyncio\n# a comment\nvalue = "<script>&"\ncount = 42\n'
        block = '<pre><code class="language-python">' + html.escape(source) + '</code></pre>'
        rendered = highlight_python_blocks(block)
        for kind in ('keyword', 'comment', 'string', 'number'):
            self.assertIn(f'class="token-{kind}"', rendered)
        code = rendered.split('>', 2)[2].split('</code>')[0]
        self.assertEqual(html.unescape(re.sub(r'<[^>]+>', '', code)), source)
        self.assertNotIn('<script>', rendered)

    def test_partial_python_example_still_builds(self):
        source = 'async def example(\n'
        block = '<pre><code class="language-python">' + source + '</code></pre>'
        rendered = highlight_python_blocks(block)
        self.assertIn('token-keyword', rendered)
        self.assertTrue(rendered.endswith('example(\n</code></pre>'))

    def test_existing_manual_highlighting_and_shell_are_preserved(self):
        source = '<pre><code><span class="token-keyword">import</span> asyncio</code></pre>'
        source += '<pre><code class="language-sh">pip install package</code></pre>'
        self.assertEqual(highlight_python_blocks(source), source)
