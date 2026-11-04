#!/usr/bin/env python3
"""Offline Chromium checks for the production IPv6 download selector.

Run with a Python environment containing Playwright and its Chromium browser.
All browser requests are intercepted; no real downloads or network calls occur.
"""
import asyncio
from pathlib import Path

from playwright.async_api import async_playwright

ORIGIN = "https://pornfetch.to"
DIRECT = "https://direct6.pornfetch.to"
PATH = "/downloads/3.9.66/app.zip"
SCRIPT = (Path(__file__).parents[1] / "static/direct-downloads.js").read_text()
HTML = f'''<a id="download" href="{DIRECT}{PATH}" data-vps-url="{PATH}">Download</a>
<a data-download-retry hidden>Retry</a><script src="/static/direct-downloads.js"></script>'''


async def main():
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        for mode in ("success", "unreachable", "missing", "timeout"):
            context = await browser.new_context()
            page = await context.new_page()
            transfers = []
            async def route(request):
                url = request.request.url
                if url == ORIGIN + "/download":
                    return await request.fulfill(body=HTML, content_type="text/html")
                if url.endswith("/static/direct-downloads.js"):
                    return await request.fulfill(body=SCRIPT, content_type="text/javascript")
                if url == DIRECT + PATH and request.request.method == "HEAD":
                    if mode == "unreachable":
                        return await request.abort("connectionrefused")
                    if mode == "timeout":
                        await asyncio.sleep(4)
                        return
                    return await request.fulfill(status=404 if mode == "missing" else 200,
                                                 headers={"Access-Control-Allow-Origin": ORIGIN})
                if url in (ORIGIN + PATH, DIRECT + PATH):
                    transfers.append(url)
                    return await request.fulfill(body="download", content_type="text/plain")
                raise AssertionError("Unexpected browser request: " + url)
            await context.route("**/*", route)
            await page.goto(ORIGIN + "/download")
            await page.locator("#download").click()
            expected = (DIRECT if mode == "success" else ORIGIN) + PATH
            await page.wait_for_url(expected, timeout=6000)
            assert transfers == [expected], (mode, transfers)
            print("PASS browser", mode)
            await context.close()
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
