"""Synthetic CI-to-website publication, direct downloads, SEO and mobile cards.

Every artifact is inert test data. Browser third-party traffic is blocked.
"""

import argparse
import hashlib
import http.client
import importlib.util
import ssl
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "tests"))
from playwright.sync_api import expect, sync_playwright
from test_website_releases import WebsiteReleaseTests, main
from werkzeug.serving import make_server


def run(browser_name="chromium"):
    fixture = WebsiteReleaseTests()
    fixture.setUp()
    main.app.config["WTF_CSRF_ENABLED"] = True
    server = make_server(
        "127.0.0.1",
        0,
        main.app,
        ssl_context="adhoc",
        threaded=True,
        request_handler=main.NoIPLoggingHandler,
    )
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f"https://localhost:{server.server_port}"
    failures = []
    try:
        manifest = fixture.manifest()
        manifest["notes"] = (
            "New platform downloads.\nSynthetic release used only for local UI verification."
        )
        manifest["artifacts"] = []
        for platform in ("linux", "windows", "macos"):
            for arch in ("x64", "arm64"):
                for kind in ("gui", "cli"):
                    manifest["artifacts"].append(
                        {
                            "filename": f"PornFetch_{platform}_{kind.upper()}_{arch}.zip",
                            "platform": platform,
                            "arch": arch,
                            "kind": kind,
                            "size": len(fixture.payload),
                            "sha256": hashlib.sha256(fixture.payload).hexdigest(),
                            "experimental": False,
                            "min_os": "Release-specific requirements",
                        }
                    )
        for arch in ("arm64", "armv7", "x86", "x64"):
            manifest["artifacts"].append(
                {
                    "filename": f"PornFetch_android_GUI_{arch}.apk",
                    "platform": "android",
                    "arch": arch,
                    "kind": "apk",
                    "size": len(fixture.payload),
                    "sha256": hashlib.sha256(fixture.payload).hexdigest(),
                    "experimental": False,
                    "min_os": "Android 9.0 or later (API 28)",
                }
            )
        manifest["artifacts"].append(
            {
                "filename": "PornFetch_windows_GUI_x64_Setup.exe",
                "platform": "windows",
                "arch": "x64",
                "kind": "installer",
                "size": len(fixture.payload),
                "sha256": hashlib.sha256(fixture.payload).hexdigest(),
                "experimental": True,
                "min_os": "Windows 10 or later",
            }
        )
        manifest["artifacts"].append(
            {
                "filename": "PornFetch_source_3.9.66.tar.gz",
                "platform": "any",
                "arch": "any",
                "kind": "source",
                "size": len(fixture.payload),
                "sha256": hashlib.sha256(fixture.payload).hexdigest(),
                "experimental": False,
                "min_os": "Source setup varies by platform",
            }
        )
        prepared = fixture.root.parent / "prepared"
        prepared.mkdir()
        for artifact in manifest["artifacts"]:
            (prepared / artifact["filename"]).write_bytes(fixture.payload)
        publisher_path = root.parent / "Porn_Fetch/packaging/publish_website_release.py"
        if publisher_path.exists():
            spec = importlib.util.spec_from_file_location(
                "ci_publisher", publisher_path
            )
            publisher = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(publisher)
            https = http.client.HTTPSConnection
            # Test-server certificate only; production publisher uses verified TLS.
            local_http = SimpleNamespace(
                client=SimpleNamespace(
                    HTTPSConnection=lambda *args, **kwargs: https(
                        *args, context=ssl._create_unverified_context(), **kwargs
                    )
                )
            )
            with patch.object(publisher, "http", local_http):
                publisher.publish(origin, "synthetic-website-token", prepared, manifest)
        else:
            fixture.stage(manifest)
            for artifact in manifest["artifacts"]:
                response = fixture.client.put(
                    f"/ci/website-releases/3.9.66/files/{artifact['filename']}",
                    data=fixture.payload,
                    headers=fixture.headers,
                )
                assert response.status_code == 201
            assert fixture.publish(manifest).status_code == 200
        with sync_playwright() as p:
            browser = getattr(p, browser_name).launch()
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1440, "height": 1000},
                reduced_motion="reduce",
            )
            context.route(
                "**/*",
                lambda route: (
                    route.continue_()
                    if route.request.url.startswith(origin)
                    else route.abort()
                ),
            )
            page = context.new_page()
            page.on("pageerror", lambda error: failures.append(str(error)))
            page.goto(origin + "/download")
            expect(page.locator("#age-overlay")).to_have_count(0)
            expect(page.locator(".platform-selector a")).to_have_count(5)
            expect(page.locator(".platform-panel:visible")).to_have_count(1)
            page.locator('[data-platform="windows"]').click()
            expect(page.locator("#windows")).to_be_visible()
            expect(page.locator("#windows .advanced-downloads")).not_to_have_attribute(
                "open", ""
            )
            page.locator("#windows .primary-package").select_option(index=1)
            expect(page.locator(".primary-cta:visible")).to_have_count(1)
            expect(page.locator("#windows .primary-version")).to_contain_text("Beta")
            with page.expect_download() as event:
                page.locator("#windows .primary-cta").click()
            download = event.value
            assert download.suggested_filename.endswith(".zip")
            assert Path(download.path()).read_bytes() == fixture.payload
            page.locator("#windows .advanced-downloads > summary").click()
            expect(page.locator("#windows .package-list").first).to_contain_text(
                "Experimental Qt installer"
            )
            expect(page.locator("#windows .cli-downloads")).not_to_have_attribute(
                "open", ""
            )
            page.locator("#windows .cli-downloads > summary").click()
            expect(page.locator("#windows .cli-downloads")).to_contain_text("CLI")
            expect(page.locator("#windows .cli-downloads")).to_contain_text(
                "source_3.9.66"
            )
            page.locator("#windows .advanced-downloads > summary").click()
            page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
            page.screenshot(
                path="/tmp/porn-fetch-downloads-desktop.png", full_page=True
            )
            page.locator('[data-platform="android"]').click()
            expect(page.locator("#android .primary-cta")).to_have_attribute(
                "href", "/downloads/3.9.66/PornFetch_android_GUI_arm64.apk"
            )
            expect(page.locator(".primary-cta:visible")).to_have_count(1)
            page.locator('[data-platform="ios"]').click()
            expect(page.locator("#ios .ios-warning")).to_contain_text(
                "xz-kitty Python build"
            )
            expect(page.locator(".primary-cta:visible")).to_have_count(0)
            detected = context.new_page()
            detected.add_init_script("""Object.defineProperty(navigator, 'userAgentData', {
                value: { platform: 'Windows', getHighEntropyValues: () =>
                    Promise.resolve({architecture: 'x86', bitness: '64'}) }
            });""")
            detected.goto(origin + "/download")
            expect(detected.locator("#windows")).to_be_visible()
            expect(detected.locator("#windows .primary-cta")).to_have_attribute(
                "href", "/downloads/3.9.66/PornFetch_windows_GUI_x64.zip"
            )
            expect(detected.locator("#windows .package-choice")).to_be_hidden()
            detected.locator("#windows .change-device").click()
            detected.locator("#windows .primary-package").select_option(
                "/downloads/3.9.66/PornFetch_windows_GUI_arm64.zip"
            )
            expect(detected.locator("#windows .primary-cta")).to_have_attribute(
                "href", "/downloads/3.9.66/PornFetch_windows_GUI_arm64.zip"
            )
            detected.locator('[data-platform="macos"]').click()
            expect(detected.locator("#macos .primary-cta")).to_be_hidden()
            expect(detected.locator("#macos .package-choice")).to_be_visible()
            detected.locator("#macos .advanced-downloads > summary").click()
            expect(
                detected.locator("#macos .download-channels a").last
            ).to_have_attribute("href", "/download/macos?channel=beta")
            detected.close()
            for width in (375, 768, 1440):
                page.set_viewport_size({"width": width, "height": 900})
                for path in (
                    "/",
                    "/download",
                    "/download/windows",
                    "/download/linux",
                    "/download/macos",
                    "/download/android",
                    "/download/ios",
                    "/download/cli",
                    "/releases",
                    "/releases/3.9.66",
                    "/help",
                    "/about",
                ):
                    page.goto(origin + path)
                    if path == "/":
                        expect(
                            page.locator(".platform-list .platform-icon")
                        ).to_have_count(5)
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= innerWidth"
                    ), (width, path)
                    assert page.locator("#main-content").evaluate(
                        "el => el.scrollWidth <= el.clientWidth"
                    ), (width, path)
                    expect(page.locator("#age-overlay")).to_have_count(0)
                    if width == 375 and path in ("/download", "/download/ios"):
                        page.screenshot(
                            path="/tmp/porn-fetch-"
                            + (
                                "downloads-mobile"
                                if path == "/download"
                                else "ios-mobile"
                            )
                            + ".png",
                            full_page=True,
                        )
                print(f"Downloads and product guides fit {width}px.", flush=True)
            page.goto(origin + "/download?channel=stable")
            expect(page.locator(".package-row")).to_have_count(0)
            page.goto(origin + "/download?channel=beta")
            expect(page.locator(".package-row")).not_to_have_count(0)
            page.goto(origin + "/porn_fetch")
            expect(page.locator("#age-overlay")).to_be_visible()
            no_js = browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=False,
                viewport={"width": 375, "height": 812},
            )
            no_js.route(
                "**/*",
                lambda route: (
                    route.continue_()
                    if route.request.url.startswith(origin)
                    else route.abort()
                ),
            )
            fallback = no_js.new_page()
            fallback.goto(origin + "/download")
            fallback.locator(".site-menu > summary").click()
            fallback.locator('[data-platform="android"]').click()
            fallback.locator(".site-menu > summary").click()
            expect(fallback.locator("#android .primary-cta")).to_be_visible()
            fallback.locator("#android .advanced-downloads > summary").click()
            expect(fallback.locator("#android .package-download")).to_have_count(5)
            expect(fallback.locator("#android .package-download").first).to_be_visible()
            no_js.close()
            assert not failures, failures
            browser.close()
        print(
            f"{browser_name}: synthetic CI publisher, verified downloads, platform selection, experimental installers, no-JavaScript access, local guides and purchase age gate passed"
        )
    finally:
        server.shutdown()
        worker.join(timeout=5)
        fixture.tearDown()
        fixture.doCleanups()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", default="chromium")
    run(parser.parse_args().browser)
