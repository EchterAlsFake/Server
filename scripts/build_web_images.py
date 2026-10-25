"""Build smaller delivery copies of existing artwork; originals stay available.

Run with: uv run --with pillow python scripts/build_web_images.py
Pillow is build tooling only, not an application dependency.
"""

from pathlib import Path

from PIL import Image

MEDIA = Path(__file__).resolve().parents[1] / "static" / "media"


def build():
    output = MEDIA / "web"
    output.mkdir(exist_ok=True)
    with Image.open(MEDIA / "porn-fetch-logo.png") as original:
        logo = original.resize((384, 216), Image.Resampling.LANCZOS)
        logo.save(output / "logo.webp", lossless=True, method=6)
    with Image.open(MEDIA / "promo-poster.jpg") as original:
        poster = original.resize((1280, 720), Image.Resampling.LANCZOS)
        poster.save(output / "promo-poster.webp", quality=88, method=6)
    for name in ("filters", "accounts", "privacy"):
        with Image.open(MEDIA / f"{name}.png") as original:
            for width in (480, 960):
                height = round(original.height * width / original.width)
                image = original.resize((width, height), Image.Resampling.LANCZOS)
                image.save(output / f"{name}-{width}.webp", quality=90, method=6)


if __name__ == "__main__":
    build()
