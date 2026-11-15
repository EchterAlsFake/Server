"""Build responsive delivery copies of the maintainer's real phone screenshots.

uv run --with pillow python scripts/build_guide_images.py /path/to/screenshots
The original files stay untouched. No synthetic UI or download result is added.
"""

import argparse
from pathlib import Path

from PIL import Image

SOURCES = {
    "ios": ("IMG_0004.PNG", "IMG_0006.PNG", "IMG_0007.PNG", "IMG_0008.PNG"),
    "android": (
        "Screenshot_2026-11-15-21-26-30-647_to.pornfetch.app.jpg",
        "Screenshot_2026-11-15-21-26-41-463_to.pornfetch.app.jpg",
        "Screenshot_2026-11-15-21-26-49-155_to.pornfetch.app.jpg",
        "Screenshot_2026-11-15-21-27-00-325_to.pornfetch.app.jpg",
    ),
}


def build(source_dir):
    output = Path(__file__).resolve().parents[1] / "static" / "media" / "web"
    output.mkdir(exist_ok=True)
    for platform, files in SOURCES.items():
        for stage, filename in zip(("start", "add", "ready", "downloading"), files):
            with Image.open(source_dir / filename) as original:
                for width in (360, 720):
                    height = round(original.height * width / original.width)
                    image = original.convert("RGB").resize((width, height), Image.Resampling.LANCZOS)
                    image.save(output / f"guide-{platform}-{stage}-3.9.1-{width}.webp", quality=85, method=6)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir", type=Path)
    build(parser.parse_args().source_dir)
