import html
import re
import shutil
from pathlib import Path

BRAND_MARKS = {
    "eaf_base_api": "EAF",
    "beeg": "B",
    "eporner": "E",
    "hqporner": "H",
    "missav": "M",
    "pornhub": "P",
    "porntrex": "P",
    "redtube": "R",
    "spankbang": "S",
    "thumbzilla": "T",
    "tube8": "T",
    "xfreehd": "X",
    "xhamster": "X",
    "xnxx": "X",
    "xvideos": "X",
    "youporn": "Y",
}


def clean_html_document(content: str) -> str:
    """Keep generated pages deterministic and free of trailing whitespace."""
    return "\n".join(line.rstrip() for line in content.splitlines()) + "\n"


def build_docs():
    base_dir = Path(__file__).parent
    template_path = base_dir / "template.html"
    content_dir = base_dir / "content"
    dist_dir = base_dir / "dist"

    if not template_path.exists():
        print(f"Error: Template not found at {template_path}")
        return

    with open(template_path, "r", encoding="utf-8") as f:
        template_html = f.read()

    if not content_dir.exists():
        print(f"Error: Content directory not found at {content_dir}")
        return

    # Clean dist dir
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir()

    assets_dir = base_dir / "assets"
    if assets_dir.exists():
        shutil.copytree(assets_dir, dist_dir / "assets")

    # Regexes for parsing content files
    slot_var_re = re.compile(r"<!--\s*SLOT:([A-Z_]+)\s*=\s*(.*?)\s*-->")
    slot_block_start_re = re.compile(r"<!--\s*BEGIN:([A-Z_]+)\s*-->")
    slot_block_end_re = re.compile(r"<!--\s*END:([A-Z_]+)\s*-->")

    apis_metadata = []

    for content_file in content_dir.glob("*.html"):
        api_name = content_file.stem
        print(f"Building docs for: {api_name}")

        with open(content_file, "r", encoding="utf-8") as f:
            content = f.read()

        slots = {}

        # 1. Parse simple single-line slots
        for match in slot_var_re.finditer(content):
            slot_name, slot_value = match.groups()
            slots[slot_name] = slot_value.strip()

        # 2. Parse multi-line blocks
        lines = content.split('\n')
        current_block_name = None
        current_block_content = []

        for line in lines:
            start_match = slot_block_start_re.search(line)
            if start_match:
                current_block_name = start_match.group(1)
                current_block_content = []
                continue

            end_match = slot_block_end_re.search(line)
            if end_match and current_block_name == end_match.group(1):
                slots[current_block_name] = '\n'.join(current_block_content)
                current_block_name = None
                continue

            if current_block_name is not None:
                current_block_content.append(line)

        # Collect metadata for index portal
        apis_metadata.append({
            "api_name": api_name,
            "title": slots.get("TITLE", slots.get("HERO_TITLE", api_name)),
            "subtitle": slots.get("HERO_SUBTITLE", ""),
            "version": slots.get("VERSION", "1.0"),
            "github_url": slots.get("GITHUB_URL", ""),
            "pypi_package": slots.get("PYPI_PACKAGE", "")
        })

        # 3. Inject into template
        final_html = template_html
        for slot_name, slot_value in slots.items():
            # Replace placeholder in template, e.g., <!-- SLOT:TITLE -->
            placeholder = f"<!-- SLOT:{slot_name} -->"
            final_html = final_html.replace(placeholder, slot_value)

        # 4. Save to dist/api_name/index.html
        api_dist_dir = dist_dir / api_name
        api_dist_dir.mkdir(parents=True, exist_ok=True)
        out_path = api_dist_dir / "index.html"
        
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(clean_html_document(final_html))
            
        print(f"✓ Created {out_path.relative_to(base_dir)}")

    # 5. Build the central portal index page (dist/index.html)
    print("Building central index hub portal...")
    
    # Separate core API and scraper APIs
    scrapers = []
    core_api = None
    for api in apis_metadata:
        if api["api_name"] == "eaf_base_api":
            core_api = api
        else:
            scrapers.append(api)
            
    # Sort scrapers alphabetically by title
    scrapers.sort(key=lambda x: x["title"].lower())
    
    # Load index template
    index_template_path = base_dir / "index_template.html"
    if not index_template_path.exists():
        print(f"Error: Index template not found at {index_template_path}")
        return
        
    with open(index_template_path, "r", encoding="utf-8") as f:
        index_html = f.read()

    # Function to generate card HTML
    def make_card_html(api, is_featured=False):
        api_name = api["api_name"]
        logo_text = html.escape(BRAND_MARKS.get(api_name, api_name[:1].upper() or "A"))
        title = html.escape(api["title"])
        version = html.escape(api["version"])
        subtitle = html.escape(api["subtitle"])
        pypi_package = html.escape(api["pypi_package"])
        github_url = html.escape(api["github_url"], quote=True)
        clean_title = html.escape(api["title"], quote=True)
        clean_package = html.escape(api["pypi_package"], quote=True)
        clean_desc = html.escape(api["subtitle"], quote=True)
        card_type = "core" if api_name == "eaf_base_api" else "scraper"
        featured_class = " featured-card" if is_featured else ""
        return f"""
                    <article class="api-card{featured_class}" data-title="{clean_title}" data-package="{clean_package}" data-desc="{clean_desc}" data-type="{card_type}">
                        <header class="card-header">
                            <span class="card-logo" aria-hidden="true">{logo_text}</span>
                            <div class="card-title-group">
                                <h3 class="card-title"><a href="./{api_name}/">{title}</a></h3>
                                <span class="card-version">v{version}</span>
                            </div>
                        </header>
                        <p class="card-desc">{subtitle}</p>
                        <footer class="card-footer">
                            <button class="card-install" type="button" onclick="copyInstall(this)" title="Copy install command">
                                <span class="prefix" aria-hidden="true">$</span>
                                <code>pip install {pypi_package}</code>
                                <span class="copy-icon" aria-hidden="true">Copy</span>
                            </button>
                            <div class="card-actions">
                                <a href="./{api_name}/" class="card-btn card-btn-primary">Read docs</a>
                                <a href="{github_url}" class="card-btn card-btn-secondary" target="_blank" rel="noopener noreferrer">GitHub <span aria-hidden="true">↗</span></a>
                            </div>
                        </footer>
                    </article>"""

    # Generate the cards HTML blocks
    core_card_html = ""
    if core_api:
        core_card_html = make_card_html(core_api, is_featured=True)
        
    scraper_cards_html = "\n".join(make_card_html(s) for s in scrapers)
    
    # Inject into the index template HTML
    index_html = index_html.replace("<!-- SLOT:CORE_API_CARD -->", core_card_html)
    index_html = index_html.replace("<!-- SLOT:SCRAPER_CARDS -->", scraper_cards_html)
    
    # Save the index to dist/index.html
    index_out_path = dist_dir / "index.html"
    with open(index_out_path, "w", encoding="utf-8") as f:
        f.write(clean_html_document(index_html))
        
    print(f"✓ Created central index portal at {index_out_path.relative_to(base_dir)}")

    # 6. Copy AI Transparency page
    transparency_src = base_dir / "transparency.html"
    if transparency_src.exists():
        transparency_dist_dir = dist_dir / "transparency"
        transparency_dist_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(transparency_src, transparency_dist_dir / "index.html")
        print(f"✓ Copied AI Transparency statement to {transparency_dist_dir / 'index.html'}")


if __name__ == "__main__":
    build_docs()
    print("Done!")
