import os
import re
import shutil
from pathlib import Path

# Custom styling definitions for each library (logo letter, custom brand gradient)
BRAND_DATA = {
    "eaf_base_api": {
        "logo_text": "EAF",
        "gradient": "linear-gradient(135deg, #8b5cf6, #c4b5fd, #fbbf24)",
        "display_name": "Base API Engine"
    },
    "beeg": {
        "logo_text": "B",
        "gradient": "linear-gradient(135deg, #fbbf24, #d97706)",
        "display_name": "Beeg API"
    },
    "eporner": {
        "logo_text": "E",
        "gradient": "linear-gradient(135deg, #0ea5e9, #0284c7)",
        "display_name": "EPorner API"
    },
    "hqporner": {
        "logo_text": "H",
        "gradient": "linear-gradient(135deg, #6366f1, #ec4899)",
        "display_name": "HQPorner API"
    },
    "missav": {
        "logo_text": "M",
        "gradient": "linear-gradient(135deg, #ec4899, #f43f5e)",
        "display_name": "MissAV API"
    },
    "pornhub": {
        "logo_text": "P",
        "gradient": "linear-gradient(135deg, #f59e0b, #000000)",
        "display_name": "Pornhub API"
    },
    "porntrex": {
        "logo_text": "P",
        "gradient": "linear-gradient(135deg, #10b981, #047857)",
        "display_name": "Porntrex API"
    },
    "redtube": {
        "logo_text": "R",
        "gradient": "linear-gradient(135deg, #ef4444, #000000)",
        "display_name": "Redtube API"
    },
    "spankbang": {
        "logo_text": "S",
        "gradient": "linear-gradient(135deg, #f43f5e, #be123c)",
        "display_name": "Spankbang API"
    },
    "thumbzilla": {
        "logo_text": "T",
        "gradient": "linear-gradient(135deg, #eab308, #854d0e)",
        "display_name": "Thumbzilla API"
    },
    "tube8": {
        "logo_text": "T",
        "gradient": "linear-gradient(135deg, #fbbf24, #d97706)",
        "display_name": "Tube8 API"
    },
    "xfreehd": {
        "logo_text": "X",
        "gradient": "linear-gradient(135deg, #3b82f6, #1d4ed8)",
        "display_name": "XFreeHD API"
    },
    "xhamster": {
        "logo_text": "X",
        "gradient": "linear-gradient(135deg, #f97316, #c2410c)",
        "display_name": "XHamster API"
    },
    "xnxx": {
        "logo_text": "X",
        "gradient": "linear-gradient(135deg, #2563eb, #dc2626)",
        "display_name": "XNXX API"
    },
    "xvideos": {
        "logo_text": "X",
        "gradient": "linear-gradient(135deg, #dc2626, #fbbf24)",
        "display_name": "XVideos API"
    },
    "youporn": {
        "logo_text": "Y",
        "gradient": "linear-gradient(135deg, #ec4899, #be185d)",
        "display_name": "YouPorn API"
    }
}

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
            f.write(final_html)
            
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
        brand = BRAND_DATA.get(api_name, {
            "logo_text": api_name[0].upper() if api_name else "A",
            "gradient": "linear-gradient(135deg, #8b5cf6, #a78bfa)",
            "display_name": api["title"]
        })
        
        logo_text = brand["logo_text"]
        gradient = brand["gradient"]
        title = api["title"]
        version = api["version"]
        subtitle = api["subtitle"]
        pypi_package = api["pypi_package"]
        github_url = api["github_url"]
        
        # Escape string values for safety in data attributes
        clean_title = title.replace('"', '&quot;')
        clean_package = pypi_package.replace('"', '&quot;')
        clean_desc = subtitle.replace('"', '&quot;')
        card_type = "core" if api_name == "eaf_base_api" else "scraper"
        
        if is_featured:
            return f"""
                    <div class="api-card featured-card" data-title="{clean_title}" data-package="{clean_package}" data-desc="{clean_desc}" data-type="{card_type}">
                        <div class="card-header" style="margin-bottom: 0;">
                            <div class="card-logo" style="background: {gradient}; width: 64px; height: 64px; font-size: 28px;">{logo_text}</div>
                            <div class="card-title-group">
                                <span class="card-title" style="font-size: 26px;">{title}</span>
                                <span class="card-version">v{version}</span>
                            </div>
                        </div>
                        <div style="display: flex; flex-direction: column; justify-content: space-between; height: 100%; gap: 16px;">
                            <p class="card-desc" style="margin-bottom: 0; font-size: 17px;">{subtitle}</p>
                            <div style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap; margin-top: 8px;">
                                <div class="card-install" onclick="copyInstall(this)" title="Click to copy" style="margin-bottom: 0; flex-grow: 1; max-width: 400px;">
                                    <span class="prefix">$</span> pip install {pypi_package}
                                    <span class="copy-icon">📋</span>
                                </div>
                                <div class="card-actions" style="flex-shrink: 0;">
                                    <a href="./{api_name}/" class="card-btn card-btn-primary" style="padding: 10px 24px;">Open Documentation</a>
                                    <a href="{github_url}" class="card-btn card-btn-secondary" target="_blank" rel="noopener" style="padding: 10px 20px;">GitHub</a>
                                </div>
                            </div>
                        </div>
                    </div>"""
        else:
            return f"""
                    <div class="api-card" data-title="{clean_title}" data-package="{clean_package}" data-desc="{clean_desc}" data-type="{card_type}">
                        <div>
                            <div class="card-header">
                                <div class="card-logo" style="background: {gradient}">{logo_text}</div>
                                <div class="card-title-group">
                                    <span class="card-title">{title}</span>
                                    <span class="card-version">v{version}</span>
                                </div>
                            </div>
                            <p class="card-desc">{subtitle}</p>
                        </div>
                        <div>
                            <div class="card-install" onclick="copyInstall(this)" title="Click to copy">
                                <span class="prefix">$</span> pip install {pypi_package}
                                <span class="copy-icon">📋</span>
                            </div>
                            <div class="card-actions">
                                <a href="./{api_name}/" class="card-btn card-btn-primary">Open Documentation</a>
                                <a href="{github_url}" class="card-btn card-btn-secondary" target="_blank" rel="noopener">GitHub</a>
                            </div>
                        </div>
                    </div>"""

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
        f.write(index_html)
        
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
