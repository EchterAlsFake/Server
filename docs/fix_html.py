import re

def fix_html():
    with open("content/xvideos.html", "r", encoding="utf-8") as f:
        text = f.read()

    # Pattern to fix the whitespace in pre blocks
    pattern = re.compile(r'<pre>\s*(<div class="code-header">.*?</div>)\s*<code>(.*?)</code>\s*</pre>', re.DOTALL)
    
    def repl(m):
        header = m.group(1)
        code = m.group(2)
        # code currently has a leading newline because of the format
        if code.startswith('\n'):
            code = code[1:]
        return f'<div class="code-window">\n        {header}\n<pre><code>{code}</code></pre>\n    </div>'

    new_text = pattern.sub(repl, text)

    top_content = """
<!-- ================================================================
     DISCLAIMER & FEATURES
     ================================================================ -->
<div class="section" id="intro-section">
    <div class="info-box warning" style="border-color: #ef4444; background: rgba(239, 68, 68, 0.08); color: #fca5a5;">
        <div class="info-box-title" style="color: #ef4444; font-size: 14px;">⚠️ Legal Disclaimer</div>
        This tool is an unofficial, independent project and is not affiliated with, endorsed by, or sponsored by the target website. This software is provided "as is" for educational and personal purposes only. The developer assumes no responsibility for any consequences arising from the use of this tool, including but not limited to account suspension, IP blocking, or any violation of the target website's Terms of Service. Users are solely responsible for ensuring their use complies with all applicable laws and policies. Use at your own risk.
    </div>

    <div class="info-box success" style="margin-top: 24px;">
        <div class="info-box-title" style="font-size: 14px;">💚 Support & Commercial Licensing</div>
        If you find this project helpful, please consider donating to support its continued development! <br><br>
        For extended features, enterprise integrations, or custom commercial licensing, please contact 
        <a href="mailto:EchterAlsFakeBS@proton.me" style="color: #4ade80; font-weight: 600; text-decoration: underline;">EchterAlsFakeBS@proton.me</a>.
    </div>

    <h3 style="margin-top: 32px; font-size: 22px;">✨ Features Overview</h3>
    <ul class="param-list" style="margin-top: 16px;">
        <li class="param-item" style="padding: 10px 0;"><span style="font-size:18px; margin-right:8px;">⚡</span> <strong style="color: var(--text-primary); margin-right: 6px;">Fully Asynchronous</strong> — High-performance scraping and downloading via <code>asyncio</code> and <code>curl_cffi</code>.</li>
        <li class="param-item" style="padding: 10px 0;"><span style="font-size:18px; margin-right:8px;">🛡️</span> <strong style="color: var(--text-primary); margin-right: 6px;">Bot Protection Bypass</strong> — Mimics real browser TLS fingerprints and automatically solves JS math challenges.</li>
        <li class="param-item" style="padding: 10px 0;"><span style="font-size:18px; margin-right:8px;">📹</span> <strong style="color: var(--text-primary); margin-right: 6px;">HLS Downloader</strong> — Built-in multi-threaded downloader with TS to MP4 remuxing and resume capabilities.</li>
        <li class="param-item" style="padding: 10px 0;"><span style="font-size:18px; margin-right:8px;">🔍</span> <strong style="color: var(--text-primary); margin-right: 6px;">Advanced Filtering</strong> — Search by duration, date, quality, and relevance just like on the main site.</li>
    </ul>
</div>
"""

    new_text = new_text.replace("<!-- BEGIN:MAIN_CONTENT -->", "<!-- BEGIN:MAIN_CONTENT -->\n" + top_content)

    with open("content/xvideos.html", "w", encoding="utf-8") as f:
        f.write(new_text)

if __name__ == "__main__":
    fix_html()
