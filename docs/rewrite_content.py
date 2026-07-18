import os

def rewrite_docs():
    donation_and_disclaimer = """
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
        
        <div style="margin: 16px 0;">
            <a href="https://nowpayments.io/donation/EchterAlsFake" class="btn-donate" target="_blank" rel="noreferrer noopener" style="border-bottom: none;">
                <span style="font-size: 20px;">💎</span> Donate Crypto
            </a>
        </div>
        
        <strong>Other Options:</strong><br>
        • <a href="https://paypal.me/EchterAlsFake" style="color: #4ade80; text-decoration: underline;" target="_blank">PayPal</a><br>
        • <a href="https://ko-fi.com/EchterAlsFake" style="color: #4ade80; text-decoration: underline;" target="_blank">Ko-Fi</a><br><br>
        
        For extended features, enterprise integrations, or custom commercial licensing, please contact 
        <a href="mailto:EchterAlsFakeBS@proton.me" style="color: #4ade80; font-weight: 600; text-decoration: underline;">EchterAlsFakeBS@proton.me</a>.
    </div>
"""

    xvideos_features = """
    <h3 style="margin-top: 32px; font-size: 22px;">✨ Features Overview</h3>
    <ul class="param-list" style="margin-top: 16px;">
        <li class="param-item" style="padding: 10px 0;"><span style="font-size:18px; margin-right:8px;">⚡</span> <strong style="color: var(--text-primary); margin-right: 6px;">Fully Asynchronous</strong> — High-performance scraping and downloading via <code>asyncio</code> and <code>curl_cffi</code>.</li>
        <li class="param-item" style="padding: 10px 0;"><span style="font-size:18px; margin-right:8px;">🛡️</span> <strong style="color: var(--text-primary); margin-right: 6px;">Bot Protection Bypass</strong> — Mimics real browser TLS fingerprints and automatically solves JS math challenges.</li>
        <li class="param-item" style="padding: 10px 0;"><span style="font-size:18px; margin-right:8px;">📹</span> <strong style="color: var(--text-primary); margin-right: 6px;">HLS Downloader</strong> — Built-in multi-threaded downloader with TS to MP4 remuxing and resume capabilities.</li>
        <li class="param-item" style="padding: 10px 0;"><span style="font-size:18px; margin-right:8px;">🔍</span> <strong style="color: var(--text-primary); margin-right: 6px;">Advanced Filtering</strong> — Search by duration, date, quality, and relevance just like on the main site.</li>
    </ul>
</div>
"""

    with open("content/xvideos.html", "w", encoding="utf-8") as f:
        f.write("""<!-- ============================================================
     XVideos API Documentation — Content File
     ============================================================ -->

<!-- META -->
<!-- SLOT:TITLE = XVideos API -->
<!-- SLOT:HERO_TITLE = XVideos API -->
<!-- SLOT:HERO_SUBTITLE = A fully asynchronous Python API wrapper and scraper for XVideos. Fetch videos, metadata, pornstar profiles, channels, playlists, and download content — all powered by the eaf_base_api networking engine. -->
<!-- SLOT:VERSION = 2.3 -->
<!-- SLOT:GITHUB_URL = https://github.com/EchterAlsFake/unofficial-api-for-xvideos -->
<!-- SLOT:PYPI_PACKAGE = xvideos_api -->

<!-- SIDEBAR_NAV -->
<!-- BEGIN:SIDEBAR_NAV -->
<div class="nav-section-title">Getting Started</div>
<a href="#installation" class="nav-link">Installation</a>
<a href="#quickstart" class="nav-link">Quick Start</a>
<a href="#configuration" class="nav-link">Configuration</a>

<div class="nav-section-title">Core Objects</div>
<a href="#client" class="nav-link">Client</a>
<a href="#video" class="nav-link">Video</a>
<a href="#channel" class="nav-link">Channel</a>
<a href="#pornstar" class="nav-link">Pornstar</a>
<a href="#account" class="nav-link">Account</a>

<div class="nav-section-title">Features</div>
<a href="#searching" class="nav-link">Search & Filtering</a>
<a href="#downloading" class="nav-link">Downloading</a>
<a href="#pagination" class="nav-link">Pagination & Iterators</a>
<a href="#error-handling" class="nav-link">Error Handling</a>

<div class="nav-section-title">Extras</div>
<a href="#cli" class="nav-link">CLI Usage</a>
<a href="#platforms" class="nav-link">Platforms</a>
<!-- END:SIDEBAR_NAV -->

<!-- MAIN_CONTENT -->
<!-- BEGIN:MAIN_CONTENT -->
""" + donation_and_disclaimer + xvideos_features + """

<div class="section" id="installation-section">
    <span class="section-anchor" id="installation"></span>
    <h2><span class="section-icon">📦</span> Installation</h2>

    <p>Install from PyPI using pip:</p>
    <div class="code-window">
        <div class="code-header"><span>bash</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code>pip install xvideos_api</code></pre>
    </div>

    <p>For <strong>TS → MP4 remuxing</strong> support (recommended), install with the optional <code>av</code> dependency:</p>
    <div class="code-window">
        <div class="code-header"><span>bash</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code>pip install xvideos_api[av]</code></pre>
    </div>

    <div class="info-box note">
        <div class="info-box-title">Note</div>
        Requires <strong>Python ≥ 3.12</strong>. The underlying networking library <code>eaf_base_api</code> is installed automatically as a dependency.
    </div>
</div>

<div class="section" id="quickstart-section">
    <span class="section-anchor" id="quickstart"></span>
    <h2><span class="section-icon">🚀</span> Quick Start</h2>

    <p>Every method in this API is <strong>asynchronous</strong>. You need to run your code inside an <code>async</code> function:</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">import</span> asyncio
<span class="token-keyword">from</span> xvideos_api <span class="token-keyword">import</span> Client

<span class="token-keyword">async def</span> <span class="token-function">main</span>():
    client = <span class="token-class">Client</span>()

    <span class="token-comment"># Fetch a video</span>
    video = <span class="token-keyword">await</span> client.get_video(<span class="token-string">"https://www.xvideos.com/video..."</span>)

    <span class="token-comment"># Access metadata</span>
    <span class="token-builtin">print</span>(video.title)
    <span class="token-builtin">print</span>(video.views)
    <span class="token-builtin">print</span>(video.likes)

    <span class="token-comment"># Download the video</span>
    <span class="token-keyword">from</span> xvideos_api <span class="token-keyword">import</span> DownloadConfigHLS
    config = <span class="token-class">DownloadConfigHLS</span>(quality=<span class="token-string">"best"</span>, path=<span class="token-string">"./downloads"</span>)
    <span class="token-keyword">await</span> video.download(configuration=config)

asyncio.run(main())</code></pre>
    </div>
</div>

<div class="section" id="configuration-section">
    <span class="section-anchor" id="configuration"></span>
    <h2><span class="section-icon">⚙️</span> Configuration</h2>

    <p>The entire API relies on <code>eaf_base_api</code> for its networking. You can configure global settings (proxies, timeouts, etc.) via the singleton <code>config</code>, or pass a custom <code>BaseCore</code> into the Client.</p>
    <p>Please refer to the <a href="../eaf_base_api/index.html" style="font-weight: 600;">eaf_base_api Documentation</a> for the complete reference on how to set up <code>RuntimeConfig</code> and properly integrate it with this API.</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">from</span> base_api <span class="token-keyword">import</span> BaseCore
<span class="token-keyword">from</span> base_api.modules.config <span class="token-keyword">import</span> RuntimeConfig
<span class="token-keyword">from</span> xvideos_api <span class="token-keyword">import</span> Client

my_config = <span class="token-class">RuntimeConfig</span>()
my_config.proxies = {<span class="token-string">"https"</span>: <span class="token-string">"socks5://127.0.0.1:9050"</span>}

core = <span class="token-class">BaseCore</span>(configuration=my_config)
client = <span class="token-class">Client</span>(core=core)</code></pre>
    </div>
</div>

<hr>

<div class="section" id="client-section">
    <span class="section-anchor" id="client"></span>
    <h2><span class="section-icon">🔌</span> Client</h2>
    <p>The <code>Client</code> class is your <strong>entry point</strong> for all interactions. It manages the session and provides methods to fetch videos, search, and access channels/pornstars.</p>

    <h3>Methods</h3>

    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">await client.get_video(url: str, load_html: bool = True) → Video</div>
        <div class="method-desc">Fetches a video page and returns a populated <code>Video</code> object.</div>
        <ul class="param-list">
            <li class="param-item"><span class="param-name">url</span> <span class="param-type">str</span> <span class="param-desc">— The full XVideos video URL</span></li>
            <li class="param-item"><span class="param-name">load_html</span> <span class="param-type">bool</span> <span class="param-desc">— If <code>True</code> (default), fetches and parses the HTML page for full metadata</span></li>
        </ul>
        <span class="returns-tag">→ Video</span>
    </div>

    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">async for result in client.search(query, sorting_sort=Sort.Sort_relevance, sorting_date=SortDate.Sort_all, sorting_time=SortVideoTime.Sort_all, sort_quality=SortQuality.Sort_all, pages="all", ...) → AsyncGenerator[ScrapeResult]</div>
        <div class="method-desc">Searches for videos and yields results as an async generator. See <a href="#searching">Search &amp; Filtering</a> for complete details.</div>
        <ul class="param-list">
            <li class="param-item"><span class="param-name">query</span> <span class="param-type">str</span> <span class="param-desc">— Search terms</span></li>
            <li class="param-item"><span class="param-name">pages</span> <span class="param-type">int | "all"</span> <span class="param-desc">— Number of result pages or <code>"all"</code> for automatic iteration</span></li>
            <li class="param-item"><span class="param-name">load_html</span> <span class="param-type">bool</span> <span class="param-desc">— Whether to fetch full HTML for each result video (default: <code>False</code>)</span></li>
            <li class="param-item"><span class="param-name">keep_original_order</span> <span class="param-type">bool</span> <span class="param-desc">— If <code>True</code>, yields videos in page order instead of arrival order</span></li>
        </ul>
        <span class="returns-tag">→ AsyncGenerator[ScrapeResult]</span>
    </div>

    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">async for result in client.get_playlist(url, pages=2, ...) → AsyncGenerator[ScrapeResult]</div>
        <div class="method-desc">Fetches videos from a playlist page by page.</div>
        <ul class="param-list">
            <li class="param-item"><span class="param-name">url</span> <span class="param-type">str</span> <span class="param-desc">— The playlist URL</span></li>
            <li class="param-item"><span class="param-name">pages</span> <span class="param-type">int</span> <span class="param-desc">— Number of pages to scrape</span></li>
        </ul>
        <span class="returns-tag">→ AsyncGenerator[ScrapeResult]</span>
    </div>

    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">await client.get_pornstar(url: str, load_html: bool = True) → Pornstar</div>
        <div class="method-desc">Fetches a pornstar profile.</div>
    </div>

    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">await client.get_channel(url: str, load_html: bool = True) → Channel</div>
        <div class="method-desc">Fetches a channel profile.</div>
    </div>

    <div class="method-card">
        <div class="method-signature">client.get_account(cookies: dict | None = None) → Account</div>
        <div class="method-desc">Creates an <code>Account</code> instance for authenticated actions. See <a href="#account">Account</a>.</div>
    </div>
</div>

<div class="section" id="video-section">
    <span class="section-anchor" id="video"></span>
    <h2><span class="section-icon">🎬</span> Video</h2>
    <p><span class="tag tag-dataclass">dataclass</span> Inherits from <code>BaseMedia</code>. Represents a single video with all its metadata.</p>

    <h3>Attributes</h3>
    <div class="table-wrapper">
        <table>
            <thead>
                <tr><th>Attribute</th><th>Type</th><th>Description</th></tr>
            </thead>
            <tbody>
                <tr><td><code>url</code></td><td><code>str</code></td><td>The video page URL</td></tr>
                <tr><td><code>title</code></td><td><code>str | None</code></td><td>Video title</td></tr>
                <tr><td><code>description</code></td><td><code>str | None</code></td><td>Video description</td></tr>
                <tr><td><code>thumbnail_url</code></td><td><code>str | None</code></td><td>Thumbnail image URL</td></tr>
                <tr><td><code>preview_video_url</code></td><td><code>str | None</code></td><td>Short preview clip URL</td></tr>
                <tr><td><code>publish_date</code></td><td><code>str | None</code></td><td>Upload date</td></tr>
                <tr><td><code>content_url</code></td><td><code>str | None</code></td><td>Direct content URL</td></tr>
                <tr><td><code>tags</code></td><td><code>list | None</code></td><td>List of tag strings</td></tr>
                <tr><td><code>views</code></td><td><code>str | None</code></td><td>View count</td></tr>
                <tr><td><code>likes</code></td><td><code>str | None</code></td><td>Like count</td></tr>
                <tr><td><code>dislikes</code></td><td><code>str | None</code></td><td>Dislike count</td></tr>
                <tr><td><code>rating_votes</code></td><td><code>str | None</code></td><td>Total rating votes</td></tr>
                <tr><td><code>comment_count</code></td><td><code>str | None</code></td><td>Comment count</td></tr>
                <tr><td><code>author_link</code></td><td><code>str | None</code></td><td>Uploader profile URL</td></tr>
                <tr><td><code>length</code></td><td><code>str | None</code></td><td>Video duration</td></tr>
                <tr><td><code>pornstars_urls</code></td><td><code>list | None</code></td><td>URLs of pornstars featured</td></tr>
                <tr><td><code>embed_url</code></td><td><code>str | None</code></td><td>Embeddable iframe URL</td></tr>
                <tr><td><code>m3u8_base_url</code></td><td><code>str | None</code></td><td>HLS master playlist URL</td></tr>
                <tr><td><code>video_id</code></td><td><code>str | None</code></td><td>Internal video ID</td></tr>
            </tbody>
        </table>
    </div>

    <h3>Methods</h3>

    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">await video.download(configuration: DownloadConfigHLS) → bool | DownloadReport</div>
        <div class="method-desc">Downloads the video using the HLS threaded downloader. The video title is automatically appended to the output path unless <code>no_title=True</code>.</div>
        <ul class="param-list">
            <li class="param-item"><span class="param-name">configuration</span> <span class="param-type">DownloadConfigHLS</span> <span class="param-desc">— Download settings (quality, path, etc.). See <a href="#downloading">Downloading</a>.</span></li>
        </ul>
    </div>

    <div class="method-card">
        <span class="tag tag-property">property</span> <span class="tag tag-async">async</span>
        <div class="method-signature">await video.get_author → Channel | None</div>
        <div class="method-desc">Lazily loads and returns the uploader's <code>Channel</code> object.</div>
    </div>

    <div class="method-card">
        <span class="tag tag-property">property</span> <span class="tag tag-async">async</span>
        <div class="method-signature">async for star in video.get_pornstars → AsyncGenerator[Pornstar]</div>
        <div class="method-desc">Yields <code>Pornstar</code> objects for each featured performer.</div>
    </div>

    <div class="info-box tip">
        <div class="info-box-title">Tip — Lazy Loading</div>
        All objects inherit from <code>BaseMedia</code>. Accessing an attribute that hasn't been loaded yet will raise a <code>DataNotLoadedError</code> with a helpful message showing you which <code>load()</code> flags you need. By default, <code>client.get_video()</code> calls <code>load(html=True)</code> which populates all HTML-scraped attributes.
    </div>
</div>

<div class="section" id="channel-section">
    <span class="section-anchor" id="channel"></span>
    <h2><span class="section-icon">📺</span> Channel</h2>
    <p><span class="tag tag-dataclass">dataclass</span> Inherits from <code>BaseChannelPornstar</code> → <code>BaseMedia</code>. Represents a channel profile.</p>

    <h3>Attributes</h3>
    <div class="table-wrapper">
        <table>
            <thead>
                <tr><th>Attribute</th><th>Type</th><th>Description</th></tr>
            </thead>
            <tbody>
                <tr><td><code>url</code></td><td><code>str</code></td><td>Channel profile URL</td></tr>
                <tr><td><code>name</code></td><td><code>str | None</code></td><td>Channel name</td></tr>
                <tr><td><code>thumbnail_url</code></td><td><code>str | None</code></td><td>Profile picture URL</td></tr>
                <tr><td><code>total_videos</code></td><td><code>int | None</code></td><td>Number of uploaded videos</td></tr>
                <tr><td><code>total_pages</code></td><td><code>int | None</code></td><td>Calculated number of video pages</td></tr>
                <tr><td><code>profile_hits</code></td><td><code>str | None</code></td><td>Total profile views</td></tr>
                <tr><td><code>subscribers</code></td><td><code>str | None</code></td><td>Subscriber count</td></tr>
                <tr><td><code>total_videos_views</code></td><td><code>str | None</code></td><td>Total views across all videos</td></tr>
                <tr><td><code>signed_up</code></td><td><code>str | None</code></td><td>Registration date</td></tr>
                <tr><td><code>last_activity</code></td><td><code>str | None</code></td><td>Last activity date</td></tr>
                <tr><td><code>worked_for_with_links</code></td><td><code>list | None</code></td><td>Links to associated studios/channels</td></tr>
            </tbody>
        </table>
    </div>

    <h3>Methods</h3>
    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">async for result in channel.videos(pages=0, ...) → AsyncGenerator[ScrapeResult]</div>
        <div class="method-desc">Iterates over the channel's uploaded videos. Set <code>pages=0</code> (default) to fetch <em>all</em> pages.</div>
    </div>

    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">await channel.worked_for_with(load_html=True) → list[Channel]</div>
        <div class="method-desc">Returns a list of channels/studios this entity has worked for/with.</div>
    </div>
</div>

<div class="section" id="pornstar-section">
    <span class="section-anchor" id="pornstar"></span>
    <h2><span class="section-icon">⭐</span> Pornstar</h2>
    <p><span class="tag tag-dataclass">dataclass</span> Inherits from <code>BaseChannelPornstar</code>. Has all Channel attributes <strong>plus</strong>:</p>

    <div class="table-wrapper">
        <table>
            <thead><tr><th>Extra Attribute</th><th>Type</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>gender</code></td><td><code>str | None</code></td><td>Gender</td></tr>
                <tr><td><code>age</code></td><td><code>str | None</code></td><td>Age</td></tr>
                <tr><td><code>video_tags</code></td><td><code>str | None</code></td><td>Most common tags</td></tr>
            </tbody>
        </table>
    </div>

    <p>Inherits the same <code>videos()</code> and <code>worked_for_with()</code> methods from <code>BaseChannelPornstar</code>.</p>
</div>

<div class="section" id="account-section">
    <span class="section-anchor" id="account"></span>
    <h2><span class="section-icon">🔑</span> Account</h2>
    <p>Provides access to <strong>authenticated</strong> endpoints. Requires login cookies.</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-comment"># Provide cookies from your browser session</span>
my_cookies = {
    <span class="token-string">"session_token"</span>: <span class="token-string">"&lt;your_token&gt;"</span>,
    <span class="token-string">"session_token_auth"</span>: <span class="token-string">"&lt;your_auth_token&gt;"</span>,
}

account = client.get_account(cookies=my_cookies)

<span class="token-comment"># Get your liked videos</span>
<span class="token-keyword">async for</span> result <span class="token-keyword">in</span> account.get_liked_videos(pages=<span class="token-number">3</span>):
    <span class="token-keyword">if</span> result.is_success:
        <span class="token-builtin">print</span>(result.video.title)</code></pre>
    </div>

    <h3>Methods</h3>
    <p>All three methods share the same signature pattern:</p>

    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">async for result in account.get_liked_videos(pages=2, videos_concurrency=None, pages_concurrency=None, on_video_error=on_error, keep_original_order=False, load_html=False)</div>
    </div>
    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">async for result in account.get_recommended_videos(...)</div>
    </div>
    <div class="method-card">
        <span class="tag tag-async">async</span>
        <div class="method-signature">async for result in account.get_watch_later_videos(...)</div>
    </div>
</div>

<hr>

<div class="section" id="searching-section">
    <span class="section-anchor" id="searching"></span>
    <h2><span class="section-icon">🔍</span> Search & Filtering</h2>

    <p>Use the <code>client.search()</code> method with the sorting enums for powerful filtering:</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">from</span> xvideos_api.modules.sorting <span class="token-keyword">import</span> Sort, SortDate, SortVideoTime, SortQuality

<span class="token-keyword">async for</span> result <span class="token-keyword">in</span> client.search(
    query=<span class="token-string">"example search"</span>,
    sorting_sort=Sort.Sort_rating,
    sorting_date=SortDate.Sort_month,
    sorting_time=SortVideoTime.Sort_long,
    sort_quality=SortQuality.Sort_1080_plus,
    pages=<span class="token-number">5</span>,
    keep_original_order=<span class="token-keyword">True</span>,
):
    <span class="token-keyword">if</span> result.is_success:
        video = result.video
        <span class="token-builtin">print</span>(f<span class="token-string">"{video.title}"</span>)</code></pre>
    </div>

    <h3>Sorting Enums</h3>

    <h4>Sort (Relevance)</h4>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>Enum Value</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>Sort.Sort_relevance</code></td><td>Most relevant (default)</td></tr>
                <tr><td><code>Sort.Sort_upload_date</code></td><td>Newest first</td></tr>
                <tr><td><code>Sort.Sort_rating</code></td><td>Highest rated</td></tr>
                <tr><td><code>Sort.Sort_length</code></td><td>Longest first</td></tr>
                <tr><td><code>Sort.Sort_views</code></td><td>Most viewed</td></tr>
                <tr><td><code>Sort.Sort_random</code></td><td>Random order</td></tr>
            </tbody>
        </table>
    </div>

    <h4>SortDate (Time Period)</h4>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>Enum Value</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>SortDate.Sort_all</code></td><td>All time (default)</td></tr>
                <tr><td><code>SortDate.Sort_last_3_days</code></td><td>Last 3 days</td></tr>
                <tr><td><code>SortDate.Sort_week</code></td><td>This week</td></tr>
                <tr><td><code>SortDate.Sort_month</code></td><td>This month</td></tr>
                <tr><td><code>SortDate.Sort_last_3_months</code></td><td>Last 3 months</td></tr>
                <tr><td><code>SortDate.Sort_last_6_months</code></td><td>Last 6 months</td></tr>
            </tbody>
        </table>
    </div>

    <h4>SortVideoTime (Duration)</h4>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>Enum Value</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>SortVideoTime.Sort_all</code></td><td>Any duration (default)</td></tr>
                <tr><td><code>SortVideoTime.Sort_short</code></td><td>1–3 minutes</td></tr>
                <tr><td><code>SortVideoTime.Sort_middle</code></td><td>3–10 minutes</td></tr>
                <tr><td><code>SortVideoTime.Sort_long</code></td><td>10+ minutes</td></tr>
                <tr><td><code>SortVideoTime.Sort_long_10_20min</code></td><td>10–20 minutes</td></tr>
                <tr><td><code>SortVideoTime.Sort_really_long</code></td><td>20+ minutes</td></tr>
            </tbody>
        </table>
    </div>

    <h4>SortQuality (Resolution)</h4>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>Enum Value</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>SortQuality.Sort_all</code></td><td>Any quality (default)</td></tr>
                <tr><td><code>SortQuality.Sort_720p</code></td><td>720p and above</td></tr>
                <tr><td><code>SortQuality.Sort_1080_plus</code></td><td>1080p and above</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="section" id="downloading-section">
    <span class="section-anchor" id="downloading"></span>
    <h2><span class="section-icon">⬇️</span> Downloading</h2>

    <p>All downloads are configured using the <code>DownloadConfigHLS</code> dataclass:</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">from</span> xvideos_api <span class="token-keyword">import</span> DownloadConfigHLS

config = <span class="token-class">DownloadConfigHLS</span>(
    quality=<span class="token-string">"best"</span>,           <span class="token-comment"># "best", "half", "worst", or int like 720</span>
    path=<span class="token-string">"./downloads"</span>,       <span class="token-comment"># Output directory (title auto-appended)</span>
    no_title=<span class="token-keyword">False</span>,           <span class="token-comment"># If True, use path as exact filename</span>
    remux=<span class="token-keyword">True</span>,               <span class="token-comment"># Convert TS segments to MP4 (needs av)</span>
    return_report=<span class="token-keyword">True</span>,       <span class="token-comment"># Return DownloadReport instead of bool</span>
)

report = <span class="token-keyword">await</span> video.download(configuration=config)
<span class="token-builtin">print</span>(report.status)       <span class="token-comment"># "completed", "failed", or "cancelled"</span>
<span class="token-builtin">print</span>(report.downloaded)    <span class="token-comment"># Segments downloaded</span>
<span class="token-builtin">print</span>(report.total)         <span class="token-comment"># Total segments</span></code></pre>
    </div>

    <h3>DownloadConfigHLS — Full Options</h3>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>Parameter</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>quality</code></td><td><code>str | int</code></td><td>—</td><td><strong>Required.</strong> "best", "half", "worst", or pixel height (720, 1080, etc.)</td></tr>
                <tr><td><code>path</code></td><td><code>str</code></td><td><code>"./"</code></td><td>Output directory or exact file path</td></tr>
                <tr><td><code>no_title</code></td><td><code>bool</code></td><td><code>False</code></td><td>Skip auto-appending video title to filename</td></tr>
                <tr><td><code>callback</code></td><td><code>(int, int) → None</code></td><td><code>None</code></td><td>Progress callback <code>(downloaded, total)</code>. Falls back to text progress bar.</td></tr>
                <tr><td><code>stop_event</code></td><td><code>asyncio.Event</code></td><td><code>None</code></td><td>Set this event to cancel the download</td></tr>
                <tr><td><code>remux</code></td><td><code>bool</code></td><td><code>False</code></td><td>Remux TS → MP4 using PyAV</td></tr>
                <tr><td><code>start_segment</code></td><td><code>int</code></td><td><code>0</code></td><td>Skip first N segments</td></tr>
                <tr><td><code>segment_state_path</code></td><td><code>str | None</code></td><td><code>None</code></td><td>Path for resume state JSON file</td></tr>
                <tr><td><code>segment_dir</code></td><td><code>str | None</code></td><td><code>None</code></td><td>Directory for individual segment files</td></tr>
                <tr><td><code>return_report</code></td><td><code>bool</code></td><td><code>False</code></td><td>Return <code>DownloadReport</code> instead of <code>bool</code></td></tr>
                <tr><td><code>cleanup_on_stop</code></td><td><code>bool</code></td><td><code>True</code></td><td>Delete temp files when cancelled</td></tr>
                <tr><td><code>keep_segment_dir</code></td><td><code>bool</code></td><td><code>False</code></td><td>Keep segment files after completion</td></tr>
                <tr><td><code>ios_support</code></td><td><code>bool</code></td><td><code>False</code></td><td>Restrict audio codec to AAC-only for iOS</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="section" id="pagination-section">
    <span class="section-anchor" id="pagination"></span>
    <h2><span class="section-icon">📄</span> Pagination & Iterators</h2>

    <p>Methods like <code>search()</code>, <code>get_playlist()</code>, and <code>channel.videos()</code> return <strong>async generators</strong> that yield <code>ScrapeResult</code> objects:</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">async for</span> result <span class="token-keyword">in</span> client.search(<span class="token-string">"query"</span>, pages=<span class="token-number">3</span>):
    <span class="token-keyword">if</span> result.is_success:
        video = result.video        <span class="token-comment"># The Video object</span>
        <span class="token-builtin">print</span>(video.title)
    <span class="token-keyword">else</span>:
        <span class="token-builtin">print</span>(f<span class="token-string">"Error for {result.url}: {result.error}"</span>)</code></pre>
    </div>

    <h3>ScrapeResult</h3>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>Attribute</th><th>Type</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>url</code></td><td><code>str</code></td><td>The video URL</td></tr>
                <tr><td><code>video</code></td><td><code>Video | None</code></td><td>The populated Video object (if successful)</td></tr>
                <tr><td><code>error</code></td><td><code>Exception | None</code></td><td>The error that occurred (if any)</td></tr>
                <tr><td><code>is_success</code></td><td><code>bool</code></td><td>Whether the scrape succeeded</td></tr>
            </tbody>
        </table>
    </div>

    <h3>Concurrency Parameters</h3>
    <p>All iterator methods accept concurrency tuning:</p>
    <ul class="param-list">
        <li class="param-item"><span class="param-name">videos_concurrency</span> <span class="param-type">int | None</span> <span class="param-desc">— Max videos loaded concurrently. Defaults to <code>config.videos_concurrency</code> (5).</span></li>
        <li class="param-item"><span class="param-name">pages_concurrency</span> <span class="param-type">int | None</span> <span class="param-desc">— Max pages fetched concurrently. Defaults to <code>config.pages_concurrency</code> (2).</span></li>
        <li class="param-item"><span class="param-name">on_video_error</span> <span class="param-type">(url, error, attempt) → bool</span> <span class="param-desc">— Custom error callback. Return <code>True</code> to retry.</span></li>
        <li class="param-item"><span class="param-name">on_page_error</span> <span class="param-type">(url, error, attempt) → bool</span> <span class="param-desc">— Same but for page fetch failures.</span></li>
        <li class="param-item"><span class="param-name">keep_original_order</span> <span class="param-type">bool</span> <span class="param-desc">— Yield results in page order (slower but deterministic).</span></li>
    </ul>
</div>

<div class="section" id="error-handling-section">
    <span class="section-anchor" id="error-handling"></span>
    <h2><span class="section-icon">⚠️</span> Error Handling</h2>

    <p>The API defines the following custom exceptions in <code>xvideos_api.modules.errors</code>. Note that base networking errors are raised from <code>eaf_base_api</code>.</p>

    <div class="table-wrapper">
        <table>
            <thead><tr><th>Exception</th><th>When Raised</th></tr></thead>
            <tbody>
                <tr><td><code>NotFound</code></td><td>Server returned HTTP 404</td></tr>
                <tr><td><code>NetworkError</code></td><td>General network failure (wraps <code>NetworkRequestError</code>)</td></tr>
                <tr><td><code>BotDetection</code></td><td>Cloudflare or similar bot protection triggered</td></tr>
                <tr><td><code>ProxyError</code></td><td>Invalid or failing proxy</td></tr>
                <tr><td><code>UnknownNetworkError</code></td><td>Unexpected network errors</td></tr>
                <tr><td><code>DownloadFailed</code></td><td>Download operation failed</td></tr>
                <tr><td><code>NoLoginCookies</code></td><td>Account accessed without cookies set</td></tr>
            </tbody>
        </table>
    </div>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">from</span> xvideos_api.modules.errors <span class="token-keyword">import</span> NotFound, BotDetection

<span class="token-keyword">try</span>:
    video = <span class="token-keyword">await</span> client.get_video(url)
<span class="token-keyword">except</span> <span class="token-class">NotFound</span>:
    <span class="token-builtin">print</span>(<span class="token-string">"Video does not exist"</span>)
<span class="token-keyword">except</span> <span class="token-class">BotDetection</span>:
    <span class="token-builtin">print</span>(<span class="token-string">"Bot protection triggered — try a proxy"</span>)</code></pre>
    </div>
</div>

<hr>

<div class="section" id="cli-section">
    <span class="section-anchor" id="cli"></span>
    <h2><span class="section-icon">💻</span> CLI Usage</h2>

    <p>XVideos API includes a command-line interface:</p>

    <div class="code-window">
        <div class="code-header"><span>bash</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-comment"># Download a single video</span>
xvideos_api --download "https://www.xvideos.com/video..." --quality best --output ./video.mp4 --no-title True

<span class="token-comment"># Download from a file of URLs</span>
xvideos_api --file urls.txt --quality 720 --output ./downloads/ --no-title False</code></pre>
    </div>

    <h3>CLI Options</h3>
    <div class="table-wrapper">
        <table>
            <thead><tr><th>Flag</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>--download URL</code></td><td>Video URL to download</td></tr>
                <tr><td><code>--file PATH</code></td><td>Text file with URLs (one per line)</td></tr>
                <tr><td><code>--quality</code></td><td>Video quality: <code>best</code>, <code>half</code>, <code>worst</code></td></tr>
                <tr><td><code>--output</code></td><td>Output path (directory or file)</td></tr>
                <tr><td><code>--no-title</code></td><td><code>True</code>/<code>False</code> — Skip auto-appending title</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="section" id="platforms-section">
    <span class="section-anchor" id="platforms"></span>
    <h2><span class="section-icon">🖥️</span> Supported Platforms</h2>

    <div class="table-wrapper">
        <table>
            <thead><tr><th>Platform</th><th>Architecture</th><th>Status</th></tr></thead>
            <tbody>
                <tr><td>Windows 11</td><td>x64</td><td>✅ Tested</td></tr>
                <tr><td>macOS Sequoia</td><td>x86_64</td><td>✅ Tested</td></tr>
                <tr><td>Linux (Arch)</td><td>x86_64</td><td>✅ Tested</td></tr>
                <tr><td>Android 16</td><td>aarch64</td><td>✅ Tested</td></tr>
            </tbody>
        </table>
    </div>

    <div class="info-box note">
        <div class="info-box-title">Note</div>
        PyAV (for TS→MP4 remuxing) is <strong>not available</strong> on Termux/Android. Use <code>remux=False</code> on those platforms.
    </div>
</div>

<!-- END:MAIN_CONTENT -->
""")

    with open("content/eaf_base_api.html", "w", encoding="utf-8") as f:
        f.write("""<!-- ============================================================
     eaf_base_api Documentation — Content File
     ============================================================ -->

<!-- META -->
<!-- SLOT:TITLE = Base API -->
<!-- SLOT:HERO_TITLE = eaf_base_api -->
<!-- SLOT:HERO_SUBTITLE = The core asynchronous networking engine for all EchterAlsFake scrapers and API wrappers. Handles HTTP sessions, bot bypasses, retries, HLS downloading, and caching. -->
<!-- SLOT:VERSION = 3.3.3 -->
<!-- SLOT:GITHUB_URL = https://github.com/EchterAlsFake/eaf_base_api -->
<!-- SLOT:PYPI_PACKAGE = eaf_base_api -->

<!-- SIDEBAR_NAV -->
<!-- BEGIN:SIDEBAR_NAV -->
<div class="nav-section-title">Getting Started</div>
<a href="#overview" class="nav-link">Overview</a>
<a href="#runtime-config" class="nav-link">RuntimeConfig</a>
<a href="#client-integration" class="nav-link">Client Integration</a>

<div class="nav-section-title">Networking Engine</div>
<a href="#networking" class="nav-link">Networking & Retries</a>
<a href="#proxies" class="nav-link">Proxies</a>
<a href="#caching" class="nav-link">Caching</a>

<div class="nav-section-title">Advanced</div>
<a href="#download-resume" class="nav-link">Download Resume</a>
<a href="#logging" class="nav-link">Logging</a>
<a href="#base-errors" class="nav-link">Error Reference</a>
<!-- END:SIDEBAR_NAV -->

<!-- MAIN_CONTENT -->
<!-- BEGIN:MAIN_CONTENT -->

<div class="section" id="overview-section">
    <span class="section-anchor" id="overview"></span>
    <h2><span class="section-icon">🏗️</span> Overview</h2>

    <p><code>eaf_base_api</code> provides the core engine behind all EchterAlsFake API wrappers:</p>

    <ul class="param-list" style="margin: 16px 0;">
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>BaseCore</strong> — HTTP session management, request retrying, caching, HLS/M3U8 downloading, TS→MP4 remuxing</li>
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>BaseMedia</strong> — Lazy-loading dataclass base with automatic <code>DataNotLoadedError</code> on missing attributes</li>
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>Helper</strong> — Concurrent page/video scraping orchestrator using async producer/consumer queues</li>
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>Cache</strong> — Thread-safe in-memory caching with FIFO eviction</li>
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>RuntimeConfig</strong> — Global configuration singleton</li>
    </ul>
</div>

<div class="section" id="runtime-config-section">
    <span class="section-anchor" id="runtime-config"></span>
    <h2><span class="section-icon">🎛️</span> RuntimeConfig</h2>

    <p>The <code>RuntimeConfig</code> class controls the entire networking stack. Import it from <code>base_api</code>:</p>

    <div class="table-wrapper">
        <table>
            <thead><tr><th>Attribute</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>max_cache_items</code></td><td><code>int</code></td><td><code>200</code></td><td>Maximum number of cached responses (FIFO eviction)</td></tr>
                <tr><td><code>max_retries</code></td><td><code>int</code></td><td><code>4</code></td><td>Max retry attempts per request (exponential backoff)</td></tr>
                <tr><td><code>request_delay</code></td><td><code>int</code></td><td><code>0</code></td><td>Seconds to wait between requests (rate limiting)</td></tr>
                <tr><td><code>timeout</code></td><td><code>int</code></td><td><code>20</code></td><td>Request timeout in seconds</td></tr>
                <tr><td><code>max_bandwidth_mb</code></td><td><code>float | None</code></td><td><code>None</code></td><td>Speed limit in MB/s. Distributed across workers.</td></tr>
                <tr><td><code>proxies</code></td><td><code>dict | None</code></td><td><code>None</code></td><td>Proxy mapping, e.g. <code>{"https": "socks5://..."}</code></td></tr>
                <tr><td><code>http_version</code></td><td><code>str</code></td><td><code>"v3"</code></td><td>HTTP version: <code>"v1"</code>, <code>"v2"</code>, or <code>"v3"</code></td></tr>
                <tr><td><code>dns_over_https</code></td><td><code>str | None</code></td><td><code>None</code></td><td>DoH server URL, e.g. <code>"https://1.1.1.1/dns-query"</code></td></tr>
                <tr><td><code>impersonation</code></td><td><code>str</code></td><td><code>"chrome"</code></td><td>Browser TLS fingerprint to impersonate</td></tr>
                <tr><td><code>custom_ja3</code></td><td><code>str | None</code></td><td><code>None</code></td><td>Custom JA3 fingerprint string (advanced only)</td></tr>
                <tr><td><code>proxy_auth</code></td><td><code>str | None</code></td><td><code>None</code></td><td>Proxy authentication <code>"user:password"</code></td></tr>
                <tr><td><code>verify_ssl</code></td><td><code>bool</code></td><td><code>True</code></td><td>Verify SSL certificates</td></tr>
                <tr><td><code>trust_env</code></td><td><code>bool</code></td><td><code>False</code></td><td>Trust environment proxy settings</td></tr>
                <tr><td><code>cookies</code></td><td><code>dict | None</code></td><td><code>None</code></td><td>Default cookies for all requests</td></tr>
                <tr><td><code>locale</code></td><td><code>str</code></td><td><code>"en-US,en;q=0.9"</code></td><td>Accept-Language header value</td></tr>
                <tr><td><code>max_workers_download</code></td><td><code>int</code></td><td><code>20</code></td><td>Concurrent segment download workers</td></tr>
                <tr><td><code>videos_concurrency</code></td><td><code>int</code></td><td><code>5</code></td><td>Max videos to scrape concurrently</td></tr>
                <tr><td><code>pages_concurrency</code></td><td><code>int</code></td><td><code>2</code></td><td>Max pages to fetch concurrently</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="section" id="client-integration-section">
    <span class="section-anchor" id="client-integration"></span>
    <h2><span class="section-icon">🔗</span> Client Integration</h2>

    <p>All APIs built on top of <code>eaf_base_api</code> follow the exact same pattern. You instantiate a <code>BaseCore</code> with your <code>RuntimeConfig</code>, and then pass that <code>BaseCore</code> into the API's <code>Client</code>. Here is an example using the <strong>XVideos API</strong>, but the logic applies universally to Pornhub, RedTube, SpankBang, etc.</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">from</span> base_api <span class="token-keyword">import</span> BaseCore
<span class="token-keyword">from</span> base_api.modules.config <span class="token-keyword">import</span> RuntimeConfig
<span class="token-keyword">from</span> xvideos_api <span class="token-keyword">import</span> Client  <span class="token-comment"># Works identical with pornhub_api, xnxx_api, etc.</span>

<span class="token-comment"># 1. Create and tweak your config</span>
my_config = <span class="token-class">RuntimeConfig</span>()
my_config.timeout = <span class="token-number">60</span>
my_config.max_retries = <span class="token-number">10</span>
my_config.proxies = {<span class="token-string">"https"</span>: <span class="token-string">"socks5://127.0.0.1:9050"</span>}

<span class="token-comment"># 2. Initialize the core engine with your custom config</span>
core = <span class="token-class">BaseCore</span>(configuration=my_config)

<span class="token-comment"># 3. Pass the configured core into ANY API client</span>
client = <span class="token-class">Client</span>(core=core)

<span class="token-comment"># Now this client will route all its requests through your specific config/proxies!</span>
</code></pre>
    </div>
</div>

<div class="section" id="networking-section">
    <span class="section-anchor" id="networking"></span>
    <h2><span class="section-icon">🌐</span> Networking & Retries</h2>

    <p>Under the hood, <code>BaseCore</code> uses <a href="https://github.com/yifeikong/curl_cffi">curl_cffi</a> for HTTP requests, which provides:</p>

    <ul class="param-list" style="margin: 16px 0;">
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>Browser impersonation</strong> — TLS fingerprint mimicking (Chrome, Firefox, etc.) to bypass WAF/bot detection</li>
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>HTTP/1.1, HTTP/2, HTTP/3</strong> — Configurable via <code>config.http_version</code></li>
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>Custom JA3</strong> — Override TLS fingerprints for advanced users</li>
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>DNS over HTTPS</strong> — Route DNS through HTTPS for privacy</li>
        <li class="param-item" style="display: block; padding: 8px 0;"><strong>Bandwidth limiting</strong> — Set per-connection speed limits with <code>CurlOpt.MAX_RECV_SPEED_LARGE</code></li>
    </ul>

    <h3>Retry Strategy</h3>
    <p>Requests are retried using <a href="https://github.com/jd/tenacity">Tenacity</a> with exponential backoff + jitter:</p>
    <ul class="param-list" style="margin: 12px 0;">
        <li class="param-item" style="display: block; padding: 4px 0;">Initial wait: 0.5s → Max: 30s → Jitter: ±0.5s</li>
        <li class="param-item" style="display: block; padding: 4px 0;">Retries on: <code>RequestsError</code>, <code>NetworkRequestError</code></li>
        <li class="param-item" style="display: block; padding: 4px 0;">HTTP 429 (Rate Limited): Respects <code>Retry-After</code> header, or random 2–6s backoff</li>
        <li class="param-item" style="display: block; padding: 4px 0;">HTTP 5xx: Automatically retried</li>
    </ul>
</div>

<div class="section" id="proxies-section">
    <span class="section-anchor" id="proxies"></span>
    <h2><span class="section-icon">🔒</span> Proxies</h2>

    <p>Full proxy support including SOCKS5, HTTPS, and authenticated proxies:</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">from</span> base_api <span class="token-keyword">import</span> config

<span class="token-comment"># SOCKS5 proxy</span>
config.proxies = {<span class="token-string">"https"</span>: <span class="token-string">"socks5://127.0.0.1:9050"</span>}

<span class="token-comment"># HTTPS proxy with auth</span>
config.proxies = {<span class="token-string">"https"</span>: <span class="token-string">"https://proxy.example.com:8080"</span>}
config.proxy_auth = <span class="token-string">"username:password"</span>

<span class="token-comment"># Disable SSL verification (for MITM proxies)</span>
config.verify_ssl = <span class="token-keyword">False</span></code></pre>
    </div>

    <div class="info-box warning">
        <div class="info-box-title">Warning</div>
        If your proxy uses a self-signed certificate, you'll get a <code>ProxySSLError</code>. Set <code>config.verify_ssl = False</code> to disable certificate verification.
    </div>
</div>

<div class="section" id="caching-section">
    <span class="section-anchor" id="caching"></span>
    <h2><span class="section-icon">💾</span> Caching</h2>

    <p>The <code>Cache</code> class provides thread-safe in-memory caching with FIFO eviction. Text responses are cached automatically (not binary/byte responses).</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-comment"># Adjust max cache size</span>
config.max_cache_items = <span class="token-number">500</span>  <span class="token-comment"># Default: 200</span>

<span class="token-comment"># The cache can be accessed on the BaseCore instance:</span>
core = client.core
core.cache.cache_dictionary  <span class="token-comment"># The raw dict</span></code></pre>
    </div>
</div>

<div class="section" id="download-resume-section">
    <span class="section-anchor" id="download-resume"></span>
    <h2><span class="section-icon">🔄</span> Download Resume & Cancel</h2>

    <p>The base HLS downloader supports <strong>resume</strong> and <strong>cancellation</strong> via state files and stop events. This works universally across all APIs when calling <code>video.download()</code>:</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">import</span> asyncio
<span class="token-keyword">import</span> threading
<span class="token-keyword">from</span> base_api <span class="token-keyword">import</span> DownloadConfigHLS

stop = threading.Event()

config = <span class="token-class">DownloadConfigHLS</span>(
    quality=<span class="token-string">"720"</span>,
    path=<span class="token-string">"video.mp4"</span>,
    segment_state_path=<span class="token-string">"video.state.json"</span>,  <span class="token-comment"># Enables resume</span>
    keep_segment_dir=<span class="token-keyword">True</span>,                   <span class="token-comment"># Keep downloaded parts</span>
    stop_event=stop,                          <span class="token-comment"># Cancel trigger</span>
)

<span class="token-comment"># Cancel from another thread: stop.set()</span>
<span class="token-comment"># Resume: just run video.download(configuration=config) again</span></code></pre>
    </div>

    <div class="info-box tip">
        <div class="info-box-title">How Resume Works</div>
        When cancelled, a JSON state file is written with segment URLs and progress. On the next run, the downloader loads this state, scans the segment directory for existing files, and only fetches what's missing. On success, the state file is automatically deleted.
    </div>
</div>

<div class="section" id="logging-section">
    <span class="section-anchor" id="logging"></span>
    <h2><span class="section-icon">📝</span> Logging</h2>

    <p>Both the base API and child APIs use Python's <code>logging</code> module. Enable verbose logging:</p>

    <div class="code-window">
        <div class="code-header"><span>python</span><button class="code-copy-btn" onclick="copyCode(this)">Copy</button></div>
<pre><code><span class="token-keyword">import</span> logging

<span class="token-comment"># Enable BaseCore logging</span>
core.enable_logging(level=logging.DEBUG)

<span class="token-comment"># Log to a file</span>
core.enable_logging(log_file=<span class="token-string">"api.log"</span>, level=logging.INFO)

<span class="token-comment"># Remote HTTP logging (sends logs to a server)</span>
core.enable_logging(
    log_ip=<span class="token-string">"192.168.1.100"</span>,
    log_port=<span class="token-number">8080</span>,
    level=logging.DEBUG
)</code></pre>
    </div>
</div>

<div class="section" id="base-errors-section">
    <span class="section-anchor" id="base-errors"></span>
    <h2><span class="section-icon">🚨</span> Error Reference</h2>

    <p>The <code>eaf_base_api</code> defines a comprehensive error hierarchy under <code>base_api.modules.errors</code>. You may catch these when calling methods from any of the APIs:</p>

    <div class="table-wrapper">
        <table>
            <thead><tr><th>Exception</th><th>When Raised</th></tr></thead>
            <tbody>
                <tr><td><code>UnknownError</code></td><td>Unexpected errors not covered by specific exceptions</td></tr>
                <tr><td><code>ResourceGone</code></td><td>HTTP 410 — resource permanently removed</td></tr>
                <tr><td><code>NetworkRequestError</code></td><td>General network request failures</td></tr>
                <tr><td><code>HTTPStatusError</code></td><td>Non-200 HTTP responses (has <code>.status_code</code>, <code>.url</code>)</td></tr>
                <tr><td><code>RateLimitError</code></td><td>HTTP 429 — too many requests (has <code>.retry_after</code>)</td></tr>
                <tr><td><code>AccessDeniedError</code></td><td>HTTP 403 — blocked by server</td></tr>
                <tr><td><code>InvalidProxy</code></td><td>Proxy configuration is invalid or unreachable</td></tr>
                <tr><td><code>ProxySSLError</code></td><td>Proxy SSL certificate verification failed</td></tr>
                <tr><td><code>BotProtectionDetected</code></td><td>Cloudflare or similar WAF detected</td></tr>
                <tr><td><code>DownloadCancelled</code></td><td>Download was stopped via <code>stop_event</code></td></tr>
                <tr><td><code>PlaylistExtractionError</code></td><td>Failed to parse M3U8 master playlist</td></tr>
                <tr><td><code>DataNotLoadedError</code></td><td>Attribute accessed before <code>load()</code> was called</td></tr>
                <tr><td><code>SecurityAbort</code></td><td>Illegal characters detected in bot challenge code</td></tr>
            </tbody>
        </table>
    </div>
</div>

<!-- END:MAIN_CONTENT -->
""")

if __name__ == "__main__":
    rewrite_docs()
