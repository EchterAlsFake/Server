"""Editorial guide content for the v3.9 workflow, checked against the app source.

See docs/SEO.md for the source checklist. Dates change only with editorial updates.
The ordering is editorial priority, not a measured market-share claim.
"""

GUIDE_DATE = "2026-10-25"
GUIDE_VERSION = "3.9 beta"

# Each section contains a heading followed by independently authored paragraphs.
GUIDES = {
    "pornhub": {
        "name": "PornHub",
        "summary": "Save a video, fetch a playlist, or use supported account collections.",
        "intro": "To download a PornHub video with Porn Fetch, copy the full video-page URL, add it in the app, choose an available quality, and start the download. The file is saved on your device. For a playlist or model page, use the matching input instead of the single-video field.",
        "sections": [
            ("PornHub video links, playlists, and model pages", [
                "For a normal video, copy the page address containing view_video.php?viewkey=… rather than a search result or the site’s homepage. The app also routes supported embed links and individual short or shorties links as videos.",
                "On desktop, put a playlist link in Playlist URL and choose Get Videos. For a model, performer, user, or channel page, use Model URL. On Android, choose the corresponding URL type in Add videos. Review the returned list before downloading it.",
                "A public user page is not the same as that user’s uploaded-video tab. The selected tab and the upstream listing can affect which videos are returned. An empty listing does not necessarily mean the URL is malformed.",
            ]),
            ("Using your PornHub account", [
                "The account page supports watch history, recommendations, the subscription feed, and favorites after login. Choose PornHub there, connect your own account using a supported login method, then use the collection button you need.",
                "Porn Fetch’s license and a PornHub account are separate. An app license does not grant access to restricted website content. PornHub photo albums are supported in the CLI only; they are not a graphical-app download feature.",
            ]),
        ],
        "question": "Why does a PornHub profile return no videos?",
        "answer": "Check that you copied an individual profile rather than a directory, and that the selected page actually lists videos you can access. Profile photo, favorites, and shorts tabs are not accepted as ordinary video-profile inputs. Use the account page for your own favorites and the single-video input for an individual supported short.",
    },
    "xhamster": {
        "name": "XHamster",
        "summary": "Download videos and shorts, fetch profiles, or open your account playlists.",
        "intro": "Porn Fetch can save individual XHamster videos and supported shorts to your device. Copy the video page’s full address, fetch it in the app, choose a quality, and download. Profiles and your own account playlists use separate workflows.",
        "sections": [
            ("Which XHamster links should I use?", [
                "Individual links under videos or movies are video inputs. Supported moments and shorts links also go through the single-video workflow. Copy the item’s address rather than the page listing many shorts.",
                "Performer, creator, user, and channel pages use Model URL on desktop, or the Model URL type on Android. Directory pages and profile tabs for photos, albums, favorites, or shorts are not accepted as ordinary profile-video inputs.",
            ]),
            ("Downloading an XHamster account playlist", [
                "XHamster collections are account-only in Porn Fetch. Open the account page, choose XHamster, and connect your own account. Use Get Liked Videos for liked videos, or paste your account playlist URL into Account playlist URL and choose Get Playlist Videos.",
                "Do not put a my/playlists address into the public Playlist URL input. A public collection workflow and an authenticated account playlist are different features; only the account workflow is supported here.",
            ]),
        ],
        "question": "Why does my XHamster playlist link fail?",
        "answer": "Use the account page and confirm that the app has a working XHamster login. The general playlist input does not handle XHamster account playlists. Check that the playlist belongs to, or is accessible through, the connected account.",
    },
    "xvideos": {
        "name": "XVideos",
        "summary": "Save individual videos, fetch profiles and playlists, or connect an account.",
        "intro": "To save an XVideos video, copy its full video-page URL and fetch it in Porn Fetch. Choose a quality from the returned video row, then download it to your output folder. Playlists, profiles, and account collections have their own inputs.",
        "sections": [
            ("Videos, profiles, and playlists on XVideos", [
                "The video input accepts supported XVideos video and embedframe links. For a performer, model, profile, or channel page, use Model URL. The router also recognizes supported username-style profile addresses.",
                "Use Playlist URL for an individual playlist or supported favorite collection. A generic profile directory, search page, or category page is not a downloadable collection. XVideos Quickies links are not supported.",
            ]),
            ("Connecting an XVideos account", [
                "Choose XVideos on the app’s account page and use its supported session-token or browser-cookie login. Once connected, the page offers watch-later videos, watch history, and liked videos.",
                "A browser login does not automatically connect Porn Fetch. Keep session tokens and cookies private; enter them only in the app’s authentication workflow, not into this website or a support email.",
            ]),
        ],
        "question": "Can I download XVideos Quickies?",
        "answer": "No. The current URL router explicitly rejects Quickies links. Use a supported regular video-page URL; the existence of a short-video feature on the website does not mean it is supported in Porn Fetch.",
    },
    "eporner": {
        "name": "Eporner",
        "summary": "Save individual videos and fetch supported performer or channel pages.",
        "intro": "Copy an Eporner video’s full page address, fetch it in Porn Fetch, and download one of the qualities the app actually returns. You can also fetch supported performer and channel pages. Eporner login and playlists are not app features.",
        "sections": [
            ("Choosing an Eporner video or channel link", [
                "Supported video-address forms include video- followed by the video ID, hd-porn, embed, and localized porno-video paths. Copy the complete address so the video ID keeps its original letter casing.",
                "For a performer or channel, use Model URL rather than Video URL. The router recognizes pornstar, pornostar, channel, and channels page forms. It does not expose Eporner search or playlist downloading.",
            ]),
            ("Eporner quality depends on the available stream", [
                "A resolution advertised on Eporner is not a promise that Porn Fetch can retrieve it. The app’s own quality help warns about Eporner restrictions above 720p. Choose from the qualities returned for the particular video; buying an app license does not remove website-side restrictions.",
            ]),
        ],
        "question": "Will Premium unlock every Eporner resolution?",
        "answer": "No. Premium removes the app’s higher-quality entitlement restriction, but it cannot make an unavailable source stream downloadable. Start with the qualities returned by the app rather than the resolution displayed on the website.",
    },
    "xnxx": {
        "name": "XNXX",
        "summary": "Download videos or fetch supported profiles without an account-login workflow.",
        "intro": "Porn Fetch downloads supported XNXX videos from their full page URLs. Fetch a video, review its available qualities, and save it locally. For a supported profile page, use the model input to load its videos first.",
        "sections": [
            ("Use a video page or an individual XNXX profile", [
                "Copy the complete video address, including its video identifier. The router recognizes supported video and video- address forms on XNXX hosts, including numbered xnxx domains.",
                "Profile, user, users, and pornstar pages go through the profile workflow. The current app does not offer XNXX account login, playlists, shorts, or photo albums. If a page requires unsupported access, a Porn Fetch license does not add that access.",
            ]),
        ],
        "question": "Can I search XNXX from inside Porn Fetch?",
        "answer": "No. Find the video in your browser and paste its full URL into the app. Keyword search is intentionally unavailable in both the graphical app and the CLI.",
    },
    "spankbang": {
        "name": "SpankBang",
        "summary": "Save supported videos and fetch individual creator or channel pages.",
        "intro": "To download from SpankBang, copy the video page’s full address into Porn Fetch, fetch the video, and choose an available quality. Creator and channel pages use the profile workflow; general playlist downloading is not supported.",
        "sections": [
            ("SpankBang link types", [
                "The router accepts supported video, play, and embed paths containing a video ID. Some SpankBang video addresses contain playlist in the path; a link resolving to one video is still different from support for fetching an entire playlist.",
                "For a pornstar, profile, creator, or channel page, use Model URL. SpankBang sometimes puts an ID or locale before the profile type; the app handles supported forms. Use the individual page, not a directory listing.",
            ]),
        ],
        "question": "Can Porn Fetch download a whole SpankBang playlist?",
        "answer": "The current app does not advertise SpankBang playlist fetching. Use individual video links or a supported creator or channel page. SpankBang account login and photo albums are also unavailable.",
    },
    "youporn": {
        "name": "YouPorn",
        "summary": "Download videos, fetch collections, and understand the MP4 quality limitation.",
        "intro": "Porn Fetch supports individual YouPorn videos, performer and channel pages, and individual video collections. Start with the correct page URL, fetch the entries, then choose which videos to save on your device.",
        "sections": [
            ("YouPorn watch links and collections", [
                "Use a watch or embed link for a single video. Performer and channel pages belong in Model URL. For a collection, use Playlist URL with an individual collection address containing collections/videos/<numeric ID> or collection/videos/<numeric ID>.",
                "A collections directory is not an individual collection. Porn Fetch does not provide YouPorn account login, shorts, or photo-album downloads.",
            ]),
            ("Why a YouPorn MP4 can require Premium", [
                "Some YouPorn videos expose an MP4 without a known resolution. The app cannot treat an unknown resolution as a verified free-quality stream, so these MP4-only videos can require a Porn Fetch license even when you did not select a resolution above 720p.",
            ]),
        ],
        "question": "Why is this YouPorn video not available in the free tier?",
        "answer": "Check whether it is an MP4-only video with an unknown resolution. That case has a licensing restriction separate from choosing a known quality above 720p. A different video may expose known qualities the free tier can use.",
    },
    "beeg": {
        "name": "Beeg",
        "summary": "Save individual video links; profiles and collections are unavailable.",
        "intro": "Porn Fetch supports individual Beeg videos. Copy the full video-page address, fetch it with the video input, and download an available quality. Beeg profiles and playlists are not supported.",
        "sections": [
            ("Keep the complete Beeg video address", [
                "Supported Beeg video paths contain a numeric video ID, either directly after the hostname or under video/. The ID can include a leading minus sign. Keep that sign and the rest of the page address when copying the link.",
                "Use Video URL on desktop or the Video URL type on Android. There is no Beeg account-login, profile, collection, shorts, or photo-album workflow in the current app.",
            ]),
            ("If a Beeg video does not load", [
                "The app’s Strict Enforcement for content language setting disables API fetching, and its help specifically warns that providers such as Beeg can be affected. If you enabled it, turn it off and fetch the video again before changing unrelated settings.",
            ]),
        ],
        "question": "Can I paste a Beeg profile into Model URL?",
        "answer": "No. Beeg support is limited to individual videos. Copy an individual video’s full page URL and use the video input.",
    },
    "porntrex": {
        "name": "Porntrex",
        "summary": "Save a video or fetch supported model and channel pages.",
        "intro": "To download a Porntrex video, paste its full video-page URL into Porn Fetch, fetch the video, and start a download at an available quality. Supported model and channel pages can also return a list of videos.",
        "sections": [
            ("Porntrex videos and model pages", [
                "Individual video URLs use video/<numeric ID>. Copy that page address rather than a listing or category link. For a model or channel, the router recognizes model, models, channel, and channels paths; use the profile input for those.",
                "The app does not offer Porntrex playlist fetching, login, shorts, or photo albums. For a page outside the supported URL types, use an individual video link instead.",
            ]),
        ],
        "question": "Why does a Porntrex model fetch return fewer videos than expected?",
        "answer": "Check Max Result Limit and any duration, quality, date, or text filters. These settings can reduce a returned list. The result also depends on what the upstream model or channel page currently exposes.",
    },
    "xfreehd": {
        "name": "XFreeHD",
        "summary": "Download individual videos; photo albums use the CLI.",
        "intro": "Porn Fetch can save individual XFreeHD videos from full video-page URLs. Fetch the video in the graphical app or CLI, review the available quality, and download it. Photo albums require the CLI.",
        "sections": [
            ("XFreeHD videos and quality names", [
                "Use an individual video/<numeric ID> address in the video workflow. XFreeHD uses SD and HD quality names; the app translates its selected quality for the provider. Those names should not be read as a promise of a particular pixel resolution.",
                "XFreeHD profiles, playlists, login, and shorts are unavailable in the current app. A creator listing is not a supported replacement for an individual video URL.",
            ]),
            ("XFreeHD photo albums in the CLI", [
                "For a supported album/<ID> page, open the terminal interface and choose Download Single URL. Album routing exists in the shared provider code, but the graphical app does not expose photo-album downloading.",
            ]),
        ],
        "question": "Why does an XFreeHD album not work in the graphical app?",
        "answer": "Photo albums are CLI-only. Use the command-line download workflow with the individual album URL. The graphical app’s XFreeHD support is for videos.",
    },
    "redtube": {
        "name": "RedTube",
        "summary": "Save individual videos and fetch supported playlists or profiles.",
        "intro": "Porn Fetch supports RedTube video links, individual playlists, and supported performer, channel, amateur, and user pages. Fetch the URL using the matching input, then review the videos and save the ones you want.",
        "sections": [
            ("Pick the matching RedTube input", [
                "A normal RedTube video URL has a numeric path directly after the hostname. Use Video URL for that address. For an individual playlist, use Playlist URL rather than the video field.",
                "Supported pornstar, channel, channels, amateur, user, and users pages use Model URL. A public user page is not an authenticated account: Porn Fetch does not provide RedTube login, shorts, or photo albums.",
                "Some numeric user pages expose playlists publicly while their video feed requires login. The app’s documented profile checks do not claim successful video-list coverage for that user-page case. Use an accessible individual video or a supported performer or channel page instead.",
            ]),
        ],
        "question": "Does a RedTube playlist start downloading as soon as I paste it?",
        "answer": "Fetching and downloading are separate steps. Fetch the individual playlist, review the returned entries, then start the selected downloads. Your result limit and filters can affect the list.",
    },
    "thumbzilla": {
        "name": "Thumbzilla",
        "summary": "Download videos or fetch individual playlists and supported profiles.",
        "intro": "To download a Thumbzilla video, copy its watch-page address and fetch it in Porn Fetch. You can also load an individual playlist or a supported performer, channel, or amateur page before choosing videos to download.",
        "sections": [
            ("Thumbzilla watch pages and playlists", [
                "Individual videos use watch/<numeric ID> page addresses. Playlist links use the separate playlist workflow. Copy the individual playlist address rather than the directory of playlists.",
                "The profile workflow recognizes pornstar, channel, and amateur pages. Thumbzilla does not have an account-login, shorts, or photo-album workflow in Porn Fetch, even though other providers have some of those features.",
            ]),
        ],
        "question": "Can I use my PornHub login for Thumbzilla in the app?",
        "answer": "The app does not expose a Thumbzilla account-login feature. Treat its supported public videos, profiles, and playlists as separate URL workflows rather than assuming another provider’s account features apply.",
    },
    "tube8": {
        "name": "Tube8",
        "summary": "Download supported videos and fetch individual performer or user pages.",
        "intro": "Porn Fetch can save supported Tube8 videos and fetch videos from supported profile pages. Copy a full video or profile URL, use the matching input, and review the returned entries before downloading.",
        "sections": [
            ("Tube8 video and profile addresses", [
                "Supported single-video paths include porn-video/<numeric ID> and video/<numeric ID>. Performer, channel, amateur, user, and users pages use the profile workflow instead.",
                "User-page results depend on the upstream page and available listing. The app’s profile diagnostics document Tube8 user-feed limitations, so an empty result is not a guarantee of a malformed URL. Try an individual video you can access.",
                "Tube8 playlists, account login, shorts, and photo albums are unavailable in the current app.",
            ]),
        ],
        "question": "What should I do when a Tube8 user page returns no videos?",
        "answer": "Confirm that it is an individual user page and review your result limit and filters. If the upstream listing is empty or unsupported, use a full individual video URL. Do not replace it with a search or directory page.",
    },
    "empflix": {
        "name": "EMPFlix",
        "summary": "Save individual videos and fetch supported profile or performer pages.",
        "intro": "Copy an EMPFlix video-page URL into Porn Fetch to fetch its details and download an available quality. Supported profile and performer pages can also be loaded through the model input.",
        "sections": [
            ("Choosing an EMPFlix page URL", [
                "The router recognizes supported numeric video paths and legacy video<ID> or title-ID.html video addresses. Copy the full page URL rather than extracting a number from the title or substituting a category link.",
                "Profile, pornstar, and pornstars page forms use Model URL. A performer directory without an individual profile is not enough. EMPFlix playlist downloading, account login, shorts, and photo albums are unavailable.",
            ]),
        ],
        "question": "Does EMPFlix use the same profile inputs as TNAFlix?",
        "answer": "There is overlap, but they are separate providers. EMPFlix supports the documented profile and performer inputs; do not assume that TNAFlix’s channel-page support applies to EMPFlix.",
    },
    "tnaflix": {
        "name": "TNAFlix",
        "summary": "Download individual videos or fetch supported profiles and channels.",
        "intro": "Porn Fetch saves supported TNAFlix videos from their full page URLs. You can also fetch supported profile, performer, and channel pages, then choose individual videos from the result list to download.",
        "sections": [
            ("TNAFlix video, profile, and channel links", [
                "Supported video forms include numeric video paths, legacy video<ID> links, and title-ID.html addresses. Keep the entire page address when copying it into the single-video input.",
                "Profile, pornstar, pornstars, channel, and channels pages go through the profile workflow. The app does not offer TNAFlix playlists, account login, shorts, or photo albums.",
            ]),
        ],
        "question": "Why is a TNAFlix category link rejected?",
        "answer": "The app routes supported individual videos and profile or channel pages. Category directories and keyword searches are outside that workflow. Open a specific video or supported profile in your browser, then copy its address.",
    },
}


def guide_path(provider):
    return f"/guides/download-{provider}-videos"


def guide_for_path(path):
    prefix, suffix = "/guides/download-", "-videos"
    if path.startswith(prefix) and path.endswith(suffix):
        return GUIDES.get(path[len(prefix):-len(suffix)])
    return None
