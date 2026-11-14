---
title: "Video \u2014 YouJizz API"
summary: "Video fields, metadata sources, comments, authors and refreshed URLs."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Video \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "reference", "video"]
---

# Video — YouJizz API

`Video(BaseMedia)` has independent `api`, `html` and `comments` sources.
API fields: title, duration (integer seconds), length, views (decimal string),
thumbnail_url, preview_video_url, is_hd, thumbnail_count and sprite_url.
HTML adds description, publish_date (site calendar date), canonical_url, embed_url,
tags, rating (float out of 5), rating_votes, author_id, author_name, author_link,
direct_urls, hls_urls, m3u8_base_url, available_qualities and content_url.
API takes precedence for shared fields except thumbnail_url, which prefers HTML.

`await video.get_author(load_api=True)` returns User or None.
`video.related_videos(...)` yields related result objects.
`await video.load_sources("comments")` loads typed comments and comment_count.
The count covers returned comment records, excluding action rows; reply references
and Unix timestamps are preserved.
`await video.refresh_sources()` returns a new HTML-loaded Video with refreshed cache.
Unloaded fields raise DataNotLoadedError; loaded absent fields are None.
