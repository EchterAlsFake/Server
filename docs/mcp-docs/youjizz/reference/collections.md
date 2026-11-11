---
title: "Collections and User \u2014 YouJizz API"
summary: "Collection, Pornstar, Category and public user uploads."
public_url: "https://docs.echteralsfake.me/youjizz/"
aliases: ["Collections and User \u2014 YouJizz API"]
keywords: ["YouJizz", "youjizz_api", "reference", "collections"]
---

# Collections and User — YouJizz API

`Collection(url=..., core=..., name=..., video_count=None)` exposes
`videos(pages=1, *, start_page=1, iterator_config=None)`.
Pornstar and Category inherit Collection. Directory video counts are snapshots.
Pornstar entries point to keyword search; there is no separate biography endpoint.
No Model or Channel class is provided.

`await client.get_user(url, load_api=True)` accepts numeric user IDs or
`/profile/user/<id>` URLs. User fields include name, description, title, avatar_url,
date_joined, last_login, is_public, public_videos and banned.
`user.videos(...)` follows numbered upload slices from the public video-ID list.
Hidden usernames and public-upload flags are independent and respected.
Private profile fields, contact information and favorites are not exposed.
