---
title: "User — RedGIFs API"
summary: "User and creator metadata, studio flags, API-only loading, video/image tabs and public collection streams. Symbols: get_user thumbnail_url creation_date video_count published_count collection_count profile_url raw_metadata User.videos User.images User.collections."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "User — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "User"
  - "creator"
  - "videos"
  - "images"
  - "collections"
  - "published_count"
---

# User — RedGIFs API

Use `await client.get_user(username_or_user_url, load_api=True)`.
`User` is a keyword-only `BaseMedia` dataclass with an `api` loader. The public API
uses one User domain for creators, models and studios; inspect flags instead of
inventing separate resource types.

## Fields

| Field | Type | Source | Meaning |
| --- | --- | --- | --- |
| `url` | `str` | identity | Canonical www watch URL, or canonical profile/niche/collection URL. |
| `core` | `BaseCore` | identity | Shared caller-configurable backend; omitted from to_dict() by default. |
| `username` | `str` | identity | Canonical lowercase profile owner username. |
| `name` | `str \| None` | api | Site display name. |
| `description` | `str \| None` | api | Site profile/niche/collection description, or null when absent. |
| `thumbnail_url` | `str \| None` | api | Thumbnail/profile image URL supplied by the selected source. |
| `creation_date` | `str \| None` | api | Profile creation time as UTC ISO 8601. |
| `followers` | `int \| None` | api | Reported follower count. |
| `following` | `int \| None` | api | Reported following count. |
| `video_count` | `int \| None` | api | Raw gifs count; this site can include images in that counter. |
| `published_count` | `int \| None` | api | Raw publishedGifs count; includes images and can exceed publicly listed records. |
| `collection_count` | `int \| None` | api | Reported publishedCollections count. |
| `views` | `int \| None` | api | Site-reported integer view count. |
| `likes` | `int \| None` | api | Site-reported integer like count. |
| `verified` | `bool \| None` | api | Site-reported uploader/profile verification flag. |
| `studio` | `bool \| None` | api | Studio/profile classification flag. |
| `status` | `str \| None` | api | Site account status. |
| `profile_url` | `str \| None` | api | Site profileUrl value, which may be an external social/creator URL. |
| `links` | `list[dict] \| None` | api | Site-provided outbound-link metadata; not independently resolved. |
| `raw_metadata` | `dict \| None` | api | Original matched API record, preserving additional site fields. |

`video_count` and `published_count` preserve the site's `gifs`/`publishedGifs` values;
those counts can include images and records missing from public tabs. `profile_url`
is the site's possibly external profile/social URL, while `url` is the canonical user
page. Full API detail is retained in `raw_metadata`.

## Streams

```python
def videos(*, pages=1, start_page=1, count=40, sort=ProfileSort.NEW,
           tags=None, iterator_config=None) -> ScrapeStream[Video]: ...
def images(*, pages=1, start_page=1, count=40,
           iterator_config=None) -> ScrapeStream[Image]: ...
def collections(*, pages=1, start_page=1, count=40,
                iterator_config=None) -> ScrapeStream[Collection]: ...
```

`videos()` selects the actual video tab (`type=g`), accepts `new`/`top` ordering and
optional tag names. `images()` selects the image tab (`type=i`) with new ordering;
it has no tag/sort argument. `collections()` selects published collections for this owner.
All three are lazy shared result streams; unwrap every result and close partial streams.

```python
async def profile_videos(client):
    user = await client.get_user("nickiipeach")
    async with user.videos(pages="all", count=40) as results:
        return [result.unwrap() async for result in results]
```

A missing/unavailable profile must not become an empty successful User. Upstream equal-time
ordering can repeat/omit IDs across pages, and public counts can be stale. See
[iteration evidence](../guides/iteration-and-results.md) and
[validation status](../guides/live-validation.md).
