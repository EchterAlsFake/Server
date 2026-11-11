---
title: "Image — RedGIFs API"
summary: "Image inherits Video loading and relationships with type=2, JPG sources, null duration and image output extensions. Symbols: get_image video_id media_type gallery_id available_qualities."
public_url: "https://docs.echteralsfake.me/redgifs/"
aliases:
  - "Image — RedGIFs API"
keywords:
  - "RedGIFs"
  - "redgifs_api"
  - "Image"
  - "JPG"
  - "gallery_id"
  - "media_type"
---

# Image — RedGIFs API

`Image` inherits `Video` and its field/source interface. Use
`await client.get_image(id_or_url, load_api=True, load_html=False)`.
The stable identity attribute remains `video_id`; `media_type` is 2, and `duration` and
`length` are normally null. Width/height, tags, author, source URLs, poster, publication
metadata and optional `gallery_id` remain available. See the [field table](video.md).

HTML loading validates a matching `SocialMediaPosting` containing an `ImageObject`.
Video HTML is rejected even in HTML-only mode. Conversely, `get_video()` rejects images.
Use `load_api=False, load_html=True`, both flags true, or both false for independent,
combined or deferred loading. Inherited `load_sources()` supports either load order.

```python
from redgifs_api import Client, DownloadConfigRAW

async def save_image():
    async with Client() as client:
        image = await client.get_image("deliciousfrontelephant", load_html=True)
        print(image.video_id, image.title, image.gallery_id)
        await image.download(DownloadConfigRAW(quality="hd", path="./"))
```

The default output extension comes from the supplied image rendition URL (observed JPG),
not `.mp4`. With `no_title=True`, the caller supplies the complete filename. Use `hd`,
`sd` or supported presets, according to `image.available_qualities`. There is no automatic
video conversion, gallery expansion or animated-image conversion.

`client.search_images()` and `user.images()` return image result streams. Public
collections may mix `Video` and `Image` instances while preserving listing order.
