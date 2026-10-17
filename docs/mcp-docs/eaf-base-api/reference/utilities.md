---
title: "Shared Utilities — eaf_base_api"
summary: "Documents Shared Utilities behavior, signatures, fields, constraints, and examples for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Shared Utilities"
  - "eaf base Shared Utilities"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Shared Utilities"
---

# Shared Utilities — eaf_base_api

Documents Shared Utilities behavior, signatures, fields, constraints, and examples for the eaf_base_api API.

## URL helpers (since 4.2.2)

Import these helpers directly from `base_api`. Provider adapters choose the resource depth and any additional provider-specific normalization.

Function| Signature| Description
---|---|---
`update_url_query`| `(url: str, **changes: str | int | None) -> str`| Replace named query keys, remove keys assigned None, retain other query parameters, and remove the fragment.
`replace_url_path`| `(url: str, path: str) -> str`| Replace the path while retaining the host and query parameters and removing the fragment.
`append_url_path`| `(url: str, *parts: str | int) -> str`| Append path components before the query string, avoiding duplicate separators at component boundaries.
`profile_base_url`| `(url: str, *, depth: int = 2) -> str`| Keep the first depth path components, remove page and tab suffixes and the page query key, and retain the host, slug spelling, and other filters. Raise ValueError if fewer than depth components are present.

`base_api` exports standardized parsing, sanitization, FFmpeg remuxing/tagging, and helper functions used across scrapers:

Function| Signature| Description
---|---|---
`get_text_safe`| `(node: Any, selector: str | None = None) -> str | None`| Safely extracts stripped text from a node or CSS selector match, returning `None` if missing or empty.
`get_attr_safe`| `(node: Any, attr: str, selector: str | None = None) -> str | None`| Safely extracts an HTML attribute string from a node or CSS selector match.
`parse_duration`| `(text: str | None) -> int | None`| Parses duration strings (e.g. `"12:34"`, `"1:23:45"`, `"45s"`, `"12m"`) into integer seconds.
`parse_count`| `(text: str | int | float | None) -> int | None`| Parses view and like counts with human-readable suffixes (e.g. `"1.5M"`, `"300K"`, `"12,450"`) into integers.
`build_m3u8_master`| `(streams: list[dict[str, Any]] | dict[str, str]) -> str`| Constructs a standard HLS master playlist (`#EXTM3U`) with resolution and bandwidth headers from a list or dictionary of stream variants.
`extract_video_grid`| `(parser: Any, base_url: str, logger: Any) -> list[dict]`| Extracts standardized video attributes (title, url, thumbnail, duration, author, preview) from search/listing grids. Used by Tube8 and Thumbzilla.
`str_to_bool`| `(value: Any) -> bool`| Coerces common string boolean representations (`"true"`, `"1"`, `"yes"`) to boolean.
`is_resource_gone`| `(exc: BaseException) -> bool`| Checks if an exception or nested cause represents an HTTP 404, 410, or `ResourceGone` error.
`contains_resource_gone`| `(exc: BaseException) -> bool`| Recursively inspects aggregate exceptions (e.g. `MediaLoadErrors`) to check if any nested failure represents a gone resource.
`find_ffmpeg`| `(ffmpeg_bin: Path | str | None = None, *, original_executable: Path | None = None, extra_roots: tuple[Path, ...] = ()) -> Path | None`| Resolves the `ffmpeg` executable from explicit paths, `RuntimeConfig.ffmpeg_path`, environment variables, bundled `third_party/` directories, or the system `PATH`.
`has_ffmpeg`| `(ffmpeg_bin: Path | str | None = None, *, original_executable: Path | None = None, extra_roots: tuple[Path, ...] = ()) -> bool`| Returns `True` if a usable `ffmpeg` binary is available.
`remux_ts_to_mp4`| `(input_path: Path | str, output_path: Path | str, ffmpeg_bin: Path | str | None = None, *, metadata: Any = None, thumbnail: bytes | Path | str | None = None, timeout: int = 600) -> bool`| Remuxes an MPEG-TS file into a faststart MP4 container, optionally embedding container metadata and cover art in a single FFmpeg pass.
`write_metadata_tags`| `(file_path: Path | str, data: Any, thumbnail: bytes | Path | str | None = None, *, ffmpeg_bin: Path | str | None = None, timeout: int = 180) -> bool`| Atomically writes MP4 metadata tags and optional cover art to an existing MP4 file via FFmpeg stream copy.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
