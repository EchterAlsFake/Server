---
title: "Download configuration — eaf_base_api"
summary: "Explains the documented download configuration and download procedure for the eaf_base_api API."
public_url: "https://docs.echteralsfake.me/eaf_base_api/"
aliases:
  - "base API Download configuration"
  - "eaf base Download configuration"
keywords:
  - "eaf_base_api"
  - "base_api"
  - "Download configuration"
  - "DownloadConfigHLS"
  - "DownloadConfigRAW"
  - "m3u8_base_url"
  - "remux"
  - "start_segment"
  - "segment_state_path"
  - "segment_dir"
  - "return_report"
  - "cleanup_on_stop"
  - "keep_segment_dir"
  - "callback_remux"
  - "ios_support"
  - "metadata"
  - "thumbnail"
  - "metadata_written"
---

# Download configuration — eaf_base_api

Explains the documented download configuration and download procedure for the eaf_base_api API.

## Shared fields

`DownloadConfigHLS` and `DownloadConfigRAW` share `quality`, `path`, `callback`, `no_title`, `stop_event`, and `metadata_written`. Quality accepts a supported integer height or `"best"`, `"half"`, `"worst"`, and common `"720p"`-style values. Version 4.1 normalizes landscape and portrait variants by their shorter dimension, chooses the closest available tier for an explicit numeric request (preferring the higher tier on a tie), and uses bandwidth and frame rate as fallbacks when a master playlist omits resolution metadata.

## HLS inspection

`await core.list_available_qualities(m3u8_url)` returns sorted, unique integer tiers from a master playlist. `await core.get_m3u8_by_quality(m3u8_url, quality)` returns the selected media-playlist URL. Both methods accept a playlist URL, inline master text, or a callable/awaitable resolving to either form. Relative variant paths can be resolved only when the master was fetched from a URL; an inline master must contain absolute variant URLs.

## DownloadConfigHLS

## m3u8_base_url

Default: None; Description: Master playlist URL, awaitable, or callable used by BaseCore.download

## remux

Default: False; Description: Remux concatenated transport stream to MP4 using FFmpeg (`ffmpeg` on `PATH` or `RuntimeConfig.ffmpeg_path`). If `ffmpeg` is missing, logs a warning and preserves the raw MPEG-TS stream cleanly.

## metadata

Default: None; Description: Optional provider `Video` object or `dict` of MP4 metadata tags (`title`, `author`, `genre`/`tags`, `date`/`publish_date`, `description`, `url`, `comment`, `network`) written in a single FFmpeg pass when remuxing.

## thumbnail

Default: None; Description: Optional cover-art image (`bytes`, `str`, or `Path`) embedded as an attached picture stream during the single-pass FFmpeg remux.

## metadata_written

Default: False; Description: Output flag set to `True` on `DownloadConfigHLS` and `DownloadReport` when single-pass metadata/cover-art tagging succeeded during remuxing.

## start_segment

Default: 0; Description: First segment index

## segment_state_path

Default: None; Description: JSON resume-state file; Path values are serialized safely in 4.1+

## segment_dir

Default: None; Description: Directory for downloaded segments

## return_report

Default: False; Description: Return a DownloadReport instead of only a boolean

## cleanup_on_stop

Default: True; Description: Remove temporary state when cancelled

## keep_segment_dir

Default: False; Description: Retain segment files after completion

## callback_remux

Default: None; Description: Progress callback for remuxing

## ios_support

Default: False; Description: Enable the iOS-compatible remux path (`-bsf:a aac_adtstoasc -movflags +faststart`)

`BaseCore.download()` reads `RuntimeConfig.timeout`, `RuntimeConfig.max_workers_download`, and `RuntimeConfig.ffmpeg_path` from that core when dispatching each HLS download. Dedicated cores therefore keep their HLS timeout, worker, and FFmpeg settings isolated from the process-wide default configuration. HLS cancellation uses an `asyncio.Event`: setting it cancels pending segment tasks promptly, and progress/remux callbacks are synchronized across worker threads. When `remux=True` and `metadata` or `thumbnail` are provided, `eaf_base_api` writes container metadata and cover art in the same FFmpeg remux pass—avoiding a second full-file rewrite—and sets `configuration.metadata_written = True` (and `DownloadReport.metadata_written = True`). If cover/tag arguments fail, it automatically falls back to a clean remux so the downloaded video is never lost.

## DownloadConfigRAW

Direct-file downloads add `allow_multipart=True`, `max_workers=5`, `read_timeout=120.0`, `chunk_size=1024`, and `max_retries=5`. These downloader retries are separate from `RuntimeConfig.request_attempts`.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
