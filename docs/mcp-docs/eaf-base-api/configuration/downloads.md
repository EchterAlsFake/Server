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
---

# Download configuration — eaf_base_api

Explains the documented download configuration and download procedure for the eaf_base_api API.

## Shared fields

`DownloadConfigHLS` and `DownloadConfigRAW` share `quality`, `path`, `callback`, `no_title`, and `stop_event`. Quality accepts a supported integer height or `"best"`, `"half"`, `"worst"`, and common `"720p"`-style values. Version 4.1 normalizes landscape and portrait variants by their shorter dimension, chooses the closest available tier for an explicit numeric request (preferring the higher tier on a tie), and uses bandwidth and frame rate as fallbacks when a master playlist omits resolution metadata.

## HLS inspection

`await core.list_available_qualities(m3u8_url)` returns sorted, unique integer tiers from a master playlist. `await core.get_m3u8_by_quality(m3u8_url, quality)` returns the selected media-playlist URL. Both methods accept a playlist URL, inline master text, or a callable/awaitable resolving to either form. Relative variant paths can be resolved only when the master was fetched from a URL; an inline master must contain absolute variant URLs.

## DownloadConfigHLS

## m3u8_base_url

Default: None; Description: Master playlist URL, awaitable, or callable used by BaseCore.download

## remux

Default: False; Description: Remux concatenated transport stream to MP4

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

Default: False; Description: Enable the iOS-compatible remux path

`BaseCore.download()` reads `RuntimeConfig.timeout` and `RuntimeConfig.max_workers_download` from that core when dispatching each HLS download. Dedicated cores therefore keep their HLS timeout and worker settings isolated from the process-wide default configuration. HLS cancellation uses an `asyncio.Event`: setting it cancels pending segment tasks promptly, and progress/remux callbacks are synchronized across worker threads. Version 4.1.1 also normalizes discontinuous packet timestamps while remuxing so valid HLS discontinuities do not abort MP4 output.

## DownloadConfigRAW

Direct-file downloads add `allow_multipart=True`, `max_workers=5`, `read_timeout=120.0`, `chunk_size=1024`, and `max_retries=5`. These downloader retries are separate from `RuntimeConfig.request_attempts`.

## Related MCP documents

- [Overview — eaf_base_api](../overview.md)
- [Error reference — eaf_base_api](../troubleshooting/errors.md)
- [EAF Python API documentation overview](../../overview.md)

## Original public page

- [https://docs.echteralsfake.me/eaf_base_api/](https://docs.echteralsfake.me/eaf_base_api/)
