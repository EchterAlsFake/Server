# Website Analytics

Website Analytics counts successful, allowlisted public HTML requests and
voluntary fixed-choice feedback. Counts include direct navigation and repeated
requests. Closed weeks use Monday boundaries in UTC. Google Search Console
uses Pacific dates and reports search activity separately.

The website does not send analytics beacons or set analytics storage. The
collector persists only day, fixed page or answer code and count. Payment,
activation, file delivery and operational monitoring have separate systems.
GPC and DNT signals suppress collection. The reporting store is kept for 26
completed weeks plus the current week. A closed series-week with a positive
daily count below 20 may publish its weekly count, but every daily count for
that series-week is withheld. Weekly counts below 20 are withheld entirely.

## Deployment and privacy review

The previous browser endpoints are retired. Historical aggregate exports can be
viewed separately in the private dashboard. The dashboard drops the former
visitor-key table from its live database. Existing backups follow their own
retention rules.

The new collector is disabled by default, even if the old analytics variable
is enabled. Before setting `WEBSITE_REQUEST_ANALYTICS_ENABLED=true`, confirm
the implementation-specific §25 TDDDG assessment and any applicable GDPR
basis, including feedback, with the operator's privacy reviewer. Verify the
German and English notices, the VPS and Pixel proxy logs, and any application or
crash logs. Identify ordinary transport and operational processing separately
from the statistics store. Test a synthetic browser request with fresh and
existing sessions. The origin should receive no browser analytics beacons.
Confirm that active production Caddy config returns HTTP 410 for the retired
paths and skips access logging for the feedback endpoint. No settings for the
old collector should be carried forward.

The existing `pornfetch-analytics.timer` calls `analytics-export` on the Pixel.
The new export is `website-request-analytics-report.json`. The old
`aggregate-analytics-report.json` is retained as a frozen archive. Install the
updated broker report reader alongside the updated dashboard service. Switching
off the new flag stops collection and preserves completed historical totals.

## Weekly review bundle

Run this on Thursday or later so the previous Google week has time to settle.

```sh
python -m flask --app main analytics-weekly --output /private/weekly-analytics
```

The command writes private files `summary.md` and `analytics.json`. An optional
`--changes` JSON file accepts objects with `date` (YYYY-MM-DD) and `note`
fields. Record public changes such as a clearer guide CTA or download layout.

To fetch Search Console data directly, supply a current OAuth access token for
the verified `sc-domain:pornfetch.to` property through `--search-token-file`
or `WEBSITE_SEARCH_CONSOLE_TOKEN_FILE`. Use only Google's
`https://www.googleapis.com/auth/webmasters.readonly` scope. Store the token
in a private file. An expired token yields a clearly labeled website-only
bundle. A scheduled deployment can instead set
`WEBSITE_SEARCH_CONSOLE_OAUTH_FILE` to a private JSON file with
`client_id`, `client_secret`, and a refresh token issued for the read-only
scope. The command refreshes the short-lived access token in memory.

Alternatively supply `--search-csv` with settled Search Console rows for the
two weeks in one normalized CSV. Use `week,dimension,value,clicks,impressions,position`.
`week` is the Monday start date, and the permitted dimensions are `page`,
`device`, `country`, and `query_theme`. Use canonical public URLs for pages,
Google's device and country codes, and themes from `installation`,
`compatibility`, `product_name`, `download`, or `other`. Supply separate
dimension reports. Google may omit queries or top-row-limited results.

Review both files before sharing them with an AI agent. The prompt should
ask for ranked hypotheses and measurable follow-ups, grounded in the reported
counts, release annotations, and coverage limits.

The optional `pf-website-analytics-weekly.timer` writes the latest private bundle
to the website container data volume. Enable it after the privacy review and
configure Google reporting separately if credentials are available.
