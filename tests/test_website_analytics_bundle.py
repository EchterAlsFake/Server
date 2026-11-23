import json
from datetime import date
from unittest.mock import patch

from pf_server.website_analytics_bundle import build_bundle, fetch_search, canonical_page, import_search


def test_search_console_query_text_is_not_exported():
    class Source:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def rows(client, start, end, dimension):
        values = {
            "date": "2026-11-15",
            "query": "private@example.invalid download",
            "page": "https://pornfetch.to/de/download?test=private",
            "device": "MOBILE",
            "country": "deu",
        }
        return [{"keys": [values[dimension]], "clicks": 12, "impressions": 90, "position": 7.2}]

    weeks = ["2026-11-09"]
    with patch("pf_server.website_analytics_bundle.httpx.Client", return_value=Source()), patch(
            "pf_server.website_analytics_bundle.gsc_rows", side_effect=rows):
        exported = fetch_search(weeks, "mock-token")
    assert exported[weeks[0]]["status"] == "available"
    assert "private" not in json.dumps(exported)
    assert {row["value"] for row in exported[weeks[0]]["rows"]} == {"/download", "download", "DEU", "MOBILE"}
    assert canonical_page("https://other.invalid/download") is None


def test_bundle_never_turns_suppression_into_zero(tmp_path):
    source = tmp_path / "search.csv"
    source.write_text("week,dimension,value,clicks,impressions,position\n"
                      "2026-11-16,page,https://pornfetch.to/download,5,50,4\n")
    weeks = ["2026-11-09", "2026-11-16"]
    search = import_search(weeks, source)
    report = dict(end_exclusive="2026-11-23", generated_at="2026-11-23T12:00:00Z", cutover="2026-11-01",
                  enabled=True, minimum_count=20, series=[dict(id="download", path="/download")],
                  weekly=[dict(week=weeks[1], series="download", count=26)])
    bundle = build_bundle(report, search, [])
    row = bundle["website"]["series"][0]
    assert row["previous"] is row["delta"] is None
    assert row["current"] == 26
    assert search[weeks[0]]["status"] == "unavailable"
    assert date.fromisoformat(bundle["weeks"][1]).weekday() == 0
