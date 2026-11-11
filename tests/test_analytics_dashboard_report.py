"""The broker receives only the bounded, suppressed export."""
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location('analytics_export_reader', Path(__file__).parents[1] / 'deploy/dashboard-analytics/aggregate_analytics_report.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class DashboardReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'report.json'
        today = datetime.now(timezone.utc).date()
        end = today - timedelta(days=today.weekday())
        self.end = end
        self.report = dict(updated_day=today.isoformat(), end_exclusive=end.isoformat(), enabled=True,
                           minimum_count=20, rows=[dict(week=(end - timedelta(weeks=1)).isoformat(),
                           page='guide_xvideos', action='pageview', count=25, email='private@example.org')],
                           token='private-token')

    def read(self, weeks=4):
        self.path.write_text(json.dumps(self.report))
        return reader.read_report(self.path, weeks)

    def test_bounded_report_drops_extra_fields(self):
        result = self.read()
        self.assertEqual(result['rows'][0]['count'], 25)
        self.assertNotIn('private', json.dumps(result))
        self.assertFalse(result['stale'])
        self.assertEqual(result['timezone'], 'UTC')
        self.report['rows'][0]['week'] = (self.end - timedelta(weeks=5)).isoformat()
        self.assertEqual(self.read()['rows'], [])

    def test_sparse_current_and_duplicate_cells_fail_closed(self):
        for count in (19, True, '25'):
            self.report['rows'][0]['count'] = count
            with self.assertRaises(reader.ReportUnavailable):
                self.read()
        self.report['rows'][0]['count'] = 25
        self.report['rows'][0]['week'] = self.end.isoformat()
        with self.assertRaises(reader.ReportUnavailable):
            self.read()
        self.report['rows'][0]['week'] = (self.end - timedelta(weeks=1)).isoformat()
        self.report['rows'] *= 2
        with self.assertRaises(reader.ReportUnavailable):
            self.read()

    def test_missing_malformed_or_invalid_window_never_returns_zero(self):
        with self.assertRaises(reader.ReportUnavailable):
            reader.read_report(self.path)
        self.path.write_text('invalid json')
        with self.assertRaises(reader.ReportUnavailable):
            reader.read_report(self.path)
        for weeks in (0, 58, True, '4'):
            with self.assertRaises(reader.ReportUnavailable):
                self.read(weeks)
