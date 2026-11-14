"""Report boundary checks use synthetic counters only."""
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location('analytics_report', Path(__file__).parents[1] / 'deploy/dashboard-analytics/aggregate_analytics_report.py')
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)


class DailyReportTests(unittest.TestCase):
    def test_daily_snapshot_and_staleness(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.json'
            now=datetime.now(timezone.utc)
            day=now.date().isoformat()
            report=dict(schema_version=2,grain='day',start=day,end_exclusive=(now.date()+timedelta(days=1)).isoformat(),
                        generated_at=now.isoformat(),enabled=True,minimum_count=20,
                        rows=[dict(day=day,page='premium',action='feedback_price',count=20)],
                        countries=[dict(day=day,country='IN',count=30)])
            path.write_text(json.dumps(report))
            result=reporter.read_report(path,days=7)
            self.assertFalse(result['stale']);self.assertFalse(result['legacy'])
            self.assertEqual(result['rows'],report['rows'])
            report['generated_at']=(now-timedelta(minutes=4)).isoformat()
            path.write_text(json.dumps(report))
            self.assertTrue(reporter.read_report(path,days=7)['stale'])
            report['rows'][0]['count']=1
            path.write_text(json.dumps(report))
            with self.assertRaises(reporter.ReportUnavailable):reporter.read_report(path)

    def test_old_weekly_export_remains_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.json'
            now=datetime.now(timezone.utc).date();end=now-timedelta(days=now.weekday())
            path.write_text(json.dumps(dict(start=(end-timedelta(weeks=4)).isoformat(),end_exclusive=end.isoformat(),
                updated_day=now.isoformat(),enabled=True,minimum_count=20,rows=[])))
            self.assertTrue(reporter.read_report(path,days=28)['legacy'])

    def test_invalid_window_rejected(self):
        for value in (0,91,True,'7'):
            with self.assertRaises(reporter.ReportUnavailable):reporter.read_report(Path('unused'),days=value)
