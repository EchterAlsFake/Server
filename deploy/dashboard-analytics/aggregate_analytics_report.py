"""Read only the suppressed export, never analytics or purchase databases."""
import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path


class ReportUnavailable(ValueError):
    pass


def read_report(path: Path, weeks: int = 4):
    if type(weeks) is not int or not 1 <= weeks <= 57:
        raise ReportUnavailable("Invalid reporting period")
    try:
        with path.open('rb') as source:
            raw = source.read(3 * 1024 * 1024 + 1)
        if len(raw) > 3 * 1024 * 1024:
            raise ValueError()
        report = json.loads(raw)
        updated = date.fromisoformat(report['updated_day'])
        end = date.fromisoformat(report['end_exclusive'])
        today = datetime.now(timezone.utc).date()
        if (end.weekday() != 0 or end > today or updated > today
                or type(report['enabled']) is not bool or report['minimum_count'] != 20):
            raise ValueError()
        start = end - timedelta(weeks=weeks)
        rows = []
        seen = set()
        for row in report['rows']:
            week = date.fromisoformat(row['week'])
            page, action, count = row['page'], row['action'], row['count']
            if (week.weekday() != 0 or week >= end or type(count) is not int or count < 20
                    or not isinstance(page, str) or not re.fullmatch(r'[a-z0-9_-]{1,64}', page)
                    or not isinstance(action, str) or not re.fullmatch(r'[a-z0-9_]{1,40}', action)):
                raise ValueError()
            key = (row['week'], page, action)
            if key in seen:
                raise ValueError()
            seen.add(key)
            if week >= start:
                rows.append(dict(week=row['week'], page=page, action=action, count=count))
        return dict(start=start.isoformat(), end_exclusive=end.isoformat(),
                    updated_day=updated.isoformat(), enabled=report['enabled'],
                    stale=(today - updated).days > 1, timezone='UTC', minimum_count=20,
                    rows=sorted(rows, key=lambda row: (row['week'], row['page'], row['action'])))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ReportUnavailable("Aggregate analytics report unavailable") from None
