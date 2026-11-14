"""Read only the suppressed export, never analytics or purchase databases."""
import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path


class ReportUnavailable(ValueError):
    pass


def read_legacy_report(path: Path, weeks: int = 4):
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


def read_report(path: Path, weeks: int = 4, *, days=None):
    """Validate a bounded daily snapshot; tolerate the old exporter during rollout."""
    if days is not None and (type(days) is not int or not 1 <= days <= 90):
        raise ReportUnavailable("Invalid reporting period")
    if type(weeks) is not int or not 1 <= weeks <= 57:
        raise ReportUnavailable("Invalid reporting period")
    days = days if days is not None else min(90, weeks * 7)
    try:
        with path.open('rb') as source:
            raw = source.read(3 * 1024 * 1024 + 1)
        if len(raw) > 3 * 1024 * 1024:
            raise ValueError()
        report = json.loads(raw)
        if report.get('schema_version') != 2:
            result = read_legacy_report(path, min(57, (days + 6) // 7))
            result.update(grain='week', legacy=True, countries=[])
            return result
        now = datetime.now(timezone.utc)
        generated = datetime.fromisoformat(report['generated_at'])
        if generated.tzinfo is None or generated > now + timedelta(minutes=5):
            raise ValueError()
        end = date.fromisoformat(report['end_exclusive'])
        source_start = date.fromisoformat(report['start'])
        if (end > now.date() + timedelta(days=1) or source_start >= end
                or (end-source_start).days > 90 or report['minimum_count'] != 20
                or type(report['enabled']) is not bool or report['grain'] != 'day'):
            raise ValueError()
        start = max(source_start, end - timedelta(days=days))
        rows, countries, seen = [], [], set()
        for field in ('rows','countries'):
            for row in report[field]:
                day = date.fromisoformat(row['day'])
                count = row['count']
                if not source_start <= day < end or type(count) is not int or not 20 <= count <= 2**63-1:
                    raise ValueError()
                if field == 'rows':
                    page, action = row['page'], row['action']
                    if not re.fullmatch(r'[a-z0-9_-]{1,64}',page) or not re.fullmatch(r'[a-z0-9_]{1,64}',action):
                        raise ValueError()
                    clean = dict(day=day.isoformat(),page=page,action=action,count=count)
                    key = (field,day,page,action)
                else:
                    country = row['country']
                    if not re.fullmatch(r'[A-Z]{2}',country):
                        raise ValueError()
                    clean = dict(day=day.isoformat(),country=country,count=count)
                    key = (field,day,country)
                if key in seen:
                    raise ValueError()
                seen.add(key)
                if day >= start:
                    (rows if field == 'rows' else countries).append(clean)
        return dict(schema_version=2,grain='day',legacy=False,start=start.isoformat(),end_exclusive=end.isoformat(),
                    generated_at=generated.isoformat(),updated_day=generated.date().isoformat(),enabled=report['enabled'],
                    stale=(now-generated).total_seconds()>180,timezone='UTC',minimum_count=20,
                    current_day_partial=True,rows=rows,countries=countries)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,OverflowError):
        raise ReportUnavailable("Aggregate analytics report unavailable") from None
