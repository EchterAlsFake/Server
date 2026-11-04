"""Offline migration of update-traffic.db; preserves totals, removes visitor identifiers.

Stop the collector and back up the database first. Run only against the update
statistics database, never the dashboard, licensing or application database.
"""
from contextlib import closing
import argparse
import sqlite3
from pathlib import Path


def migrate(path: Path) -> bool:
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='traffic'").fetchone():
            return False
        columns = {row[1] for row in db.execute("PRAGMA table_info(traffic)")}
        if columns != {"source", "path", "visitor", "day", "requests", "ranges", "bytes"}:
            raise ValueError("Unexpected traffic schema; no changes made")
        db.execute("PRAGMA secure_delete=ON")
        db.execute("CREATE TABLE IF NOT EXISTS download_daily (source TEXT, path TEXT, day TEXT, requests INTEGER, ranges INTEGER, bytes INTEGER, PRIMARY KEY(source,path,day))")
        db.execute("""INSERT INTO download_daily
            SELECT source,path,day,SUM(requests),SUM(ranges),SUM(bytes) FROM traffic
            WHERE 1 GROUP BY source,path,day
            ON CONFLICT(source,path,day) DO UPDATE SET
                requests=requests+excluded.requests,
                ranges=ranges+excluded.ranges,
                bytes=bytes+excluded.bytes""")
        db.execute("DROP TABLE traffic")
        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.execute("VACUUM")
    # Filesystem snapshots, backups and SSD remnants require separate handling.
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    print("Migrated" if migrate(args.database) else "No legacy traffic table; nothing changed")
