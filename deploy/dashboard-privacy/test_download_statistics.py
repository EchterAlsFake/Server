"""Test the migration and patched importer using synthetic logs and databases.

UPDATE_ADMIN_CANDIDATE=/path/to/patched/update_admin.py python -m unittest discover \
    -s deploy/dashboard-privacy -p test_download_statistics.py
"""
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = load_module('statistics_migration', Path(__file__).with_name('migrate_download_statistics.py'))


class DownloadPrivacyTests(unittest.TestCase):
    def test_migration_preserves_totals_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'update-traffic.db'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE traffic (source TEXT, path TEXT, visitor TEXT, day TEXT, requests INTEGER, ranges INTEGER, bytes INTEGER, PRIMARY KEY(source,path,visitor,day))')
                db.executemany('INSERT INTO traffic VALUES (?,?,?,?,?,?,?)', [
                    ('website', '/downloads/a.zip', 'test-person-a', '2026-10-31', 2, 1, 100),
                    ('website', '/downloads/a.zip', 'test-person-b', '2026-10-31', 3, 0, 200),
                    ('website', '/downloads/a.zip', 'test-person-a', '2026-11-01', 1, 0, 50),
                ])
                db.execute('CREATE TABLE cursor (inode INTEGER PRIMARY KEY, offset INTEGER)')
                db.execute('INSERT INTO cursor VALUES (42, 100)')
            self.assertTrue(migration.migrate(path))
            self.assertFalse(migration.migrate(path))
            with closing(sqlite3.connect(path)) as db, db:
                self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='traffic'").fetchone())
                self.assertEqual(db.execute('SELECT SUM(requests),SUM(ranges),SUM(bytes) FROM download_daily').fetchone(), (6, 1, 350))
                self.assertEqual(db.execute('SELECT COUNT(*) FROM download_daily').fetchone()[0], 2)
                self.assertEqual(db.execute('SELECT * FROM cursor').fetchall(), [(42, 100)])
                self.assertNotIn('visitor', [row[1] for row in db.execute('PRAGMA table_info(download_daily)')])
            self.assertNotIn(b'test-person-', path.read_bytes())

    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'missing.db'
            with self.assertRaises(sqlite3.OperationalError):
                migration.migrate(path)
            self.assertFalse(path.exists())

    def test_unexpected_schema_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrong.db'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE traffic (unexpected TEXT)')
                db.execute("INSERT INTO traffic VALUES ('keep')")
            with self.assertRaises(ValueError):
                migration.migrate(path)
            with closing(sqlite3.connect(path)) as db, db:
                self.assertEqual(db.execute('SELECT * FROM traffic').fetchall(), [('keep',)])

    @unittest.skipUnless(os.environ.get('UPDATE_ADMIN_CANDIDATE'), 'Set UPDATE_ADMIN_CANDIDATE to test the patched importer')
    def test_import_without_identifiers_keeps_counts_and_cursor(self):
        module = load_module('test_update_admin', Path(os.environ['UPDATE_ADMIN_CANDIDATE']))
        with tempfile.TemporaryDirectory() as directory:
            module.STATE = Path(directory) / 'state'
            module.LOG = Path(directory) / 'update-downloads.json'
            def event(status=200, size=100, path='/downloads/a.zip', **request):
                return dict(ts=1793491200, status=status, size=size,
                            request=dict(host='pornfetch.to', method='GET', uri=path, **request))
            events = [event(), event(status=206, size=50),
                      event(size=25, client_ip='legacy-check-value', remote_ip='legacy-check-value'),
                      event(path='/downloads/manifest.json'), event(status=404), event(size=0)]
            module.LOG.write_text(''.join(json.dumps(item) + '\n' for item in events))
            module.collect()
            module.collect()  # Must not count the same file twice.
            stats = module.stats()
            self.assertEqual(len(stats['items']), 1)
            self.assertEqual(stats['items'][0]['requests'], 3)
            self.assertEqual(stats['items'][0]['ranges'], 1)
            self.assertEqual(stats['items'][0]['bytes'], 175)
            self.assertIsNone(stats['items'][0]['downloaders'])
            database = module.STATE / 'update-traffic.db'
            with closing(sqlite3.connect(database)) as db, db:
                self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='traffic'").fetchone())
            self.assertNotIn(b'legacy-check-value', database.read_bytes())


if __name__ == '__main__':
    unittest.main()
