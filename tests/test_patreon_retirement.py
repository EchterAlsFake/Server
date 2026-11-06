"""Membership retirement leaves Shop activation and historical data available."""
import tempfile
from pathlib import Path
from unittest.mock import patch
from sqlalchemy import text
from _support import ServerTestCase, main


class PatreonRetirementTests(ServerTestCase):
    def test_membership_callback_is_unregistered_and_cannot_issue_licenses(self):
        self.assertNotIn('/patreon-webhook', {r.rule for r in main.app.url_map.iter_rules()})
        for host in ('https://api.echteralsfake.me', 'https://echteralsfake.me'):
            response = self.client.post('/patreon-webhook', base_url=host,
                json={'data': {'type': 'member', 'id': 'retired-member'}},
                headers={'X-Patreon-Signature': '0' * 32, 'X-Patreon-Event': 'members:update'})
            self.assertEqual(response.status_code, 404)
        with patch.dict(main.app.config, PATREON_SHOP_ENABLED=True):
            self.assertEqual(self.client.get('/activate').status_code, 200)
        for setting in ('PATREON_SECRET', 'PATREON_LICENSE_TIER_IDS', 'PATREON_PAYMENTS_ENABLED'):
            self.assertNotIn(setting, main.app.config)

    def test_migration_check_preserves_retired_delivery_records(self):
        with tempfile.TemporaryDirectory() as directory:
            app = main.create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + str(Path(directory) / 'archive.db')})
            runner = app.test_cli_runner()
            result = runner.invoke(args=['db', 'upgrade'])
            self.assertEqual(result.exit_code, 0, result.output)
            with app.app_context():
                self.assertNotIn('patreon_license_deliveries', main.db.metadata.tables)
                main.db.session.execute(text("INSERT INTO patreon_license_deliveries (member_id, status, created_at, updated_at) VALUES ('historical-member', 'sent', '2026-01-01', '2026-01-01')"))
                main.db.session.commit()
            result = runner.invoke(args=['db', 'check'])
            self.assertEqual(result.exit_code, 0, result.output)
            with app.app_context():
                self.assertEqual(main.db.session.execute(text('SELECT member_id FROM patreon_license_deliveries')).scalar_one(), 'historical-member')
