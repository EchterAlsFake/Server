import uuid
from unittest.mock import patch
import httpx
from _support import ServerTestCase, main
from license_fixtures import POLICY, issuance
from pf_server import keygen_service, licensing
from pf_server.models import License

class KeygenTests(ServerTestCase):
    def test_create_reconciles_same_uuid_after_conflict(self):
        identity = str(uuid.uuid4())
        with main.app.app_context(), patch.dict(main.app.config, {"KEYGEN_POLICY_ID": POLICY}), patch.object(
            keygen_service, "request", side_effect=[
                httpx.Response(404), httpx.Response(422), httpx.Response(200,json={"data": issuance(identity)})
            ]) as request:
            result = keygen_service.ensure_license(identity)
            self.assertEqual(result["id"], identity)
            self.assertEqual(request.call_args_list[1].kwargs["json"]["data"]["id"], identity)

    def test_timeout_retries_same_persisted_identity(self):
        self.keygen_mock.stop()
        with main.app.app_context():
            record = licensing.get_or_create_license("synthetic-purchase")
            with patch.object(licensing, "ensure_license", side_effect=keygen_service.KeygenUnavailable("unavailable")):
                with self.assertRaises(keygen_service.KeygenUnavailable):
                    licensing.build_license_file(record.license_key, record.issuance_reference, record.created_at)
            identity = record.keygen_id
            with patch.object(licensing, "ensure_license", side_effect=issuance) as request:
                first = licensing.build_license_file(record.license_key, record.issuance_reference, record.created_at)
                second = licensing.build_license_file(record.license_key, record.issuance_reference, record.created_at)
                request.assert_called_once_with(identity)
                self.assertEqual(first, second)
                self.assertNotIn(b"synthetic-purchase", first)
            self.assertEqual(License.query.count(), 1)

    def test_old_validation_endpoint_is_retired(self):
        self.assertEqual(self.client.post("/check_license", json={"license_key": "old"}).status_code, 410)
