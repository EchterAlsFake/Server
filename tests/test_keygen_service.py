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
                httpx.Response(404), httpx.Response(200, json={"data": {"id": POLICY, "attributes": keygen_service.ANNUAL_POLICY_ATTRIBUTES}}), httpx.Response(422), httpx.Response(200,json={"data": issuance(identity)})
            ]) as request:
            result = keygen_service.ensure_license(identity)
            self.assertEqual(result["id"], identity)
            self.assertEqual(request.call_args_list[2].kwargs["json"]["data"]["id"], identity)

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
                request.assert_called_once_with(identity, test=False)
                self.assertEqual(first, second)
                self.assertNotIn(b"synthetic-purchase", first)
            self.assertEqual(License.query.count(), 1)

    def test_old_validation_endpoint_is_retired(self):
        self.assertEqual(self.client.post("/check_license", json={"license_key": "old"}).status_code, 410)

    def test_annual_policy_is_verified_without_modifying_existing_policies(self):
        with main.app.app_context(), patch.dict(main.app.config, {"KEYGEN_POLICY_ID": POLICY}):
            for changes in ({"duration": None}, {"expirationBasis": "FROM_CREATION"}, {"expirationStrategy": "RESTRICT_ACCESS"}, {"maxMachines": 1}):
                with self.subTest(changes=changes), patch.object(keygen_service, "request", side_effect=[
                    httpx.Response(404), httpx.Response(200, json={"data": {"id": POLICY, "attributes": keygen_service.ANNUAL_POLICY_ATTRIBUTES | changes}})
                ]) as remote:
                    with self.assertRaises(keygen_service.KeygenUnavailable):
                        keygen_service.ensure_license(str(uuid.uuid4()))
                    self.assertEqual([call.args[0] for call in remote.call_args_list], ["GET", "GET"])
            with patch.object(keygen_service, "request", return_value=httpx.Response(200, json={"data": {"id": POLICY, "attributes": keygen_service.ANNUAL_POLICY_ATTRIBUTES}})) as remote:
                self.assertEqual(keygen_service.verify_annual_policy()["attributes"]["expirationStrategy"], "MAINTAIN_ACCESS")
                remote.assert_called_once_with("GET", "/policies/" + POLICY)

    def test_read_only_cli_requires_matching_shipped_client_policy(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory, patch.dict(main.app.config, {"KEYGEN_POLICY_ID": POLICY}):
            public = Path(directory) / 'production.json'
            public.write_text(json.dumps({'policy_id': POLICY}))
            with patch.object(keygen_service, 'verify_annual_policy') as verify:
                result = main.app.test_cli_runner().invoke(args=['verify-license-policy', '--client-config', str(public)])
                self.assertEqual(result.exit_code, 0, result.output)
                verify.assert_called_once_with()
            public.write_text(json.dumps({'policy_id': 'different-policy'}))
            with patch.object(keygen_service, 'verify_annual_policy') as verify:
                result = main.app.test_cli_runner().invoke(args=['verify-license-policy', '--client-config', str(public)])
                self.assertNotEqual(result.exit_code, 0)
                verify.assert_not_called()
