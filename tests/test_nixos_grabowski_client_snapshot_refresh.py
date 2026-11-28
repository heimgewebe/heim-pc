"""NixOS Grabowski signed connector snapshot adapter regressions."""
from __future__ import annotations

from contextlib import nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "nixos/system/modules/grabowski-client-snapshot-refresh.py"
)


def load_module():
    fake = types.ModuleType("grabowski_client_snapshot")
    fake.connector_session_id = MagicMock(return_value="tunnel-session-pinned")
    fake._observer_session_state = MagicMock(return_value=("tunnel-session-pinned", False))
    fake._snapshot_refresh_reason = MagicMock(return_value=None)
    fake._write_observer_state = MagicMock()
    fake._read_transport_connector_capability = MagicMock(return_value="private-test-capability")
    fake._observe_and_bind_snapshot = MagicMock()
    fake._state_lock = nullcontext
    fake._read_private_json = MagicMock(side_effect=FileNotFoundError())
    fake._validate_receipt = MagicMock()
    fake.SNAPSHOT_PATH = Path("/nonexistent/snapshot")
    fake.AUTO_REFRESH_CLIENT_ID = "grabowski-tunnel-watchdog-observer-v1"
    fake.ClientSnapshotError = type("ClientSnapshotError", (ValueError,), {})
    fake.AUTO_REFRESH_CONNECTOR_TOKEN_PATH = Path("/nonexistent/test-token")
    fake.AUTO_REFRESH_MCP_URL = "http://127.0.0.1:18181/mcp"
    spec = importlib.util.spec_from_file_location("nixos_grabowski_snapshot_adapter", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"grabowski_client_snapshot": fake}):
        spec.loader.exec_module(module)
    return module, fake


async def successful_observer(**kwargs):
    return {
        "state": "renewed", "release_id": "release-expected",
        "schema_contract_matches": True, "tool_count": 207,
        "receipt_sha256": "a" * 64,
    }


class NixOSGrabowskiSnapshotRefreshTests(unittest.TestCase):
    def test_not_due_preserves_valid_observation_without_mcp_mutation(self):
        module, fake = load_module()
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            result = module.refresh("release-expected", now_unix=1700000000)
        self.assertEqual(result, {"state": "not_due"})
        fake._observe_and_bind_snapshot.assert_not_called()
        fake._write_observer_state.assert_not_called()

    def test_expired_snapshot_renews_with_fresh_real_mcp_session(self):
        module, fake = load_module()
        fake._snapshot_refresh_reason.return_value = "renewal-window"
        fake._observe_and_bind_snapshot.side_effect = successful_observer
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            result = module.refresh("release-expected", now_unix=1700000000)
        self.assertEqual(result["state"], "renewed")
        self.assertEqual(result["receipt_sha256"], "a" * 64)
        self.assertEqual(
            fake._observe_and_bind_snapshot.call_args.kwargs["session_id"],
            "tunnel-session-pinned-observation-1700000000",
        )
        fake._write_observer_state.assert_called_once_with(
            session_id="tunnel-session-pinned",
            release_id="release-expected",
            now_unix=1700000000,
        )

    def test_same_tunnel_fresh_receipt_is_not_rebound_every_two_minutes(self):
        module, fake = load_module()
        fake._read_private_json.side_effect = None
        fake._read_private_json.return_value = {
            "client_declaration": {
                "client_id": fake.AUTO_REFRESH_CLIENT_ID,
                "session_id": "tunnel-session-pinned-observation-1700000000",
            }
        }
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            result = module.refresh("release-expected", now_unix=1700000100)
        self.assertEqual(result, {"state": "not_due"})
        self.assertEqual(
            fake._snapshot_refresh_reason.call_args.kwargs["session_id"],
            "tunnel-session-pinned-observation-1700000000",
        )
        fake._observe_and_bind_snapshot.assert_not_called()

    def test_tunnel_replacement_forces_fresh_observation_even_if_receipt_fresh(self):
        module, fake = load_module()
        fake._observer_session_state.return_value = ("old-tunnel-epoch", False)
        fake._snapshot_refresh_reason.return_value = None
        fake._observe_and_bind_snapshot.side_effect = successful_observer
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            result = module.refresh("release-expected", now_unix=1700000200)
        self.assertEqual(result["reason"], "connector-session-changed")
        self.assertEqual(result["state"], "renewed")
        self.assertEqual(
            fake._observe_and_bind_snapshot.call_args.kwargs["session_id"],
            "tunnel-session-pinned-observation-1700000200",
        )

    def test_unknown_or_foreign_receipt_session_never_claims_current_tunnel(self):
        module, fake = load_module()
        fake._read_private_json.side_effect = None
        fake._read_private_json.return_value = {
            "client_declaration": {
                "client_id": fake.AUTO_REFRESH_CLIENT_ID,
                "session_id": "foreign-tunnel-observation-1700000000",
            }
        }
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            module.refresh("release-expected", now_unix=1700000100)
        self.assertEqual(
            fake._snapshot_refresh_reason.call_args.kwargs["session_id"],
            "tunnel-session-pinned",
        )

    def test_same_observation_session_packet_is_not_repeated(self):
        module, fake = load_module()
        fake._read_private_json.side_effect = None
        fake._read_private_json.return_value = {
            "client_declaration": {
                "client_id": fake.AUTO_REFRESH_CLIENT_ID,
                "session_id": "tunnel-session-pinned-observation-1700000000",
            }
        }
        fake._snapshot_refresh_reason.return_value = "renewal-window"
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            with self.assertRaisesRegex(RuntimeError, "already recorded"):
                module.refresh("release-expected", now_unix=1700000000)
        fake._observe_and_bind_snapshot.assert_not_called()

    def test_external_client_declaration_is_preserved_when_fresh(self):
        module, fake = load_module()
        fake._read_private_json.side_effect = None
        fake._read_private_json.return_value = {
            "client_declaration": {
                "client_id": "chatgpt-external",
                "session_id": "external-observation",
            }
        }
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            result = module.refresh("release-expected", now_unix=1700000000)
        self.assertEqual(result, {"state": "not_due"})
        fake._observe_and_bind_snapshot.assert_not_called()

    def test_invalid_receipt_does_not_derive_fresh_session(self):
        module, fake = load_module()
        fake._read_private_json.side_effect = None
        fake._read_private_json.return_value = {"client_declaration": {"session_id": "untrusted"}}
        fake._validate_receipt.side_effect = fake.ClientSnapshotError("invalid digest")
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            module.refresh("release-expected", now_unix=1700000000)
        self.assertEqual(
            fake._snapshot_refresh_reason.call_args.kwargs["session_id"],
            "tunnel-session-pinned",
        )

    def test_different_active_release_fails_without_observer_promotion(self):
        module, fake = load_module()
        fake._snapshot_refresh_reason.return_value = "runtime-release-changed"

        async def wrong_release(**kwargs):
            return {"state": "renewed", "release_id": "unrelated-release",
                    "schema_contract_matches": True}

        fake._observe_and_bind_snapshot.side_effect = wrong_release
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            with self.assertRaisesRegex(RuntimeError, "did not verify"):
                module.refresh("release-expected", now_unix=1700000000)
        fake._write_observer_state.assert_not_called()

    def test_failed_observer_does_not_mark_tunnel_as_refreshed(self):
        module, fake = load_module()
        fake._snapshot_refresh_reason.return_value = "renewal-window"

        async def observer_failure(**kwargs):
            raise RuntimeError("transport rejected")

        fake._observe_and_bind_snapshot.side_effect = observer_failure
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            with self.assertRaises(RuntimeError):
                module.refresh("release-expected", now_unix=1700000000)
        fake._write_observer_state.assert_not_called()

    def test_missing_tunnel_fails_without_snapshot_attempt(self):
        module, fake = load_module()
        with patch.object(module, "_tunnel_identity", side_effect=RuntimeError("tunnel missing")):
            with self.assertRaises(RuntimeError):
                module.refresh("release-expected", now_unix=1700000000)
        fake._observe_and_bind_snapshot.assert_not_called()


class NixOSPublicationReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.module, self.fake = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        package = Path(self.temp.name)
        self.manifest = package / "share/grabowski/nixos-integrity-manifest.json"
        self.manifest.parent.mkdir(parents=True)
        self.fake.__file__ = str(package / "lib/grabowski_client_snapshot.py")
        self.manifest.write_text(json.dumps({
            "release_id": "release-expected",
            "repo_head": "a" * 40,
            "agent_instructions_sha256": "b" * 64,
            "entrypoint_contract": {"expected_tools": ["example"]},
        }))
        self.fake._sha256_json = MagicMock(side_effect=lambda value: (
            "c" * 64 if isinstance(value, list) else
            hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
        ))
        self.fake.OBSERVATION_SCOPE_SERVER_LOOPBACK = "server_loopback"
        self.fake.OBSERVATION_SCOPE_EXTERNAL_CLIENT = "external_client"
        self.receipt = {
            "verified": True, "mismatches": [],
            "created_at_unix": 1700000000, "expires_at_unix": 1700003600,
            "server_binding": {
                "release_id": "release-expected", "repo_head": "a" * 40,
                "registered_tool_count": 1, "registered_names_sha256": "c" * 64,
                "agent_instructions_sha256": "b" * 64,
            },
            "client_declaration": {
                "observed_release_id": "release-expected",
                "observed_tool_count": 1, "observed_names_sha256": "c" * 64,
                "observed_agent_instructions_sha256": "b" * 64,
                "observation_scope": "server_loopback",
                "observed_complete_schema_count": 1,
                "observed_complete_schema_sha256": "d" * 64,
            },
            "schema_evidence": {
                "probe": {"matches": True, "schema_contract_matches": True},
                "observed_artifact": {
                    "complete_schema_observable": True,
                    "complete_schema_count": 1, "complete_schema_sha256": "d" * 64,
                },
            },
        }
        self.fake._read_private_json.side_effect = None
        self.fake._read_private_json.return_value = self.receipt
        self.fake._read_publication_current = MagicMock(return_value=None)
        self.contract = {"tool_contract_sha256": "e" * 64}
        self.fake._platform_publication_contract = MagicMock(return_value=self.contract)
        self.fake.prepare_platform_publication_for_runtime = MagicMock(
            return_value={"state": "pending_activation", "request_id": "gpp-new"}
        )
        self.fake.activate_platform_publication_request = MagicMock(
            return_value={"state": "publication_pending", "request_id": "gpp-new"}
        )
        self.fake._read_publication_request = MagicMock()
        self.generation = ("/nix/store/abcdefghijklmno-nixos-system", "system-126-link",
                           42, 900, "boot-id")
        self.cutover_id = "nixos-snapshot-" + self.fake._sha256_json({
            "activation": self.generation, "repo_head": "a" * 40,
        })
        p = patch.object(self.module, "_accepted_generation", return_value=self.generation)
        self.live = p.start()
        self.addCleanup(p.stop)
        t = patch.object(self.module.time, "time", return_value=1700000100)
        t.start()
        self.addCleanup(t.stop)

    def reconcile(self):
        return self.module.reconcile_publication(self.manifest, "release-expected")

    def test_prepare_and_activate_from_complete_current_receipt(self):
        result = self.reconcile()
        self.assertEqual(result, {"state": "publication_pending", "request_id": "gpp-new"})
        self.fake.prepare_platform_publication_for_runtime.assert_called_once_with(
            registered_tool_count=1, registered_names_sha256="c" * 64,
            complete_schema_count=1, complete_schema_sha256="d" * 64,
            cutover_id=self.cutover_id,
        )
        self.fake.activate_platform_publication_request.assert_called_once_with(
            request_id="gpp-new"
        )

    def test_unchanged_semantic_contract_reuses_native_request(self):
        self.fake.prepare_platform_publication_for_runtime.return_value = {
            "state": "publication_pending", "request_id": "gpp-existing", "reused": True,
        }
        self.assertEqual(self.reconcile(), {"state": "unchanged", "request_id": "gpp-existing"})
        self.fake.activate_platform_publication_request.assert_not_called()

    def test_unapproved_generation_does_not_prepare(self):
        self.live.return_value = None
        self.assertEqual(self.reconcile()["reason"], "system-not-approved")
        self.fake.prepare_platform_publication_for_runtime.assert_not_called()

    def test_schema_metadata_must_match_declaration(self):
        self.receipt["client_declaration"]["observed_complete_schema_sha256"] = "f" * 64
        self.assertEqual(self.reconcile()["reason"], "complete-current-schema-evidence-required")
        self.fake.prepare_platform_publication_for_runtime.assert_not_called()

    def test_expired_or_historical_evidence_does_not_prepare(self):
        for changes in ({"expires_at_unix": 1700000001}, {"cutover_transition": {"historical": True}}):
            with self.subTest(changes=changes), patch.dict(self.receipt, changes):
                self.assertEqual(self.reconcile()["state"], "deferred")
        self.fake.prepare_platform_publication_for_runtime.assert_not_called()

    def test_foreign_pending_activation_is_not_overwritten(self):
        self.fake._read_publication_current.return_value = {
            "state": "pending_activation", "request_id": "gpp-foreign",
        }
        self.fake._read_publication_request.return_value = {
            "cutover_id": "foreign", "expected_contract": self.contract,
        }
        self.assertEqual(self.reconcile()["reason"], "foreign-pending-activation")
        self.fake.prepare_platform_publication_for_runtime.assert_not_called()
        self.fake.activate_platform_publication_request.assert_not_called()

    def test_interrupted_own_preparation_is_recovered(self):
        self.fake._read_publication_current.return_value = {
            "state": "pending_activation", "request_id": "gpp-own",
        }
        self.fake._read_publication_request.return_value = {
            "cutover_id": self.cutover_id, "expected_contract": self.contract,
            "request_id": "gpp-own",
        }
        self.assertEqual(self.reconcile()["state"], "publication_pending")
        self.fake.prepare_platform_publication_for_runtime.assert_not_called()
        self.fake.activate_platform_publication_request.assert_called_once_with(
            request_id="gpp-own"
        )

    def test_previous_own_generation_same_contract_reuses_pending_request(self):
        self.fake._read_publication_current.return_value = {
            "state": "pending_activation", "request_id": "gpp-previous",
        }
        self.fake._read_publication_request.return_value = {
            "cutover_id": "nixos-snapshot-" + "0" * 64,
            "expected_contract": self.contract, "request_id": "gpp-previous",
        }
        self.assertEqual(self.reconcile()["state"], "publication_pending")
        self.fake.prepare_platform_publication_for_runtime.assert_not_called()
        self.fake.activate_platform_publication_request.assert_called_once_with(
            request_id="gpp-previous"
        )

    def test_previous_own_generation_different_contract_gets_successor(self):
        self.fake._read_publication_current.return_value = {
            "state": "pending_activation", "request_id": "gpp-previous",
        }
        self.fake._read_publication_request.return_value = {
            "cutover_id": "nixos-snapshot-" + "0" * 64,
            "expected_contract": {"tool_contract_sha256": "f" * 64},
            "request_id": "gpp-previous",
        }
        self.assertEqual(self.reconcile()["state"], "publication_pending")
        self.fake.prepare_platform_publication_for_runtime.assert_called_once()
        self.fake.activate_platform_publication_request.assert_called_once_with(
            request_id="gpp-new"
        )

    def test_restored_generation_uses_new_activation_epoch(self):
        self.live.return_value = (*self.generation[:2], 43, 901, "new-boot-id")
        self.reconcile()
        observed = self.fake.prepare_platform_publication_for_runtime.call_args.kwargs
        self.assertNotEqual(observed["cutover_id"], self.cutover_id)
        self.assertRegex(observed["cutover_id"], r"^nixos-snapshot-[0-9a-f]{64}$")

    def test_generation_changed_after_prepare_does_not_activate(self):
        self.live.side_effect = [self.generation, self.generation, None]
        self.assertEqual(self.reconcile()["reason"], "generation-changed-after-prepare")
        self.fake.activate_platform_publication_request.assert_not_called()

    def test_immutable_manifest_release_must_match(self):
        with self.assertRaisesRegex(RuntimeError, "release identity mismatch"):
            self.module.reconcile_publication(self.manifest, "foreign-release")
        self.fake.prepare_platform_publication_for_runtime.assert_not_called()


if __name__ == "__main__":
    unittest.main()
