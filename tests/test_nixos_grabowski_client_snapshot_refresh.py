"""NixOS Grabowski signed connector snapshot adapter regressions."""
from __future__ import annotations

from contextlib import nullcontext
import importlib.util
from pathlib import Path
import sys
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


if __name__ == "__main__":
    unittest.main()
