"""NixOS Grabowski signed connector snapshot adapter regressions."""
from __future__ import annotations

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
    fake.AUTO_REFRESH_CONNECTOR_TOKEN_PATH = Path("/nonexistent/test-token")
    fake.AUTO_REFRESH_MCP_URL = "http://127.0.0.1:18181/mcp"
    spec = importlib.util.spec_from_file_location("nixos_grabowski_snapshot_adapter", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"grabowski_client_snapshot": fake}):
        spec.loader.exec_module(module)
    return module, fake


class NixOSGrabowskiSnapshotRefreshTests(unittest.TestCase):
    def test_not_due_preserves_valid_observation_without_mcp_mutation(self):
        module, fake = load_module()
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            result = module.refresh("release-expected", now_unix=1700000000)
        self.assertEqual(result, {"state": "not_due"})
        fake._observe_and_bind_snapshot.assert_not_called()
        fake._write_observer_state.assert_not_called()

    def test_expired_snapshot_renews_via_real_signed_ingress_path(self):
        module, fake = load_module()
        fake._snapshot_refresh_reason.return_value = "renewal-window"
        async def observer(**kwargs):
            return {
                "state": "renewed", "release_id": "release-expected",
                "schema_contract_matches": True, "tool_count": 207,
                "receipt_sha256": "a" * 64,
            }
        fake._observe_and_bind_snapshot.side_effect = observer
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            result = module.refresh("release-expected", now_unix=1700000000)
        self.assertEqual(result["state"], "renewed")
        self.assertEqual(result["receipt_sha256"], "a" * 64)
        fake._write_observer_state.assert_called_once_with(
            session_id="tunnel-session-pinned",
            release_id="release-expected",
            now_unix=1700000000,
        )

    def test_different_active_release_fails_without_observer_promotion(self):
        module, fake = load_module()
        fake._snapshot_refresh_reason.return_value = "runtime-release-changed"
        async def observer(**kwargs):
            return {
                "state": "renewed", "release_id": "unrelated-release",
                "schema_contract_matches": True,
            }
        fake._observe_and_bind_snapshot.side_effect = observer
        with patch.object(module, "_tunnel_identity", return_value=(3543, 1270)):
            with self.assertRaisesRegex(RuntimeError, "did not verify"):
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
