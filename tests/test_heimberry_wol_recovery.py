"""Fast, offline regression tests for independent heimberry WoL recovery."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "heimberry_wol_recovery.py"
spec = importlib.util.spec_from_file_location("heimberry_wol_recovery", SCRIPT)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class TestHeimberryWolRecovery(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        directory = Path(self.directory.name)
        self.state_file = directory / "state.json"
        self.config_file = directory / "private.json"
        self.config = {
            "lan_host": "192.0.2.10",
            "tailnet_host": "198.51.100.20",
            "gateway": "192.0.2.1",
            "broadcast": "192.0.2.255",
            "mac": "02:00:00:00:00:01",
        }
        self.config_file.write_text(json.dumps(self.config), encoding="utf-8")

    def run_check(self):
        argv = ["recovery", "--config", str(self.config_file), "--state", str(self.state_file)]
        with mock.patch.object(sys, "argv", argv):
            recovery.main()

    def state(self):
        return json.loads(self.state_file.read_text(encoding="utf-8"))

    def test_private_config_is_read_and_validated(self):
        self.assertEqual(recovery.load_config(self.config_file), self.config)
        self.config_file.write_text('{"lan_host":"not-an-ip"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            recovery.load_config(self.config_file)

    def test_missing_config_never_sends_magic_packet(self):
        self.config_file.unlink()
        with mock.patch.object(recovery, "wake") as wake:
            with self.assertRaises(FileNotFoundError):
                self.run_check()
            wake.assert_not_called()
        self.assertFalse(self.state_file.exists())

    def test_online_host_does_not_wake(self):
        with (
            mock.patch.object(recovery, "ssh_port_alive", side_effect=[True, False]),
            mock.patch.object(recovery, "wake") as wake,
        ):
            self.run_check()
            wake.assert_not_called()
        self.assertFalse(self.state_file.exists())

    def test_waits_for_three_failures_and_rate_limits_wake(self):
        with (
            mock.patch.object(recovery, "ssh_port_alive", return_value=False),
            mock.patch.object(recovery, "local_lan_alive", return_value=True),
            mock.patch.object(recovery, "wake", return_value="sent") as wake,
            mock.patch.object(recovery.time, "time", return_value=1_800_000_000),
        ):
            self.run_check()
            self.run_check()
            wake.assert_not_called()
            self.run_check()
            wake.assert_called_once_with(self.config)
            self.assertEqual(self.state()["attempts"], 1)
            self.run_check()
            wake.assert_called_once()

    def test_no_magic_packet_when_lan_is_down(self):
        with (
            mock.patch.object(recovery, "ssh_port_alive", return_value=False),
            mock.patch.object(recovery, "local_lan_alive", return_value=False),
            mock.patch.object(recovery, "wake") as wake,
        ):
            for _ in range(4):
                self.run_check()
            wake.assert_not_called()
        self.assertFalse(self.state_file.exists())

    def test_recovery_clears_failed_state(self):
        with (
            mock.patch.object(recovery, "ssh_port_alive", return_value=False),
            mock.patch.object(recovery, "local_lan_alive", return_value=True),
            mock.patch.object(recovery, "wake", return_value="sent"),
            mock.patch.object(recovery.time, "time", return_value=1_800_000_000),
        ):
            for _ in range(3):
                self.run_check()
        self.assertEqual(self.state()["attempts"], 1)
        with (
            mock.patch.object(recovery, "ssh_port_alive", side_effect=[True, False]),
            mock.patch.object(recovery, "wake") as wake,
        ):
            self.run_check()
            wake.assert_not_called()
        self.assertEqual(self.state()["attempts"], 0)
        self.assertEqual(self.state()["failures"], 0)

    def test_hard_limit_three_attempts_per_outage(self):
        with (
            mock.patch.object(recovery, "ssh_port_alive", return_value=False),
            mock.patch.object(recovery, "local_lan_alive", return_value=True),
            mock.patch.object(recovery, "wake", return_value="sent") as wake,
            mock.patch.object(recovery.time, "time", return_value=1_800_000_000) as clock,
        ):
            for _ in range(3):
                self.run_check()
            for i in range(1, 5):
                clock.return_value = 1_800_000_000 + i * recovery.COOLDOWN_SECONDS
                self.run_check()
            self.assertEqual(wake.call_count, 3)
        self.assertEqual(self.state()["attempts"], 3)


if __name__ == "__main__":
    unittest.main()
