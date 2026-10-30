"""Fast, offline regression tests for the independent heimberry WoL monitor."""
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
        self.state_file = Path(self.directory.name) / "state.json"

    def run_check(self):
        with mock.patch.object(sys, "argv", ["recovery", "--state", str(self.state_file)]):
            recovery.main()

    def state(self):
        return json.loads(self.state_file.read_text(encoding="utf-8"))

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
            wake.assert_called_once()
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


if __name__ == "__main__":
    unittest.main()
