"""Guard RustDesk ScreenCast grant reconciliation for the active iPad KRDP output.

This is a source-contract test; a live KWin hotplug remains a separate
functional acceptance and must not be inferred from Python test success.
"""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "nixos/system/modules/rustdesk-screen-grant-hotplug.cpp"
MONITOR = ROOT / "runtime/krdp-ipad/ipad-krdp-monitor.service"


class RustdeskKdeGrantTest(unittest.TestCase):
    def test_both_virtual_screens_are_allowlisted(self):
        source = SOURCE.read_text()
        monitor = MONITOR.read_text()
        self.assertIn('name!="Virtual-iPadRemote"', source)
        self.assertIn('name!="Virtual-iPadKrdp"', source)
        self.assertIn("desired.size()>4", source)
        self.assertIn("--name iPadKrdp", monitor)

    def test_duplicate_positions_recover_by_current_logical_width(self):
        source = SOURCE.read_text()
        self.assertIn('QStringLiteral("DP-1"), QStringLiteral("DP-2")', source)
        self.assertIn('QStringLiteral("Virtual-iPadRemote"), QStringLiteral("Virtual-iPadKrdp")', source)
        self.assertIn('nextX += screen->geometry().width()', source)
        self.assertIn('overlapRepairs>=3', source)
        self.assertIn('QProcess::execute(QStringLiteral("kscreen-doctor"),args)', source)
        self.assertNotIn('if (!apply || !dp1 || !dp2 || !virtualScreen', source)

    def test_grant_readback_and_rollback_remain_required(self):
        source = SOURCE.read_text()
        self.assertIn('CONCURRENT_MODIFICATION_ABORT', source)
        self.assertIn('ROLLBACK_FAILED', source)
        self.assertIn('KDE_HOTPLUG_GRANT_VERIFIED', source)
        self.assertIn('UNKNOWN_OUTPUT_NAME', source)
        self.assertIn('previous.size() != static_cast<int>(count)', source)


if __name__ == "__main__":
    unittest.main()
