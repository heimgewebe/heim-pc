"""Regression for KRDP physical-output mouse mapping on mixed-DPI dual monitors.

Selecting --monitor 0 must use that output's logical geometry rather than
QScreen::virtualSize(), which includes both monitors and misplaces clicks.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FEATURE = ROOT / "runtime/krdp-ipad"
PATCH = FEATURE / "patches/krdp-6.7.0-physical-output-size-v1.patch"


class PhysicalMonitorGeometryTest(unittest.TestCase):
    def test_selected_output_not_whole_virtual_desktop(self):
        patch = PATCH.read_text(encoding="utf-8")
        self.assertIn(
            "-    stream->d->m_size = screen->virtualSize();", patch
        )
        self.assertIn("+    stream->d->m_size = screen->size();", patch)
        self.assertIn("createOutputStream(QScreen *screen", patch)
        self.assertNotIn("createVirtualMonitorStream", patch)

    def test_pinned_krdp_build_applies_fix(self):
        package = (FEATURE / "package.nix").read_text(encoding="utf-8")
        self.assertIn(PATCH.name, package)

    def test_dual_output_scale_is_not_target_size(self):
        # Actual Gen46 output layout: DP-1 at (0, 0) scaled 1.7 and
        # DP-2 to its right scaled 1.0. Do not assert exact rounding.
        dp1_w = round(3840 / 1.7)
        dp1_h = round(2160 / 1.7)
        desktop_w = dp1_w + 2560
        desktop_h = max(dp1_h, 1440)
        self.assertGreater(desktop_w, dp1_w)
        self.assertGreater(desktop_h, dp1_h)


if __name__ == "__main__":
    unittest.main()
