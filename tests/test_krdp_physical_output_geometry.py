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


    def test_pointer_offset_patch_uses_selected_physical_output_geometry(self):
        pointer_patch = (FEATURE / "patches/krdp-6.7.0-physical-output-pointer-coordinates-v1.patch").read_text(
            encoding="utf-8"
        )
        package = (FEATURE / "package.nix").read_text(encoding="utf-8")
        self.assertIn("else if (const auto physicalIndex = activeStream())", pointer_patch)
        self.assertIn("qApp->screens().at(*physicalIndex)->geometry()", pointer_patch)
        self.assertIn("geometry.width() + geometry.x()", pointer_patch)
        self.assertIn("geometry.height() + geometry.y()", pointer_patch)
        self.assertIn("krdp-6.7.0-physical-output-pointer-coordinates-v1.patch", package)

    def test_dp2_pointer_mapping_preserves_nonzero_screen_origin(self):
        # Independently calibrated FreeRDP/KWin: 2560x1440 DP-2 at x=2259.
        for cx, cy, expected_x, expected_y in [
            (256, 360, 2515, 360), (640, 360, 2899, 360),
            (1024, 360, 3283, 360), (640, 144, 2899, 144),
            (640, 576, 2899, 576),
        ]:
            with self.subTest(client=(cx, cy)):
                x = (cx / 2560) * 2560 + 2259
                y = (cy / 1440) * 1440
                self.assertAlmostEqual(x, expected_x, delta=0.5)
                self.assertAlmostEqual(y, expected_y, delta=0.5)

    def test_dp1_pointer_mapping_respects_logical_scale(self):
        # Independently calibrated FreeRDP/KWin: 3840x2160, scale 1.7.
        logical_width = round(3840 / 1.7)
        logical_height = round(2160 / 1.7)
        for cx, cy, expected_x, expected_y in [
            (320, 450, 188, 265), (800, 450, 471, 265),
            (1280, 450, 753, 265), (800, 180, 471, 106),
            (800, 720, 471, 424),
        ]:
            with self.subTest(client=(cx, cy)):
                x = (cx / 3840) * logical_width
                y = (cy / 2160) * logical_height
                self.assertAlmostEqual(x, expected_x, delta=1.0)
                self.assertAlmostEqual(y, expected_y, delta=1.0)


if __name__ == "__main__":
    unittest.main()
