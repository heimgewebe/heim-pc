"""Regression tests for the alex iPad-native KRDP runtime contract."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import signal
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FEATURE = ROOT / "runtime" / "krdp-ipad"


class TestIpadKrdpRuntime(unittest.TestCase):
    def test_runtime_is_native_and_has_a_recovery_path(self):
        service = (FEATURE / "krdp-native-override.conf").read_text()
        controller = (FEATURE / "krdp-ipad-display-controller.service").read_text()
        desktop = (FEATURE / "org.kde.krdpserver-ipad-test.desktop").read_text()
        self.assertIn("--virtual-monitor 1168x812@1 --plasma", service)
        self.assertIn("KRDP_EMBED_CURSOR=1", service)
        self.assertNotIn("KRDP_LETTERBOX", service)
        self.assertIn("127.0.0.1 --port 3390", service)
        self.assertIn("ExecStopPost=", controller)
        self.assertIn("--restore", controller)
        self.assertIn("Restart=on-failure", controller)
        self.assertIn("X-KDE-Wayland-Interfaces=org_kde_kwin_fake_input,zkde_screencast_unstable_v1", desktop)
        self.assertTrue((FEATURE / "krdp-unit-before-native-v1.conf").is_file())

    def test_rdpei_touch_is_explicit_opt_in(self):
        package = (FEATURE / "package.nix").read_text()
        patch = (FEATURE / "patches" / "krdp-6.7.0-rdpei-touch-input-v1.patch").read_text()
        service = (FEATURE / "krdp-native-override.conf").read_text()
        self.assertIn("krdp-6.7.0-rdpei-touch-input-v1.patch", package)
        self.assertIn("rdpei_server_context_new", patch)
        self.assertIn('KRDP_RDPEI_TOUCH', patch)
        self.assertIn("onTouchEvent", patch)
        # The active server must not enable an unverified client input mode.
        self.assertNotIn("KRDP_RDPEI_TOUCH", service)

    def test_runtime_unit_and_kwin_registration_match_binary(self):
        import re
        service = (FEATURE / "krdp-native-override.conf").read_text()
        desktop = (FEATURE / "org.kde.krdpserver-ipad-test.desktop").read_text()
        binary = re.search(r"^ExecStart=(/nix/store/[^ ]+/bin/krdpserver) ", service, re.M)
        self.assertIsNotNone(binary)
        self.assertIn("Exec=" + binary.group(1), desktop)
        self.assertIn("-krdp-6.7.0/bin/krdpserver", binary.group(1))
        self.assertIn("ExecStartPre=/run/current-system/sw/bin/kbuildsycoca6 --noincremental", service)
        self.assertIn("TimeoutStopSec=15s", service)
        self.assertIn("rgldrc8llk7k44b70946lhhzh3rn4w1l-krdp-6.7.0", binary.group(1))
        self.assertIn("--virtual-monitor 1168x812@1", service)

    def test_pointer_fixes_are_reproducible(self):
        patches = FEATURE / "patches"
        expected = {
            "krdp-6.6.6-vm-size-v1.patch": "stream->d->m_size",
            "krdp-6.6.6-wl-fixed-pointer-v1.patch": "wl_fixed_from_double",
            "krdp-6.6.6-fakeinput-auth-v1.patch": "authenticate(",
            "krdp-6.6.6-virtual-output-pointer-offset-v1.patch": "geometry().topLeft()",
            "krdp-6.6.6-embedded-pointer-v3.patch": "State::Streaming",
            "krdp-6.6.6-disable-ext-security-v1.patch": "FreeRDP_ExtSecurity, false",
        }
        for name, marker in expected.items():
            with self.subTest(patch=name):
                content = (patches / name).read_text()
                self.assertIn(marker, content)
                self.assertIn("--- a/", content)
                self.assertIn("+++ b/", content)

    def test_progressive_source_pin_and_cleanup(self):
        package = (FEATURE / "package.nix").read_text()
        self.assertIn('version = "6.7.0";', package)
        self.assertIn("b1a49644aed95132ac0d2eee19780040c061fdaa", package)
        self.assertIn("sha256-PLOOAIKz3YVPFipC0gndLaeLk2Sq6nNmJsyLiut7+8s=", package)
        self.assertIn("pkgs.kdePackages.kirigami-addons", package)
        expected = {
            "krdp-6.7.0-virtual-output-pointer-offset-v1.patch": "geometry().topLeft()",
            "krdp-6.7.0-embedded-pointer-v1.patch": "KRDP_EMBED_CURSOR",
            "krdp-6.7.0-close-videostream-on-qt-thread-v1.patch": "Qt::BlockingQueuedConnection",
            "krdp-6.7.0-position-before-mouse-button-v1.patch": "Q_EMIT inputEvent(motion);",
            "krdp-6.7.0-rdpei-touch-input-v1.patch": "rdpei_server_context_new",
        }
        for name, marker in expected.items():
            self.assertIn(name, package)
            self.assertIn(marker, (FEATURE / "patches" / name).read_text())
        self.assertIn("FreeRDP_ExtSecurity, false", (FEATURE / "patches" / "krdp-6.6.6-disable-ext-security-v1.patch").read_text())
        # Absolute RDP button events must first move the KWin cursor:
        # Windows App on iPad can send a button without preceding MOVE.
        click_fix = (FEATURE / "patches" / "krdp-6.7.0-position-before-mouse-button-v1.patch").read_text()
        self.assertIn("button != Qt::NoButton", click_fix)
        self.assertIn("!(flags & PTR_FLAGS_MOVE)", click_fix)
        self.assertLess(click_fix.index("Q_EMIT inputEvent(motion);"),
                        click_fix.index("std::shared_ptr<QMouseEvent> event;"))

        self.assertIn("krdp-6.6.6-embedded-pointer-v3.patch", (FEATURE / "package-krdp-6.6.6.nix").read_text())

    def test_exclusive_takeover_restores_physical_preimage(self):
        source = FEATURE / "controller.py"
        prior_signals = {x: signal.getsignal(x) for x in (signal.SIGTERM, signal.SIGINT)}
        spec = importlib.util.spec_from_file_location("krdp_ipad_test_controller", source)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        finally:
            for signum, handler in prior_signals.items():
                signal.signal(signum, handler)

        self.assertEqual(module.VIRTUAL, "Virtual-1168x812@1")
        self.assertEqual((module.WIDTH, module.HEIGHT), (1168, 812))
        self.assertEqual(module.HEIGHT % 2, 0)  # Odd AVC420 heights cause black video.
        with tempfile.TemporaryDirectory(prefix="krdp-mock-output-") as folder:
            module.STATE = Path(folder)
            module.PREIMAGE = Path(folder) / "physical-outputs.json"
            physical = {"name": "DP-2", "id": 1, "connected": True, "enabled": True,
                        "pos": {"x": 0, "y": 0}, "scale": 1,
                        "size": {"width": 2560, "height": 1440}, "currentModeId": "1"}
            virtual = {"name": module.VIRTUAL, "id": 2, "connected": True, "enabled": True,
                       "pos": {"x": 2560, "y": 0}, "scale": 1,
                       "size": {"width": 1168, "height": 812}, "currentModeId": "1",
                       "modes": [{"name": "1168x812@60.00"}]}
            state = {physical["name"]: physical, virtual["name"]: virtual}

            def outputs():
                return list(state.values())

            def doctor(*commands):
                for command in commands:
                    parts = command.split(".")
                    self.assertEqual(parts[0], "output")
                    target = state.get(parts[1])
                    if target is None:
                        target = next((v for v in state.values() if str(v["id"]) == parts[1]), None)
                    self.assertIsNotNone(target)
                    operation = parts[2]
                    if operation in ("disable", "enable"):
                        target["enabled"] = operation == "enable"
                    elif operation == "position":
                        x, y = parts[3].split(",")
                        target["pos"] = {"x": int(x), "y": int(y)}
                    elif operation == "mode":
                        target["currentModeId"] = parts[3]
                    elif operation == "scale":
                        target["scale"] = float(parts[3])
                    else:
                        self.fail("Unexpected KScreen command " + command)
                return ""

            module.outputs = outputs
            module.doctor = doctor
            module.takeover(outputs(), virtual)
            self.assertFalse(physical["enabled"])
            self.assertEqual(virtual["pos"], {"x": 0, "y": 0})
            self.assertTrue(module.PREIMAGE.is_file())
            self.assertTrue(module.restore())
            self.assertTrue(physical["enabled"])
            self.assertEqual(physical["pos"], {"x": 0, "y": 0})
            self.assertEqual(physical["scale"], 1)
            self.assertFalse(module.PREIMAGE.exists())


if __name__ == "__main__":
    unittest.main()
