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

    def test_pointer_fixes_are_reproducible(self):
        patches = FEATURE / "patches"
        expected = {
            "krdp-6.6.6-vm-size-v1.patch": "stream->d->m_size",
            "krdp-6.6.6-wl-fixed-pointer-v1.patch": "wl_fixed_from_double",
            "krdp-6.6.6-fakeinput-auth-v1.patch": "authenticate(",
            "krdp-6.6.6-virtual-output-pointer-offset-v1.patch": "geometry().topLeft()",
            "krdp-6.6.6-embedded-pointer-v3.patch": "State::Streaming",
        }
        for name, marker in expected.items():
            with self.subTest(patch=name):
                content = (patches / name).read_text()
                self.assertIn(marker, content)
                self.assertIn("--- a/", content)
                self.assertIn("+++ b/", content)

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
