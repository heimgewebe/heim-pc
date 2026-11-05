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
        desktop = (FEATURE / "org.kde.krdp-ipad-runtime-v13.desktop").read_text()
        self.assertIn("--monitor 0 --plasma", service)
        self.assertNotIn("--virtual-monitor", service)
        self.assertIn("KRDP_EMBED_CURSOR=1", service)
        self.assertNotIn("KRDP_LETTERBOX", service)
        self.assertIn("127.0.0.1 --port 3390", service)
        self.assertIn("ExecStopPost=", controller)
        self.assertIn("--restore", controller)
        self.assertIn("Restart=on-failure", controller)
        self.assertIn("X-KDE-Wayland-Interfaces=org_kde_kwin_fake_input,zkde_screencast_unstable_v1", desktop)
        self.assertTrue((FEATURE / "krdp-unit-before-native-v1.conf").is_file())

    def test_physical_output_embeds_cursor_when_client_pointer_is_hidden(self):
        # Native iPad --monitor 0 uses createOutputStream(), not virtualMonitor().
        # Do not suppress remote pointer PDUs without embedding the host cursor.
        source = (FEATURE / "patches" / "krdp-6.7.0-embedded-pointer-v1.patch").read_text()
        service = (FEATURE / "krdp-native-override.conf").read_text()
        self.assertIn('createOutputStream(screen, qEnvironmentVariableIntValue("KRDP_EMBED_CURSOR") ? Screencasting::Embedded : Screencasting::Metadata)', source)
        self.assertIn("KRDP_EMBED_CURSOR=1", service)
        self.assertIn("connection->cursor()->setCursorType(KRdp::Cursor::CursorType::Hidden)", source)

    def test_native_client_input_diagnostics_are_bounded_and_coordinate_free(self):
        source = (FEATURE / "patches" / "krdp-6.7.0-input-diag-v1.patch").read_text()
        package = (FEATURE / "package.nix").read_text()
        service = (FEATURE / "krdp-native-override.conf").read_text()
        self.assertIn("krdp-6.7.0-input-diag-v1.patch", package)
        self.assertIn("KRDP_INPUT_DIAG=1", service)
        self.assertIn('RDP_TOUCH_CONTACT', source)
        self.assertIn('RDP_MOUSE_PDU', source)
        self.assertIn("count & (count - 1)", source)
        self.assertNotIn('<< x', source)
        self.assertNotIn('<< y', source)

    def test_rdpei_touch_is_explicit_opt_in(self):
        package = (FEATURE / "package.nix").read_text()
        patch = (FEATURE / "patches" / "krdp-6.7.0-rdpei-touch-input-v1.patch").read_text()
        service = (FEATURE / "krdp-native-override.conf").read_text()
        self.assertIn("krdp-6.7.0-rdpei-touch-input-v1.patch", package)
        self.assertIn("rdpei_server_context_new", patch)
        self.assertIn('KRDP_RDPEI_TOUCH', patch)
        self.assertIn("onTouchEvent", patch)
        # FreeRDP +multitouch/Qt Contact tests are successful before opt-in.
        self.assertIn("KRDP_RDPEI_TOUCH=1", service)

    def test_runtime_unit_and_kwin_registration_match_binary(self):
        import re

        service = (FEATURE / "krdp-native-override.conf").read_text()
        desktop = (FEATURE / "org.kde.krdp-ipad-runtime-v13.desktop").read_text()
        running = re.search(
            r"^ExecStart=(/run/user/1000/[^ ]+/krdpserver) --address 127.0.0.1",
            service, re.M,
        )
        install = re.search(
            r"^ExecStartPre=/run/current-system/sw/bin/install -Dm755 "
            r"(/nix/store/[^ ]+-krdp-6\.7\.0/bin/\.krdpserver-wrapped) "
            r"(/run/user/1000/[^ ]+/krdpserver)$",
            service, re.M,
        )
        self.assertIsNotNone(running)
        self.assertIsNotNone(install)
        self.assertEqual(running.group(1), install.group(2))
        self.assertIn("Exec=" + running.group(1) + "\n", desktop)
        self.assertIn("2gzx8hw3mjgid4zw570js4fg7ck9cgvx-krdp-6.7.0", install.group(1))
        self.assertIn("X-KDE-Wayland-Interfaces=org_kde_kwin_fake_input,zkde_screencast_unstable_v1", desktop)
        self.assertIn("ExecCondition=/run/current-system/sw/bin/test -S /run/user/1000/wayland-0", service)
        self.assertIn("TimeoutStopSec=15s", service)
        self.assertNotIn("KWIN_WAYLAND_NO_PERMISSION_CHECKS", service)
        self.assertNotIn("--virtual-monitor", service)

    def test_boot_and_krdp_restart_restore_bin_and_warm_kwin_in_order(self):
        """Avoid the first-connection KWin permissions race after sycoca refresh."""
        service = (FEATURE / "krdp-native-override.conf").read_text()
        desktop = (FEATURE / "org.kde.krdp-ipad-runtime-v13.desktop").read_text()
        running = next(line.split("=", 1)[1].split(" --address", 1)[0]
                       for line in service.splitlines() if line.startswith("ExecStart=") and " --address" in line)
        pre = [line for line in service.splitlines() if line.startswith("ExecStartPre=")]
        self.assertEqual(len(pre), 4)
        self.assertTrue(pre[0].startswith("ExecStartPre=/run/current-system/sw/bin/install -Dm755 /nix/store/"))
        self.assertTrue(pre[0].endswith(" " + running))
        self.assertEqual(pre[1], "ExecStartPre=/run/current-system/sw/bin/kbuildsycoca6 --noincremental")
        self.assertEqual(pre[2], "ExecStartPre=-/run/current-system/sw/bin/busctl --user call org.kde.KWin /KWin org.kde.KWin reconfigure")
        self.assertEqual(pre[3], "ExecStartPre=" + running + " --help")
        self.assertIn("Exec=" + running + "\n", desktop)
        self.assertIn("KRDP_EMBED_CURSOR=1", service)
        self.assertIn("KRDP_RDPEI_TOUCH=1", service)
        self.assertIn("KRDP_INPUT_DIAG=1", service)
        self.assertFalse((FEATURE / "org.kde.krdpserver-ipad-test.desktop").exists())

    def test_unbound_kwin_fakeinput_proxy_is_never_authenticated(self):
        # Live v11 SIGSEGV 258707: wl_proxy_get_version on an unbound proxy.
        package = (FEATURE / "package.nix").read_text()
        name = "krdp-6.7.0-guard-unbound-fakeinput-v1.patch"
        patch = (FEATURE / "patches" / name).read_text()
        self.assertIn(name, package)
        self.assertIn("if (d->remoteInterface->isActive()) {", patch)
        self.assertIn("-    d->remoteInterface->authenticate(", patch)
        self.assertIn("+        d->remoteInterface->authenticate(", patch)
        # Preserve active-server behavior; do not remove working authentication.

    def test_windows_app_suspended_frame_acks_do_not_block_video(self):
        # KDE bug 520260; cherry-picked concept from upstream fe003738...
        # KRDP 6.7.0 has separate H264 and Progressive frame submissions.
        package = (FEATURE / "package.nix").read_text()
        patch_name = "krdp-6.7.0-suspended-frame-ack-v1.patch"
        patch = (FEATURE / "patches" / patch_name).read_text()
        self.assertIn(patch_name, package)
        self.assertIn("SUSPEND_FRAME_ACKNOWLEDGEMENT", patch)
        self.assertIn("+        d->pendingFrames.clear();", patch)
        self.assertIn("+    bool frameAcknowledgementSuspended = false;", patch)
        self.assertEqual(patch.count("+        d->frameAcknowledgementSuspended = false;"), 2)
        self.assertEqual(patch.count("+        if (!d->frameAcknowledgementSuspended) {"), 2)
        # Both H264 and the iPad's Progressive encoder must keep sending
        # while the client explicitly suspends RDPGFX frame ACKs.
        self.assertEqual(patch.count("+            d->pendingFrames.insert(frameId);"), 2)

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
