"""The MOTU startup path is level-triggered; the local device serial stays private."""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1] / "nabu"


class AudioHotplugTests(unittest.TestCase):
    def test_direct_path_and_no_unconditional_quadlet_start(self):
        path = (ROOT / "heimgewebe-assist-motu-hotplug.path").read_text()
        mic = (ROOT / "heimgewebe-assist-microphone.container.in").read_text()
        self.assertIn("PathExists=/dev/snd/by-id/@MOTU_DEVICE@", path)
        self.assertIn("Unit=heimgewebe-assist-microphone.service", path)
        self.assertIn("WantedBy=default.target", path)
        self.assertNotIn("PathChanged=", path)
        self.assertNotIn("WantedBy=default.target", mic)
        self.assertIn("ConditionPathExists=/dev/snd/by-id/@MOTU_DEVICE@", mic)
        self.assertIn("BindsTo=@MOTU_DEVICE_UNIT@", mic)
        self.assertIn("After=pipewire-pulse.service @MOTU_DEVICE_UNIT@", mic)
        self.assertIn("Restart=on-failure", mic)
        self.assertIn("TimeoutStartSec=90", mic)

    def test_sendspin_device_loss_binding(self):
        binding = (ROOT / "motu-device-binding.conf.in").read_text()
        self.assertIn("BindsTo=@MOTU_DEVICE_UNIT@", binding)
        self.assertIn("After=@MOTU_DEVICE_UNIT@", binding)
        self.assertNotIn("ExecStart", binding)
        self.assertNotIn("WantedBy", binding)

    def test_no_private_serial_in_templates(self):
        for name in ("heimgewebe-assist-microphone.container.in",
                     "heimgewebe-assist-motu-hotplug.path", "motu-device-binding.conf.in"):
            text = (ROOT / name).read_text()
            self.assertNotRegex(text, r"usb-MOTU_M2_[A-Za-z0-9]+-00")
            self.assertRegex(text, r"@MOTU_DEVICE(?:_UNIT)?@")

    @unittest.skipUnless(shutil.which("systemd-escape"), "systemd-escape not available")
    def test_same_exact_device_renders_path_audio_and_unit(self):
        device = "usb-MOTU_M2_TEST-00"
        target = "/dev/snd/by-id/" + device
        unit = subprocess.check_output(
            ["systemd-escape", "--path", "--suffix=device", target],
            text=True).strip()
        for name in ("heimgewebe-assist-microphone.container.in",
                     "heimgewebe-assist-motu-hotplug.path", "motu-device-binding.conf.in"):
            rendered = (ROOT / name).read_text().replace(
                "@MOTU_DEVICE@", device).replace("@MOTU_DEVICE_UNIT@", unit)
            self.assertNotRegex(rendered, r"@MOTU_DEVICE")
            if name.endswith(".path"):
                self.assertIn("PathExists=" + target, rendered)
            else:
                self.assertIn("BindsTo=" + unit, rendered)
                self.assertIn(unit, rendered.split("After=", 1)[1].splitlines()[0])
            if name.endswith(".container.in"):
                self.assertIn("ConditionPathExists=" + target, rendered)
                self.assertIn("alsa_input." + device, rendered)
                self.assertIn("alsa_output." + device, rendered)


if __name__ == "__main__":
    unittest.main()
