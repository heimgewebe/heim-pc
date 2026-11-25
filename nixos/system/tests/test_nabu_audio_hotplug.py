"""Both MOTU audio services use one private device binding and level-triggered start."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1] / "nabu"
MIC = "heimgewebe-assist-microphone.container.in"
MUSIC = "heimgewebe-music-sendspin.service"
PATHS = {"heimgewebe-assist-motu-hotplug.path": "heimgewebe-assist-microphone.service",
         "heimgewebe-music-sendspin.path": MUSIC}
FILES = (MIC, MUSIC, *PATHS)


class AudioHotplugTests(unittest.TestCase):
    def test_direct_paths_and_no_unconditional_quadlet_start(self):
        for name, target in PATHS.items():
            path = (ROOT / name).read_text()
            self.assertIn("PathExists=/dev/snd/by-id/@MOTU_DEVICE@", path)
            self.assertIn("Unit=" + target, path)
            self.assertIn("WantedBy=default.target", path)
            self.assertNotIn("PathChanged=", path)
        mic = (ROOT / MIC).read_text()
        self.assertNotIn("WantedBy=default.target", mic)
        self.assertIn("Restart=on-failure", mic)
        self.assertIn("TimeoutStartSec=90", mic)

    def test_both_services_bind_selected_device_lifetime(self):
        for name in (MIC, MUSIC):
            unit = (ROOT / name).read_text()
            self.assertIn("BindsTo=@MOTU_DEVICE_UNIT@", unit)
            self.assertIn("After=@MOTU_DEVICE_UNIT@", unit)
            self.assertIn("ConditionPathExists=/dev/snd/by-id/@MOTU_DEVICE@", unit)
            self.assertNotIn("WantedBy=default.target", unit)

    def test_no_private_serial_in_templates(self):
        for name in FILES:
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
        for name in FILES:
            rendered = (ROOT / name).read_text().replace(
                "@MOTU_DEVICE@", device).replace("@MOTU_DEVICE_UNIT@", unit)
            self.assertNotRegex(rendered, r"@MOTU_DEVICE")
            if name in PATHS:
                self.assertIn("PathExists=" + target, rendered)
            else:
                self.assertIn("BindsTo=" + unit, rendered)
                self.assertIn("After=" + unit, rendered)
                self.assertIn("ConditionPathExists=" + target, rendered)
            if name == MIC:
                self.assertIn("alsa_input." + device, rendered)
                self.assertIn("alsa_output." + device, rendered)


if __name__ == "__main__":
    unittest.main()
