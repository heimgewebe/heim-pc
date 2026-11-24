"""Exercise the sysfs mutation contract without accessing real hardware."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "modules/thermal-mitigation.py"
spec = importlib.util.spec_from_file_location("thermal_mitigation", MODULE)
thermal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(thermal)


class ThermalMitigationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "original.json"
        self.put("sys/class/dmi/id/board_name", thermal.BOARD)
        self.put("proc/cpuinfo", "model name : " + thermal.CPU)
        self.policy = "sys/devices/system/cpu/cpufreq/policy0/"
        for name, value in {
            "scaling_driver": "amd-pstate-epp",
            "scaling_max_freq": "4981510",
            "scaling_min_freq": "1740528",
            "energy_performance_preference": "balance_performance",
            "energy_performance_available_preferences": "performance balance_performance balance_power power",
        }.items():
            self.put(self.policy + name, value)
        self.fan = "sys/class/hwmon/hwmon4/"
        self.put(self.fan + "name", "nct6798")
        for channel, (source, temperatures, _) in thermal.FAN_CURVES.items():
            prefix = self.fan + f"pwm{channel}_"
            self.put(prefix + "enable", "5")
            self.put(prefix + "temp_sel", str(source))
            for i, temperature in enumerate(temperatures, 1):
                self.put(prefix + f"auto_point{i}_temp", str(temperature))
            for i, pwm in enumerate((51, 114 if channel == 2 else 76, 255), 1):
                self.put(prefix + f"auto_point{i}_pwm", str(pwm))

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n")

    def value(self, name):
        return (self.root / name).read_text().strip()

    def test_apply_restore(self):
        thermal.apply(self.root, self.state)
        self.assertEqual(self.value(self.policy + "scaling_max_freq"), "4200000")
        self.assertEqual(self.value(self.policy + "energy_performance_preference"), "balance_power")
        self.assertEqual(self.value(self.fan + "pwm2_auto_point2_pwm"), "230")
        self.assertEqual(self.value(self.fan + "pwm3_auto_point1_pwm"), "102")
        self.assertEqual(self.value(self.fan + "pwm2_enable"), "5")
        thermal.restore(self.root, self.state)
        self.assertEqual(self.value(self.policy + "scaling_max_freq"), "4981510")
        self.assertEqual(self.value(self.policy + "energy_performance_preference"), "balance_performance")
        self.assertEqual(self.value(self.fan + "pwm2_auto_point2_pwm"), "114")
        self.assertFalse(self.state.exists())

    def test_wrong_hardware_no_write(self):
        self.put("sys/class/dmi/id/board_name", "other")
        thermal.apply(self.root, self.state)
        self.assertEqual(self.value(self.policy + "scaling_max_freq"), "4981510")
        self.assertEqual(self.value(self.fan + "pwm2_auto_point2_pwm"), "114")

    def test_preserve_stricter_cap_higher_fan_and_explicit_profile(self):
        self.put(self.policy + "scaling_max_freq", "3800000")
        self.put(self.policy + "energy_performance_preference", "power")
        self.put(self.fan + "pwm2_auto_point2_pwm", "250")
        thermal.apply(self.root, self.state)
        self.assertEqual(self.value(self.policy + "scaling_max_freq"), "3800000")
        self.assertEqual(self.value(self.policy + "energy_performance_preference"), "power")
        self.assertEqual(self.value(self.fan + "pwm2_auto_point2_pwm"), "250")

    def test_changed_firmware_layout_preserved(self):
        self.put(self.fan + "pwm2_temp_sel", "1")
        thermal.apply(self.root, self.state)
        self.assertEqual(self.value(self.fan + "pwm2_auto_point2_pwm"), "114")
        self.assertEqual(self.value(self.fan + "pwm3_auto_point2_pwm"), "153")

    def test_restore_preserves_later_operator_change(self):
        thermal.apply(self.root, self.state)
        self.put(self.policy + "energy_performance_preference", "performance")
        self.put(self.fan + "pwm2_enable", "1")
        thermal.restore(self.root, self.state)
        self.assertEqual(self.value(self.policy + "energy_performance_preference"), "performance")
        self.assertEqual(self.value(self.fan + "pwm2_auto_point2_pwm"), "230")

    def test_intervening_fan_point_change_preserves_whole_curve(self):
        thermal.apply(self.root, self.state)
        self.put(self.fan + "pwm2_auto_point1_pwm", "200")
        thermal.restore(self.root, self.state)
        self.assertEqual(self.value(self.fan + "pwm2_auto_point1_pwm"), "200")
        self.assertEqual(self.value(self.fan + "pwm2_auto_point2_pwm"), "230")

    def test_partial_write_failure_restores_original_values(self):
        original_write = thermal.write
        def fail_once(path, value):
            if path.name == "pwm2_auto_point1_pwm" and value == "128":
                raise OSError("simulated write failure")
            return original_write(path, value)
        with patch.object(thermal, "write", side_effect=fail_once):
            with self.assertRaises(OSError):
                thermal.apply(self.root, self.state)
        self.assertEqual(self.value(self.policy + "scaling_max_freq"), "4981510")
        self.assertEqual(self.value(self.policy + "energy_performance_preference"), "balance_performance")
        self.assertEqual(self.value(self.fan + "pwm2_auto_point1_pwm"), "51")
        self.assertEqual(self.value(self.fan + "pwm2_auto_point2_pwm"), "114")
        self.assertFalse(self.state.exists())

    def test_missing_fan_device_keeps_cpu_mitigation(self):
        (self.root / self.fan / "name").unlink()
        thermal.apply(self.root, self.state)
        self.assertEqual(self.value(self.policy + "scaling_max_freq"), "4200000")


if __name__ == "__main__":
    unittest.main()
