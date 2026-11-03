"""Regression guards for the physical systemd-boot pinned-profile install hook.

This test does not claim a physical reboot, EFI write, or MCP recovery.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "nixos/system/modules/storage-layout.nix"


def storage_script() -> str:
    text = SOURCE.read_text(encoding="utf-8")
    match = re.search(
        r"privateStorageTool = pkgs\.writeShellApplication \{.*?\n    text = ''\n(.*?)\n    '';",
        text,
        flags=re.DOTALL,
    )
    assert match is not None, "private storage hook is missing"
    script = match.group(1).replace("''${", "${")
    return (
        script.replace("${lib.escapeShellArg mapperName}", "'heimpc-nixos-crypt'")
        .replace("${lib.escapeShellArg loaderSortKeyLine}", "'sort-key nixos'")
        .replace("${mapperName}", "heimpc-nixos-crypt")
    )


class PinnedBootProfilesTest(unittest.TestCase):
    def test_generated_shell_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n"],
            input=storage_script(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_physical_storage_install_hook_controls_default(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("boot.loader.systemd-boot.extraInstallCommands =", source)
        self.assertIn("heim-pc-private-storage patch-loader-entries", source)
        self.assertIn("boot.loader.efi.canTouchEfiVariables = false;", source)
        self.assertIn("pkgs.gnugrep pkgs.systemd", source)

    def test_profiles_are_native_gc_pins_not_fixed_generation_numbers(self) -> None:
        script = storage_script()
        self.assertIn("/nix/var/nix/profiles/system-profiles/$name", script)
        self.assertIn("pinned_entry heim-pc-approved", script)
        self.assertIn("pinned_entry heim-pc-recovery", script)
        self.assertIn('entry="nixos-$name-generation-$generation.conf"', script)
        self.assertIn('"$token" == "init=$closure/init"', script)
        self.assertNotIn("nixos-generation-42.conf", script)
        self.assertNotIn("nixos-generation-38.conf", script)

    def test_install_preserves_luks_patch_before_default_selection(self) -> None:
        script = storage_script()
        branch = script.split("patch-loader-entries)", 1)[1]
        self.assertLess(branch.index("patch_entries\n"), branch.index("select_approved_boot\n"))
        self.assertIn('grep -qxF "default $approved" "$conf"', script)

    def test_efi_override_and_recovery_are_both_verified(self) -> None:
        script = storage_script()
        self.assertIn('bootctl --esp-path=/boot set-default "$approved"', script)
        self.assertIn('bootctl --esp-path=/boot set-sysfail "$fallback"', script)
        self.assertIn('Default Entry: $approved', script)
        self.assertIn('SysFail Entry: $fallback', script)
        self.assertIn('[[ "$(grep -c \'^default \' "$conf" || true)" == 1 ]]', script)


if __name__ == "__main__":
    unittest.main()
