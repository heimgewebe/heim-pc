"""Regression guards for pinned systemd-boot profiles on the real Seagate host.

The tests do not claim a physical EFI write, reboot or MCP recovery.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "nixos/system/modules"
BOOT = MODULES / "boot-approved-profiles.nix"
SEAGATE = MODULES / "seagate-primary-candidate.nix"
STORAGE = MODULES / "storage-layout.nix"


def boot_script() -> str:
    text = BOOT.read_text(encoding="utf-8")
    match = re.search(
        r"bootProfileSelection = pkgs\.writeShellApplication \{.*?\n    text = ''\n(.*?)\n    '';",
        text,
        flags=re.DOTALL,
    )
    assert match is not None, "shared systemd-boot install hook is missing"
    script = match.group(1).replace("''${", "${")
    return script.replace(
        "${lib.escapeShellArg loaderSortKeyLine}", "'sort-key nixos'"
    )


class PinnedBootProfilesTest(unittest.TestCase):
    def test_shared_hook_shell_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n"],
            input=boot_script(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_actually_bootable_seagate_host_imports_hook(self) -> None:
        source = SEAGATE.read_text(encoding="utf-8")
        self.assertIn("./stage0-no-usb.nix", source)
        self.assertIn("./boot-approved-profiles.nix", source)
        self.assertIn('"/dev/disk/by-label/NIXOS2_EFI"', source)
        self.assertIn("config.boot.loader.efi.canTouchEfiVariables", source)

    def test_private_storage_uses_same_hook_after_luks_patch(self) -> None:
        source = STORAGE.read_text(encoding="utf-8")
        boot = BOOT.read_text(encoding="utf-8")
        self.assertIn("imports = [ ./boot-approved-profiles.nix ];", source)
        self.assertIn("heim-pc-private-storage patch-loader-entries", source)
        self.assertNotIn("select_approved_boot\n", source)
        self.assertIn('lib.mkAfter "${bootProfileSelection}/bin/heim-pc-boot-profile-selection"', boot)
        self.assertIn("pkgs.systemd", boot)
        self.assertIn("boot.loader.efi.canTouchEfiVariables = false;", source)

    def test_profiles_are_gc_pins_independent_of_system_generation(self) -> None:
        script = boot_script()
        self.assertIn("/nix/var/nix/profiles/system-profiles/$name", script)
        self.assertIn("pinned_entry heim-pc-approved", script)
        self.assertIn("pinned_entry heim-pc-recovery", script)
        self.assertIn('entry="nixos-$name-generation-$generation.conf"', script)
        self.assertIn('"$token" == "init=$closure/init"', script)
        self.assertNotIn("nixos-generation-42.conf", script)
        self.assertNotIn("nixos-generation-38.conf", script)

    def test_efi_override_and_recovery_are_both_verified(self) -> None:
        script = boot_script()
        self.assertIn('bootctl --esp-path=/boot set-default "$approved"', script)
        self.assertIn('bootctl --esp-path=/boot set-sysfail "$fallback"', script)
        self.assertIn('Default Entry: $approved', script)
        self.assertIn('SysFail Entry: $fallback', script)
        self.assertIn('grep -qxF "default $approved" "$conf"', script)
        self.assertIn('[[ "$(grep -c \'^default \' "$conf" || true)" == 1 ]]', script)

    def test_source_config_sort_key_matches_runtime_entries(self) -> None:
        module = BOOT.read_text(encoding="utf-8")
        self.assertIn(
            '"sort-key ${config.boot.loader.systemd-boot.sortKey}"', module
        )
        self.assertIn('grep -qxF ${lib.escapeShellArg loaderSortKeyLine}', module)

    def test_never_write_unmounted_esp_or_unsupported_arguments(self) -> None:
        script = boot_script()
        self.assertIn('[[ "$#" == 0 ]]', script)
        self.assertIn("findmnt --first-only -r -n -o FSTYPE --mountpoint /boot", script)
        self.assertIn('[[ "$closure" == /nix/store/*-nixos-system-*', script)


if __name__ == "__main__":
    unittest.main()
