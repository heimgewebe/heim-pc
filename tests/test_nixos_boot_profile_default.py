"""Regression guards for pinned systemd-boot profiles on the real Seagate host.

The tests do not claim a physical EFI write, reboot or MCP recovery.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
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

    def test_future_storage_install_remains_bootstrap_independent(self) -> None:
        source = STORAGE.read_text(encoding="utf-8")
        boot = BOOT.read_text(encoding="utf-8")
        # The future encrypted storage installer has no named GC profiles
        # during nixos-install. Do not install the Seagate promotion hook there.
        self.assertNotIn("./boot-approved-profiles.nix", source)
        self.assertIn("heim-pc-private-storage patch-loader-entries", source)
        self.assertNotIn("select_approved_boot", source)
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

    def test_shell_variable_initialization_uses_defined_name(self) -> None:
        script = boot_script()
        self.assertIn('local name="$1"\n        local link=', script)
        self.assertNotIn('local name="$1" link=', script)

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


    @staticmethod
    def _resolve_fixture(
        variants: list[str], *,
        title: str = "NixOS [heim-pc-approved]",
        version: str = "Generation 2 NixOS test",
        init_suffix: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        # Execute the actual pinned_entry Bash function against temporary
        # profile/ESP fixtures only; no root or bootloader mutation.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profiles = root / "profiles"
            entries = root / "boot/loader/entries"
            closure = root / "nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-heim-pc-26.05"
            profiles.mkdir()
            entries.mkdir(parents=True)
            closure.mkdir(parents=True)
            (closure / "init").write_text("#!/bin/sh\nexit 0\n")
            (closure / "init").chmod(0o755)
            (profiles / "heim-pc-approved-2-link").symlink_to(closure)
            (profiles / "heim-pc-approved").symlink_to("heim-pc-approved-2-link")
            filenames = []
            for index, variant in enumerate(variants):
                # Upstream hashes exactly the entry bytes, without a final LF.
                # Distinct valid hashes in one profile must remain ambiguous.
                contents = (
                    f"title {title}\n"
                    "sort-key nixos\n"
                    f"version {version}\n"
                    f"options init={closure}/init{init_suffix} root=fstab"
                )
                if index:
                    contents += f"\n# alternate entry {index}"
                digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
                if variant == "legacy":
                    filename = "nixos-heim-pc-approved-generation-2.conf"
                elif variant == "hash":
                    filename = f"nixos-{digest}.conf"
                elif variant == "counted":
                    filename = f"nixos-{digest}+3-0.conf"
                elif variant == "bad-hash":
                    filename = "nixos-" + "a" * 64 + ".conf"
                elif variant == "untrusted":
                    filename = "nixos-untrusted.conf"
                else:
                    raise ValueError(variant)
                (entries / filename).write_bytes(contents.encode("utf-8"))
                filenames.append(filename)

            script = boot_script()
            function = script.split("      pinned_entry() {", 1)[1].split(
                "\n      select_approved_boot()", 1
            )[0]
            function = "      pinned_entry() {" + function
            function = function.replace(
                "/nix/var/nix/profiles/system-profiles", str(profiles)
            ).replace(
                "/nix/store/*-nixos-system-*", str(root / "nix/store/*-nixos-system-*")
            ).replace(
                "/boot/loader/entries", str(entries)
            )
            result = subprocess.run(
                ["bash", "-c",
                 "set -euo pipefail\n"
                 "fail() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                 + function + "\npinned_entry heim-pc-approved\n"],
                text=True, capture_output=True, check=False,
            )
            return result, filenames

    def test_legacy_and_hash_named_approved_entries(self) -> None:
        for variant in ("legacy", "hash", "counted"):
            with self.subTest(variant=variant):
                result, filenames = self._resolve_fixture([variant])
                expected = filenames[0].replace("+3-0.conf", ".conf")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_hash_selection_rejects_wrong_identity_and_duplicates(self) -> None:
        invalid = [
            (["hash"], {"title": "NixOS [other]"}, "missing pinned boot entry"),
            (["hash"], {"version": "Generation 20 NixOS test"}, "missing pinned boot entry"),
            (["hash"], {"init_suffix": "-wrong"}, "pinned entry closure mismatch"),
            (["hash", "hash"], {}, "ambiguous pinned boot entries"),
            (["bad-hash"], {}, "missing pinned boot entry"),
            (["untrusted"], {}, "missing pinned boot entry"),
        ]
        for variants, overrides, error in invalid:
            with self.subTest(variants=variants, overrides=overrides):
                result, _ = self._resolve_fixture(variants, **overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)


if __name__ == "__main__":
    unittest.main()
