"""Exact EFI boot-default provenance tests, no host ESP access."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "nixos/system/hosts/heim-pc/efi-boot-default-audit.py"
spec = importlib.util.spec_from_file_location("heim_pc_efi_default", PARSER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

CLOSURE = "/nix/store/" + "a" * 32 + "-nixos-system-heim-pc-26.05.20261031.fa13731"
LEGACY = "nixos-heim-pc-approved-generation-2.conf"
HASHED = "nixos-" + "b" * 64 + ".conf"


class EfiDefaultReadbackTest(unittest.TestCase):
    @staticmethod
    def fixture(
        root: Path, *,
        entry: str = LEGACY,
        other_loader_default: str | None = None,
        options: str = "init=" + CLOSURE + "/init root=fstab",
    ) -> tuple[Path, Path, Path]:
        efi = root / "LoaderEntryDefault"
        loader = root / "loader.conf"
        entries = root / "entries"
        entries.mkdir()
        efi.write_bytes(b"\x07\x00\x00\x00" + entry.encode("utf-16-le") + b"\x00\x00")
        loader.write_text("timeout 5\ndefault " + (other_loader_default or entry) + "\n")
        (entries / entry).write_text("title NixOS\noptions " + options + "\n")
        return efi, loader, entries

    def test_efi_default_is_independent_of_latest_system_profile(self) -> None:
        # The system profile may already point at a staged Gen47 while
        # EFI remains on approved Gen46. The actual default is Gen46.
        with tempfile.TemporaryDirectory() as temp:
            efi, loader, entries = self.fixture(Path(temp))
            entry, system = module.read_efi_default(efi, loader, entries)
            self.assertEqual(entry, LEGACY)
            self.assertEqual(system, CLOSURE)

    def test_26_11_hash_named_entry_remains_parseable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            efi, loader, entries = self.fixture(Path(temp), entry=HASHED)
            self.assertEqual(module.read_efi_default(efi, loader, entries), (HASHED, CLOSURE))

    def test_negative_cases_fail_closed(self) -> None:
        cases = (
            ("mismatched-loader-default", "loader.conf and EFI default disagree"),
            ("ambiguous-loader-default", "loader.conf and EFI default disagree"),
            ("missing-entry", "EFI default entry missing or unsafe"),
            ("duplicate-init", "ambiguous init"),
            ("missing-init", "ambiguous init"),
            ("foreign-init", "not a NixOS system store closure"),
            ("bad-utf16", "variable"),
            ("embedded-null", "terminator"),
            ("unsafe-entry-symlink", "missing or unsafe"),
        )
        for case, message in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                efi, loader, entries = self.fixture(Path(temp))
                if case == "mismatched-loader-default":
                    loader.write_text("default nixos-generation-47.conf\n")
                elif case == "ambiguous-loader-default":
                    loader.write_text("default " + LEGACY + "\ndefault " + LEGACY + "\n")
                elif case == "missing-entry":
                    (entries / LEGACY).unlink()
                elif case == "duplicate-init":
                    (entries / LEGACY).write_text(
                        "options init=" + CLOSURE + "/init init=" + CLOSURE + "/init\n"
                    )
                elif case == "missing-init":
                    (entries / LEGACY).write_text("options root=fstab\n")
                elif case == "foreign-init":
                    (entries / LEGACY).write_text("options init=/tmp/foreign/init\n")
                elif case == "bad-utf16":
                    efi.write_bytes(b"\x07\x00\x00\x00\xff")
                elif case == "embedded-null":
                    efi.write_bytes(b"\x07\x00\x00\x00" + ("nixos\0-invalid.conf\0").encode("utf-16-le"))
                else:
                    (entries / LEGACY).unlink()
                    (entries / LEGACY).symlink_to(loader)
                with self.assertRaisesRegex((ValueError, UnicodeError), message):
                    module.read_efi_default(efi, loader, entries)

    def test_module_reports_actual_efi_default_and_protects_its_gc_root(self) -> None:
        nix = (ROOT / "nixos/system/modules/nix-lifecycle.nix").read_text()
        self.assertIn("efi-boot-default-audit.py", nix)
        self.assertIn('system_profile="$(resolve_link /nix/var/nix/profiles/system)"', nix)
        self.assertNotIn('boot_default="$(resolve_link /nix/var/nix/profiles/system)"', nix)
        self.assertIn("elif root_target_is_enumerated \"$boot_default\"; then", nix)
        self.assertIn("efi_boot_default_readback_ok: $efi_default_readback_ok", nix)
        self.assertIn("efi_boot_default_gc_rooted: $efi_default_gc_rooted", nix)
        self.assertIn("system_profile_system: $system_profile", nix)
        self.assertIn("boot_default_system: $boot_default", nix)


if __name__ == "__main__":
    unittest.main()
