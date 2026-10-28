"""Regression for scheduled NixOS Restic backups sharing a repository with checks."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


MODULE = (
    Path(__file__).resolve().parents[1]
    / "nixos/system/modules/restic-seagate-backup.nix"
)


class SeagateNativeResticLockWaitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = MODULE.read_text(encoding="utf-8")

    def test_native_backup_waits_for_existing_integrity_check_lock(self) -> None:
        match = re.search(
            r'extraBackupArgs\s*=\s*\[(.*?)\];', self.module, re.DOTALL
        )
        self.assertIsNotNone(match)
        assert match is not None
        args = re.findall(r'"([^"]+)"', match.group(1))
        self.assertEqual(args.count("--retry-lock=30m"), 1)
        self.assertNotIn("--no-lock", args)
        self.assertIn("--host=heim-pc-nixos", args)
        self.assertIn("--tag=nixos-seagate", args)

    def test_wait_is_finite_and_the_native_timer_is_preserved(self) -> None:
        self.assertIn('OnCalendar = "19:30";', self.module)
        self.assertIn('RandomizedDelaySec = "10m";', self.module)
        self.assertIn('Persistent = true;', self.module)
        self.assertIn('initialize = false;', self.module)
        self.assertIn('pruneOpts = [ ];', self.module)
        self.assertIn('RequiresMountsFor', self.module)
        self.assertIn('test -f /var/lib/heim-pc-backup/restic/heim-pc/config', self.module)
        self.assertNotIn("backupCleanupCommand", self.module)


if __name__ == "__main__":
    unittest.main()
