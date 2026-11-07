"""Static NixOS binding checks; destructive effects are tested separately."""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "nixos/system/modules/restic-seagate-backup.nix"
RETENTION = ROOT / "nixos/system/modules/heim-pc-restic-retention.py"


class SeagateResticRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = MODULE.read_text(encoding="utf-8")
        self.retention = self.module.split(
            'systemd.services."heim-pc-restic-retention" = {', 1
        )[1].split('systemd.timers."heim-pc-restic-retention" = {', 1)[0]
        self.script = RETENTION.read_text(encoding="utf-8")

    def test_twice_daily_backup_survives_with_extended_lock_wait(self) -> None:
        self.assertIn('pruneOpts = [ ];', self.module)
        self.assertIn('OnCalendar = "*-*-* 07,19:30:00";', self.module)
        self.assertIn('"--retry-lock=6h"', self.module)
        self.assertIn('"--host=heim-pc-nixos"', self.module)
        self.assertIn('"--tag=nixos-seagate"', self.module)

    def test_retention_is_automatic_but_only_for_recent_complete_backups(self) -> None:
        self.assertNotIn("ConditionPathExists", self.retention)
        self.assertIn('heim-pc-restic-retention.py', self.retention)
        self.assertNotIn("pkgs.openssl", self.retention)
        self.assertIn('ReadWritePaths = [ "/var/lib/heim-pc-backup" ];', self.retention)
        self.assertIn('RequiresMountsFor = [ "/var/lib/heim-pc-backup" "/persist" ];', self.retention)
        self.assertIn('restic("forget", "--dry-run", "--json", "--retry-lock=6h"', self.script)
        self.assertIn('restic("forget", "--retry-lock=6h", *removed', self.script)
        self.assertIn('restic("prune", "--retry-lock=6h"', self.script)
        self.assertIn("latest_healthy_snapshot", self.script)
        self.assertNotIn("independent_proof", self.script)
        self.assertIn("MAX_BACKUP_AGE = 72 * 3600", self.script)
        self.assertNotIn('restic unlock', self.script)

    def test_pop_os_history_is_never_targeted_by_policy(self) -> None:
        self.assertIn('HOST, TAG = "heim-pc-nixos", "nixos-seagate"', self.script)
        self.assertIn('"--host", HOST, "--tag", TAG', self.script)
        self.assertIn("sid == protected_snapshot", self.script)
        self.assertIn('snap.get("hostname") != HOST', self.script)

    def test_retention_timer_and_non_suspending_io(self) -> None:
        self.assertIn('OnCalendar = "Sun *-*-* 03:30:00";', self.module)
        self.assertIn('Persistent = true;', self.module)
        self.assertIn('RandomizedDelaySec = "30m";', self.module)
        self.assertIn('systemd-inhibit --mode=block --what=sleep', self.retention)
        self.assertIn('TimeoutStartSec = "0";', self.retention)
        self.assertIn('PrivateNetwork = true;', self.retention)
        self.assertIn('CPUWeight = 30;', self.retention)
        self.assertIn('IOWeight = 20;', self.retention)


if __name__ == "__main__":
    unittest.main()