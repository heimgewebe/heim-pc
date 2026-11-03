"""Keep Pop!_OS history outside the native NixOS retention selection."""

from __future__ import annotations

from pathlib import Path
import unittest


MODULE = (
    Path(__file__).resolve().parents[1]
    / "nixos/system/modules/restic-seagate-backup.nix"
)


class SeagateResticRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = MODULE.read_text(encoding="utf-8")
        self.retention = self.text.split(
            'systemd.services."heim-pc-restic-retention" = {', 1
        )[1].split(
            'systemd.timers."heim-pc-restic-retention" = {', 1
        )[0]

    def test_backup_keeps_fast_twice_daily_path(self) -> None:
        self.assertIn('pruneOpts = [ ];', self.text)
        self.assertIn('OnCalendar = "*-*-* 07,19:30:00";', self.text)
        self.assertIn('"--host=heim-pc-nixos"', self.text)
        self.assertIn('"--tag=nixos-seagate"', self.text)

    def test_retention_selects_nixos_only_and_never_unconditionally_unlocks(self) -> None:
        command = self.retention.split("script = ''", 1)[1]
        self.assertIn("restic forget --retry-lock=30m", command)
        self.assertIn("--host heim-pc-nixos --tag nixos-seagate", command)
        self.assertIn("--group-by host,paths,tags", command)
        self.assertIn("--keep-last 14 --keep-within 7d", command)
        self.assertIn("--keep-daily 14 --keep-weekly 8", command)
        self.assertIn("--keep-monthly 12 --keep-yearly 2", command)
        self.assertIn("restic prune --retry-lock=30m", command)
        self.assertNotIn("restic unlock\n", command)
        self.assertNotIn("--host heim-pc ", command)
        self.assertNotIn("--tag daily", command)

    def test_mount_guard_and_low_impact_weekly_timer(self) -> None:
        self.assertIn('RequiresMountsFor = [ "/var/lib/heim-pc-backup" "/persist" ];', self.retention)
        self.assertIn('test -f /var/lib/heim-pc-backup/restic/heim-pc/config', self.retention)
        self.assertIn('RESTIC_PASSWORD_FILE = "/persist/secrets/restic/heim-pc-password";', self.retention)
        self.assertIn('ProtectSystem = "strict";', self.retention)
        self.assertIn('ReadWritePaths = [ "/var/lib/heim-pc-backup" ];', self.retention)
        self.assertIn('CPUWeight = 30;', self.retention)
        self.assertIn('IOWeight = 20;', self.retention)
        self.assertIn('OnCalendar = "Sun *-*-* 03:30:00";', self.text)
        self.assertIn('Persistent = true;', self.text)


if __name__ == "__main__":
    unittest.main()
