"""Bind existing Grabowski post-merge reconciliation to its NixOS runtime."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "nixos/system/modules/grabowski-production.nix"
NAME = "grabowski-repoground-post-merge-reconcile"


class RepoGroundPostMergeNixOSContractTests(unittest.TestCase):
    def test_existing_immutable_operator_is_the_only_reconciler_runtime(self):
        data = SOURCE.read_text(encoding="utf-8")
        service = data.split(
            f'systemd.services."{NAME}" = lib.mkIf admit {{', 1
        )[1].split("systemd.timers.", 1)[0]
        # The publisher wrapper has a /usr/bin/env bash shebang, and the
        # unit PATH cannot assume an interactive shell environment.
        self.assertIn('path = [ cfg.operatorPackage pkgs.bash pkgs.git pkgs.openssh pkgs.systemd ];', service)
        self.assertIn(
            '${cfg.operatorPackage}/bin/python3 -I -B -m '
            'grabowski_repoground_post_merge --reconcile-audit-followups '
            '--reconcile-lookback-seconds 25200',
            service,
        )
        self.assertIn('User = "alex";', service)
        self.assertIn('Group = "users";', service)
        self.assertIn('"XDG_RUNTIME_DIR=/run/user/1000"', service)
        self.assertIn('"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"', service)
        self.assertNotIn('.local/share/grabowski-mcp/.venv', service)
        self.assertNotIn('systemctl start', service)
        self.assertNotIn('repoground-publish-fleet --', service)

    def test_existing_publisher_can_write_home_owned_output_roots(self):
        # RepoGround writes to ~/repos/manifest-publications, source clones,
        # ~/.local/state/repoground-publish and ~/logs/repoground-publish.
        data = SOURCE.read_text(encoding="utf-8")
        service = data.split(
            f'systemd.services."{NAME}" = lib.mkIf admit {{', 1
        )[1].split("systemd.timers.", 1)[0]
        self.assertIn('ProtectSystem = "full";', service)
        self.assertIn("ProtectHome = false;", service)
        self.assertNotIn('ProtectSystem = "strict";', service)
        self.assertNotIn('ProtectHome = "read-only";', service)
        self.assertNotIn("ReadWritePaths", service)

    def test_timer_reuses_level_triggered_verified_audit_scan(self):
        data = SOURCE.read_text(encoding="utf-8")
        timer = data.split(
            f'systemd.timers."{NAME}" = lib.mkIf admit {{', 1
        )[1].split('    # The root-only Restic proof', 1)[0]
        self.assertIn('wantedBy = [ "timers.target" ];', timer)
        self.assertIn('OnActiveSec = "15s";', timer)
        self.assertIn('OnUnitInactiveSec = "1min";', timer)
        self.assertIn('Persistent = true;', timer)
        self.assertIn(f'Unit = "{NAME}.service";', timer)
        self.assertNotIn('OnCalendar', timer)


if __name__ == "__main__":
    unittest.main()
