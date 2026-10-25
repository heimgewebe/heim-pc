"""NixOS Photoatelier jobs remain scoped to Alex and preserve the validated transport gates."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FLAKE = ROOT / "nixos/system/flake.nix"
MODULE = ROOT / "nixos/system/modules/fotoatelier.nix"


class FotoatelierNixOSSourceTests(unittest.TestCase):
    def test_only_full_operator_candidate_imports_fotoatelier(self):
        flake = FLAKE.read_text(encoding="utf-8")
        self.assertEqual(flake.count("./modules/fotoatelier.nix"), 1)
        full_operator = flake.split(
            "nixosConfigurations.heim-pc-seagate-grabowski-headless-candidate =", 1
        )[1].split("nixosModules.intentionalBreak =", 1)[0]
        self.assertIn("./modules/fotoatelier.nix", full_operator)
        baseline = flake.split(
            "nixosConfigurations.heim-pc-seagate-primary-candidate =", 1
        )[1].split("nixosConfigurations.heim-pc-vm =", 1)[0]
        self.assertNotIn("./modules/fotoatelier.nix", baseline)

    def test_backup_and_publisher_use_existing_local_scripts_and_readonly_hardening(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("systemd.user.services.fotoatelier-backup =", source)
        self.assertIn("systemd.user.services.fotoatelier-public-sync =", source)
        self.assertEqual(source.count('unitConfig.ConditionUser = "alex";'), 4)
        self.assertIn('ExecStart = "${python} ${source}/ops/fotoatelier-backup-sync.py";', source)
        self.assertIn('ExecStart = "${python} ${source}/ops/public-sync.py";', source)
        self.assertEqual(source.count('NoNewPrivileges = true;'), 2)
        self.assertEqual(source.count('ProtectHome = "read-only";'), 2)
        self.assertIn('ProtectSystem = "strict";', source)
        self.assertIn('ProtectSystem = "full";', source)
        self.assertIn('ReadWritePaths = [ publicRepo stateRoot ];', source)
        self.assertIn('ReadWritePaths = [ "${home}/.local/share/fotoatelier/backups" ];', source)
        self.assertNotIn("Tailscale Funnel", source)
        self.assertNotIn("ExecCondition", source)
        self.assertNotIn('User = "root";', source)
        self.assertNotIn('ProtectHome = false', source)

    def test_calendar_matches_current_proven_user_timers(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn('systemd.user.timers.fotoatelier-backup =', source)
        self.assertIn('systemd.user.timers.fotoatelier-public-sync =', source)
        self.assertEqual(source.count('wantedBy = [ "timers.target" ];'), 2)
        self.assertIn('OnCalendar = "*-*-* 08,12,16,20:20:00";', source)
        self.assertIn('RandomizedDelaySec = "20min";', source)
        self.assertIn('OnUnitActiveSec = "5min";', source)
        self.assertIn('OnBootSec = "1min";', source)
        self.assertIn('GIT_SSH_COMMAND=${pkgs.openssh}/bin/ssh -F ${sshConfig}', source)
        self.assertIn('FOTOATELIER_SSH_CONFIG=${sshConfig}', source)
        self.assertEqual(source.count('Persistent = true;'), 2)


if __name__ == "__main__":
    unittest.main()
