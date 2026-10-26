"""NixOS Photoatelier jobs remain scoped to Alex and preserve the validated transport gates."""

from pathlib import Path
import os
import shutil
import stat
import subprocess
import sys
import tempfile
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

    def test_missing_state_is_provisioned_before_sandbox_without_broadening_writes(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("systemd.tmpfiles.rules = [", source)
        for path in (
            "${home}/.local/share/fotoatelier/backups",
            "${home}/.local/share/fotoatelier/backups/current",
            "${stateRoot}",
        ):
            self.assertIn(f'd {path} 0700 alex users -', source)
        self.assertIn('ConditionPathExists = "${publicRepo}/.git";', source)
        self.assertNotIn('d ${publicRepo}', source)

        tmpfiles = shutil.which("systemd-tmpfiles")
        systemd_run = shutil.which("systemd-run")
        systemctl = shutil.which("systemctl")
        if not all((tmpfiles, systemd_run, systemctl)):
            self.skipTest("User systemd unavailable for isolated namespace test")
        manager = subprocess.run(
            [systemctl, "--user", "is-active", "default.target"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if manager.returncode != 0:
            self.skipTest("No active systemd user manager in this environment")

        # Never manipulate the actual Fotoatelier state, its public checkout,
        # or the original photo archive. Only synthetic disposable directories.
        home_state = Path.home() / ".local/state"
        if not home_state.is_dir():
            self.skipTest("No isolated test parent on this host")
        with tempfile.TemporaryDirectory(prefix=".fotoatelier-coldstart-", dir=home_state) as temp:
            root = Path(temp)
            backup = root / "backup"
            publisher = root / "publisher"
            self.assertFalse(backup.exists())
            self.assertFalse(publisher.exists())
            rules = root / "tmpfiles.conf"
            rules.write_text(
                f"d {backup} 0700 - - -\n"
                f"d {publisher} 0700 - - -\n", encoding="utf-8"
            )
            provision = subprocess.run(
                [tmpfiles, "--user", "--create", str(rules)],
                capture_output=True, text=True, timeout=20, check=False,
            )
            self.assertEqual(provision.returncode, 0, provision.stderr)
            for path in (backup, publisher):
                self.assertTrue(path.is_dir())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                self.assertEqual(path.stat().st_uid, os.getuid())

            write_synthetic_only = (
                "from pathlib import Path; import sys; "
                "[Path(x, 'probe').write_text('ok') for x in sys.argv[1:]]"
            )
            run = subprocess.run(
                [
                    systemd_run, "--user", "--quiet", "--wait", "--pipe",
                    "--collect", "-p", "Type=exec",
                    "-p", "ProtectHome=read-only", "-p", "ProtectSystem=strict",
                    "-p", f"ReadWritePaths={backup}",
                    "-p", f"ReadWritePaths={publisher}",
                    "-p", "NoNewPrivileges=yes", "-p", "PrivateTmp=yes",
                    sys.executable, "-c", write_synthetic_only, str(backup), str(publisher),
                ],
                capture_output=True, text=True, timeout=40, check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual((backup / "probe").read_text(), "ok")
            self.assertEqual((publisher / "probe").read_text(), "ok")

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
