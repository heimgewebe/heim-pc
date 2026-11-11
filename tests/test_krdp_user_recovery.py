"""Source-level regression for reproducible KRDP v13 user-service recovery.

The real iPad Windows App must still be independently accepted by a person.
"""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
FEATURE = ROOT / "runtime" / "krdp-ipad"
INSTALLER = FEATURE / "recover-user.sh"
RUNTIME = "/run/user/1000/krdp-ipad-native-v13/krdpserver"


class KrdpRecoveryTest(unittest.TestCase):
    def test_recovery_shell_syntax(self):
        result = subprocess.run(
            ["bash", "-n", str(INSTALLER)],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unit_and_kservice_are_bound_to_one_runtime_elf(self):
        unit = (FEATURE / "krdp-native-override.conf").read_text()
        desktop = (FEATURE / "org.kde.krdp-ipad-runtime-v13.desktop").read_text()
        installer = INSTALLER.read_text()
        self.assertIn("ExecStart=" + RUNTIME + " --address 127.0.0.1", unit)
        self.assertIn("Exec=" + RUNTIME + "\n", desktop)
        self.assertIn("X-KDE-Wayland-Interfaces=org_kde_kwin_fake_input", desktop)
        self.assertIn("store_binary=\"$(awk -v target=\"$runtime\"", installer)
        self.assertIn("sha256sum \"$store_binary\"", installer)
        self.assertIn("readlink -f \"/proc/$pid/exe\"", installer)
        self.assertIn("gc_root=", installer)

    def test_recovery_preserves_virtual_ipad_monitor_and_restart_order(self):
        source = INSTALLER.read_text()
        unit = (FEATURE / "krdp-native-override.conf").read_text()
        monitor = (FEATURE / "ipad-krdp-monitor.service").read_text()
        self.assertIn("source_monitor=", source)
        self.assertIn('cmp -s "$source_monitor" "$target_monitor"', source)
        self.assertIn('cp -p -- "$target_monitor" "$backup/monitor"', source)
        self.assertIn("KRDP has an active client; not restarting", source)
        self.assertLess(source.index('systemctl --user enable --now "$monitor_unit"'),
                        source.rindex('systemctl --user restart "$unit"'))
        self.assertIn("--resolution 1168x768 --name iPadKrdp --scale 1 --port -1", monitor)
        self.assertIn("--monitor-name Virtual-iPadKrdp --plasma", unit)

    def test_apply_never_restarts_live_rdp_client_or_kde(self):
        source = INSTALLER.read_text()
        self.assertIn("--check", source)
        self.assertIn("--apply", source)
        self.assertIn("ss -Htn state established sport :3390", source)
        self.assertIn("could not determine whether a KRDP client is connected", source)
        self.assertIn("KRDP has an active client; not restarting", source)
        self.assertIn("iPad monitor unit drift while active", source)
        self.assertLess(source.index("iPad monitor unit drift while active"),
                        source.index('install -Dm644 "$source_monitor" "$target_monitor"'))
        self.assertIn("[[ -S /run/user/1000/wayland-0 ]]", source)
        self.assertIn("systemctl --user restart \"$unit\"", source)
        self.assertNotIn("systemctl --user restart plasma-", source)
        self.assertNotIn("nixos-rebuild switch", source)
        self.assertNotIn("kscreen-doctor output.", source)

    def test_apply_has_existing_config_backup_and_rollback(self):
        source = INSTALLER.read_text()
        self.assertIn("mktemp -d", source)
        self.assertIn("cp -p -- \"$target_unit\" \"$backup/unit\"", source)
        self.assertIn("cp -p -- \"$target_desktop\" \"$backup/desktop\"", source)
        self.assertIn("trap rollback EXIT", source)
        self.assertIn("KRDP_RECOVERY_ROLLED_BACK", source)
        self.assertIn("KRDP_RECOVERY_APPLIED", source)
        self.assertIn("KRDP_RECOVERY_ALREADY_CURRENT", source)
        self.assertIn("nix-store --add-root", source)

    def test_readme_names_correct_recovery_path(self):
        readme = (FEATURE / "README.md").read_text()
        self.assertIn("recover-user.sh --check", readme)
        self.assertIn("recover-user.sh --apply", readme)
        self.assertIn("native iPad", readme)
        self.assertIn("PR #302", readme)


if __name__ == "__main__":
    unittest.main()
