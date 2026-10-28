"""Guard against XRDP FUSE redirects breaking the native NixOS Restic backup.

Only temporary synthetic files are used. Neither production credentials nor
the real /home/alex/thinclient_drives directory are accessed by these tests.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "nixos/system/modules/restic-seagate-backup.nix"
PRIVATE = "--exclude-file=/persist/secrets/restic/heim-pc-excludes"
XRDP_HARD = (
    '--exclude-file=${pkgs.writeText "heim-pc-restic-hard-xrdp-excludes" '
    '"/home/alex/thinclient_drives\\n"}'
)
PLAINTEXT_HARD = (
    '--exclude-file=${pkgs.writeText "heim-pc-restic-hard-plaintext-excludes" '
    '"**/*.sql.gz\\n"}'
)
TIMER = 'OnCalendar = "*-*-* 07,19:30:00";'


class NixOsResticXrdpExclusionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = MODULE.read_text(encoding="utf-8")

    def _backup_args(self) -> str:
        match = re.search(r"extraBackupArgs\s*=\s*\[(.*?)\];", self.module, re.S)
        self.assertIsNotNone(match)
        assert match is not None
        return match.group(1)

    def test_native_redirect_has_immutable_exclusion_after_private_and_before_plaintext(self) -> None:
        args = self._backup_args()
        self.assertEqual(args.count(PRIVATE), 1)
        self.assertEqual(args.count(XRDP_HARD), 1)
        self.assertEqual(args.count(PLAINTEXT_HARD), 1)
        self.assertLess(args.index(PRIVATE), args.index(XRDP_HARD))
        self.assertLess(args.index(XRDP_HARD), args.index(PLAINTEXT_HARD))
        self.assertEqual(args.strip().splitlines()[-1].strip(), f'"{PLAINTEXT_HARD}"')

    def test_exclude_never_drops_entire_home_or_ignores_restic_errors(self) -> None:
        paths = re.search(r"paths\s*=\s*\[(.*?)\];", self.module, re.S)
        self.assertIsNotNone(paths)
        assert paths is not None
        self.assertIn('"/home/alex"', paths.group(1))
        args = self._backup_args()
        self.assertIn("/home/alex/thinclient_drives", args)
        self.assertNotIn("--ignore-errors", args)
        self.assertNotIn("--one-file-system", args)
        self.assertNotIn("--exclude=/home/alex", args)
        self.assertNotIn('"--exclude=**"', args)

    def test_timer_has_margin_against_random_delay_and_24h_freshness(self) -> None:
        self.assertEqual(self.module.count(TIMER), 1)
        self.assertIn('RandomizedDelaySec = "10m";', self.module)
        self.assertIn("Persistent = true;", self.module)
        self.assertNotIn('OnCalendar = "19:30";', self.module)
        systemd_analyze = shutil.which("systemd-analyze")
        if systemd_analyze:
            result = subprocess.run(
                [systemd_analyze, "calendar", "*-*-* 07,19:30:00"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr[:1000])

    def test_real_restic_keeps_normal_files_and_excludes_only_redirect(self) -> None:
        binary = shutil.which("restic")
        if binary is None and Path("/run/current-system/sw/bin/restic").is_file():
            binary = "/run/current-system/sw/bin/restic"
        if binary is None:
            self.skipTest("Restic unavailable; static contract still enforced")
        with tempfile.TemporaryDirectory(prefix="restic-xrdp-synthetic-") as tmp:
            root = Path(tmp)
            source = root / "source"
            redirect = source / "thinclient_drives"
            redirect.mkdir(parents=True)
            (source / "ordinary-home-file.txt").write_text("kept", encoding="utf-8")
            (redirect / "session-only.txt").write_text("synthetic", encoding="utf-8")
            private = root / "private-excludes"
            private.write_text("!**/thinclient_drives\n!**/thinclient_drives/**\n",
                               encoding="utf-8")
            immutable = root / "hard-redirect-excludes"
            immutable.write_text(f"{redirect}\n", encoding="utf-8")
            password = root / "password"
            password.write_text("test-only-restic-password\n", encoding="utf-8")
            password.chmod(0o600)
            prefix = [binary, "--no-cache", "-r", str(root / "repo"),
                      "--password-file", str(password)]

            def run(*args: str) -> str:
                result = subprocess.run(
                    [*prefix, *args], capture_output=True, text=True,
                    check=False, timeout=50,
                )
                self.assertEqual(result.returncode, 0, result.stderr[:1400])
                return result.stdout

            run("init")

            def contents(*excludes: str) -> tuple[bool, bool]:
                run("backup", str(source), *excludes)
                rows = [
                    json.loads(line) for line in
                    run("ls", "latest", "--json").splitlines()
                    if line.strip().startswith("{")
                ]
                files = [str(row["path"]) for row in rows if row.get("type") == "file"]
                return (
                    any(path.endswith("/ordinary-home-file.txt") for path in files),
                    any(path.endswith("/thinclient_drives/session-only.txt") for path in files),
                )

            self.assertEqual(contents(
                f"--exclude-file={private}", f"--exclude-file={immutable}",
            ), (True, False))
            # An earlier hard-exclude loses authority if a later private
            # negation re-enables the redirect: the immutable rule must follow it.
            self.assertEqual(contents(
                f"--exclude-file={immutable}", f"--exclude-file={private}",
            ), (True, True))


if __name__ == "__main__":
    unittest.main()
