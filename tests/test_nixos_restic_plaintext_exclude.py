"""Regression for NixOS Restic snapshot-time PostgreSQL plaintext exclusion.

The private exclude file may contain a negation. A final Nix-store exclude
file must prevent any late plaintext dump from entering the actual archive.
All backup contents and credentials used here are disposable fixtures.
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
FINAL = (
    '--exclude-file=${pkgs.writeText "heim-pc-restic-hard-plaintext-excludes" '
    '"**/*.sql.gz\\n"}'
)


class ResticPlaintextExclusionTests(unittest.TestCase):
    def test_immutable_plaintext_rule_is_last_native_restic_exclusion(self):
        module = MODULE.read_text(encoding="utf-8")
        match = re.search(r'extraBackupArgs\s*=\s*\[(.*?)\];', module, re.S)
        self.assertIsNotNone(match)
        assert match is not None
        args = match.group(1)
        self.assertEqual(args.count(PRIVATE), 1)
        self.assertEqual(args.count(FINAL), 1)
        self.assertLess(args.index(PRIVATE), args.index(FINAL))
        self.assertEqual(args.strip().splitlines()[-1].strip(), f'"{FINAL}"')
        self.assertNotIn('"--exclude=**/*.sql.gz"', args)
        self.assertIn('"--retry-lock=30m"', args)

    def test_real_restic_late_plaintext_and_negative_rule_cannot_override_final_exclude(self):
        restic = shutil.which("restic")
        if restic is None:
            self.skipTest("Restic executable absent; NixOS evaluation is required")
        with tempfile.TemporaryDirectory(prefix="restic-hard-deny-") as tmp:
            root = Path(tmp)
            source = root / "source" / "dumps"
            source.mkdir(parents=True)
            plain = source / "2026-postgres.sql.gz"
            cipher = source / "2026-postgres.sql.gz.age"
            plain.write_bytes(b"synthetic-plaintext-postgres-dump")
            cipher.write_bytes(b"synthetic-age-named-file-not-production-ciphertext")
            private = root / "private-excludes"
            private.write_text("!**/*.sql.gz\n", encoding="utf-8")
            immutable = root / "immutable-excludes"
            immutable.write_text("**/*.sql.gz\n", encoding="utf-8")
            passwd = root / "test-password"
            passwd.write_text("temporary-test-password\n", encoding="utf-8")
            passwd.chmod(0o600)
            prefix = [restic, "--no-cache", "-r", str(root / "repo"),
                      "--password-file", str(passwd)]

            def run(*args: str) -> str:
                p = subprocess.run(
                    [*prefix, *args], capture_output=True, text=True,
                    check=False, timeout=40,
                )
                self.assertEqual(p.returncode, 0, p.stderr[:1000])
                return p.stdout

            run("init")

            def check_snapshot(*exclude_args: str) -> tuple[bool, bool]:
                run("backup", str(source), *exclude_args)
                rows = [
                    json.loads(line) for line in
                    run("ls", "latest", "--json").splitlines()
                    if line.strip().startswith("{")
                ]
                files = [row["path"] for row in rows if row.get("type") == "file"]
                return (
                    any(name.endswith("/2026-postgres.sql.gz") for name in files),
                    any(name.endswith("/2026-postgres.sql.gz.age") for name in files),
                )

            # Negative: an earlier hard rule can be undone by a later
            # private-file negation. The final hard file must come last.
            self.assertEqual(check_snapshot(
                f"--exclude-file={immutable}", f"--exclude-file={private}",
            ), (True, True))
            self.assertEqual(check_snapshot(
                f"--exclude-file={private}", f"--exclude-file={immutable}",
            ), (False, True))


if __name__ == "__main__":
    unittest.main()