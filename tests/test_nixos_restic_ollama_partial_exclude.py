"""Regression for volatile Ollama downloads breaking native Restic backup.

Only synthetic temporary files and a private test repository are used.
"""
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "nixos/system/modules/restic-seagate-backup.nix"
PRIVATE = "--exclude-file=/persist/secrets/restic/heim-pc-excludes"
PARTIAL = '--exclude-file=${pkgs.writeText "heim-pc-restic-hard-ollama-partials" "/home/alex/.local/share/heimgewebe/assist/ollama/models/blobs/*-partial-*\\n"}'
PLAINTEXT = '--exclude-file=${pkgs.writeText "heim-pc-restic-hard-plaintext-excludes" "**/*.sql.gz\\n"}'

class TestOllamaPartialExclusion(unittest.TestCase):
    def test_nix_contract_is_narrow_and_private_cannot_reenable(self):
        source = MODULE.read_text(encoding="utf-8")
        match = re.search(r"extraBackupArgs\s*=\s*\[(.*?)\];", source, re.S)
        self.assertIsNotNone(match)
        args = match.group(1)
        self.assertIn(PARTIAL, args)
        self.assertLess(args.index(PRIVATE), args.index(PARTIAL))
        self.assertLess(args.index(PARTIAL), args.index(PLAINTEXT))
        self.assertEqual(args.strip().splitlines()[-1].strip(), f'"{PLAINTEXT}"')
        self.assertNotIn("--ignore-errors", args)
        self.assertIn('"/home/alex"', source)

    def test_real_restic_keeps_completed_blob_and_home_data(self):
        binary = shutil.which("restic") or ("/run/current-system/sw/bin/restic" if Path("/run/current-system/sw/bin/restic").is_file() else None)
        if not binary:
            self.skipTest("Restic unavailable")
        with tempfile.TemporaryDirectory(prefix="restic-ollama-partial-") as tmp:
            base = Path(tmp)
            src = base / "home/alex/.local/share/heimgewebe/assist"
            blobs = src / "ollama/models/blobs"
            blobs.mkdir(parents=True)
            (blobs / "sha256-abc").write_text("completed model", encoding="utf-8")
            (blobs / "sha256-abc-partial-0").write_text("in progress", encoding="utf-8")
            (src / "personal.txt").write_text("ordinary data", encoding="utf-8")
            private = base / "private"
            private.write_text("!**/ollama/models/blobs/*-partial-*\n", encoding="utf-8")
            hard = base / "hard"
            hard.write_text(str(blobs / "*-partial-*") + "\n", encoding="utf-8")
            pw = base / "password"
            pw.write_text("test-only-password\n", encoding="utf-8")
            pw.chmod(0o600)
            cmd = [binary, "--no-cache", "-r", str(base / "repo"), "--password-file", str(pw)]
            def run(*args):
                p = subprocess.run([*cmd, *args], capture_output=True, text=True, timeout=50)
                self.assertEqual(p.returncode, 0, p.stderr[-1500:])
                return p.stdout
            run("init")
            run("backup", str(src), f"--exclude-file={private}", f"--exclude-file={hard}")
            rows = [json.loads(x) for x in run("ls", "latest", "--json").splitlines() if x.startswith("{")]
            paths = [str(x["path"]) for x in rows if x.get("type") == "file"]
            self.assertTrue(any(x.endswith("/personal.txt") for x in paths), paths)
            self.assertTrue(any(x.endswith("/sha256-abc") for x in paths), paths)
            self.assertFalse(any(x.endswith("/sha256-abc-partial-0") for x in paths), paths)
