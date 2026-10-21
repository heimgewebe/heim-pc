"""Exercise the production Nixer NAR rehash shell, not only its Python preflight.

Nix and timeout are stubbed; tests neither fetch sources nor publish caches.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/heim-pc-nix.yml"
TRUST = ROOT / "nixos/production/trust-contract-v1.json"
LOCK = ROOT / "flake.lock"
MARKER = "NIXER_UPSTREAM_NAR_VERIFIED="
STEP = "      - name: Independently rehash pinned Nixer GitHub source\n        run: |\n"
EXPECTED_NAR = "sha256-zQCJ2ZI8ApEljh0U0+rrfBMK/DWkXHhzKIGHViyxG8A="


def _production_shell() -> str:
    source = WORKFLOW.read_text(encoding="utf-8")
    if source.count(STEP) != 1:
        raise AssertionError("exactly one Nixer upstream rehash step required")
    body = source.split(STEP, 1)[1].split("\n      - name:", 1)[0]
    shell = textwrap.dedent(body).strip("\n") + "\n"
    if not shell.startswith("set -euo pipefail\n"):
        raise AssertionError("rehash shell no longer starts fail-closed")
    return shell


NIX_STUB = """#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

mode = os.environ["NIX_TEST_MODE"]
args = sys.argv[1:]
with Path(os.environ["NIX_TEST_LOG"]).open("a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\\n")
if args[:2] == ["flake", "prefetch"]:
    if mode == "prefetch-fails":
        sys.exit(72)
    if mode == "prefetch-malformed":
        print("{invalid-json")
        sys.exit(0)
    result = {
        "hash": os.environ["NIX_TEST_EXPECTED_NAR"],
        "storePath": "/nix/store/12345678901234567890123456789012-source",
    }
    if mode == "prefetch-wrong-nar":
        result["hash"] = "sha256-" + "A" * 43 + "="
    elif mode == "prefetch-wrong-path":
        result["storePath"] = "/tmp/untrusted-source"
    elif mode == "prefetch-wrong-suffix":
        result["storePath"] = "/nix/store/12345678901234567890123456789012-wrong"
    elif mode == "prefetch-missing-hash":
        del result["hash"]
    print(json.dumps(result))
    sys.exit(0)
if args[:2] == ["hash", "path"]:
    if mode == "rehash-fails":
        sys.exit(73)
    print("sha256-" + "B" * 43 + "=" if mode == "rehash-wrong-nar" else
          os.environ["NIX_TEST_EXPECTED_NAR"])
    sys.exit(0)
sys.exit(97)
"""


class NixerNarRehashExecutionTests(unittest.TestCase):
    def _run_production(self, mode: str, *, shell: str | None = None) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory(prefix="heim-pc-nar-neg-") as temp:
            target = Path(temp)
            (target / "nixos/production").mkdir(parents=True)
            shutil.copyfile(TRUST, target / "nixos/production/trust-contract-v1.json")
            shutil.copyfile(LOCK, target / "flake.lock")
            bin_dir = target / "bin"
            bin_dir.mkdir()
            nix = bin_dir / "nix"
            nix.write_text(NIX_STUB, encoding="utf-8")
            nix.chmod(0o700)
            log = target / "nix-requests.log"
            if mode == "prefetch-timeout":
                timeout = bin_dir / "timeout"
                timeout.write_text("#!/bin/sh\nexit 124\n", encoding="utf-8")
                timeout.chmod(0o700)
            env = {
                **os.environ,
                "PATH": str(bin_dir) + ":/usr/bin:/bin",
                "NIX_TEST_MODE": mode,
                "NIX_TEST_LOG": str(log),
                "NIX_TEST_EXPECTED_NAR": EXPECTED_NAR,
            }
            completed = subprocess.run(
                ["/bin/bash", "-c", shell if shell is not None else _production_shell()],
                cwd=target, env=env, text=True, capture_output=True,
                check=False, timeout=15,
            )
            requests = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            return completed, requests

    def test_baseline_requires_independent_prefetch_and_store_path_hash(self) -> None:
        completed, requests = self._run_production("valid")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines(), [MARKER + EXPECTED_NAR])
        self.assertEqual(len(requests), 2, requests)
        self.assertIn("flake prefetch --json --refresh --no-write-lock-file github:heimgewebe/nixer/", requests[0])
        self.assertIn("hash path --type sha256 --sri /nix/store/", requests[1])
        self.assertNotIn("narHash=", requests[0])

    def test_adversarial_prefetch_and_rehash_fail_closed(self) -> None:
        failures = (
            "prefetch-fails",
            "prefetch-timeout",
            "prefetch-malformed",
            "prefetch-wrong-nar",
            "prefetch-wrong-path",
            "prefetch-wrong-suffix",
            "prefetch-missing-hash",
            "rehash-fails",
            "rehash-wrong-nar",
        )
        for attack in failures:
            with self.subTest(attack=attack):
                completed, _requests = self._run_production(attack)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertNotIn(MARKER, completed.stdout)

    def test_negative_cases_detect_removed_nar_guard(self) -> None:
        # Mutation challenge: prove the negative fixture would turn RED when
        # the production NAR equality guard is silently removed.
        original = _production_shell()
        required = 'test "$' + '{remote_values[0]}" = "$' + '{pin_values[1]}"'
        self.assertEqual(original.count(required), 1)
        weakened = original.replace(required, ': # intentionally weakened for mutation challenge', 1)
        completed, _requests = self._run_production("prefetch-wrong-nar", shell=weakened)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(MARKER + EXPECTED_NAR, completed.stdout)
