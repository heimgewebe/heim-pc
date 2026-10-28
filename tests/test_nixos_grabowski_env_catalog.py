"""Regress the pinned NixOS Grabowski interpreter and catalog packaging.

The physical Gen5 boot showed exec -a changes CPython's sys.executable and
plain PYTHONPATH disappears under -I. These probes run without Nix builds,
network access, privileges, or writing to either physical system disk.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "nixos/system/modules/grabowski-operator-package.nix"


class NixGrabowskiEnvironmentTests(unittest.TestCase):
    def test_package_stages_store_owned_isolated_python(self) -> None:
        definition = PACKAGE.read_text()
        self.assertIn('ln -s ${python}/bin/python3.12 "$out/bin/python3"', definition)
        self.assertIn('> "$out/pyvenv.cfg"', definition)
        self.assertIn('makeWrapper "$out/bin/python3" "$out/bin/grabowski-operator"', definition)
        self.assertIn('--argv0 "$out/bin/grabowski-operator"', definition)
        self.assertIn('if original == "src/grabowski_runtime.py":', definition)
        self.assertIn('if original == "src/grabowski_coding_agent_router.py":', definition)
        self.assertIn("src/grabowski_runtime.py", definition)
        self.assertIn('sys.prefix == sys.base_prefix', definition)
        self.assertIn('importlib.util.find_spec("grabowski_job_finalizer")', definition)
        self.assertIn("coding_agent_catalog_health()", definition)
        self.assertNotIn("GRABOWSKI_CODING_AGENT_CATALOG_OVERRIDE=1", definition)

    def test_exec_a_venv_survives_python_isolated_mode(self) -> None:
        if not Path("/proc/self/exe").exists():
            self.skipTest("Linux procfs is required")
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / "venv"
            binary = root / "bin/python3"
            site = root / (
                f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
            )
            binary.parent.mkdir(parents=True)
            site.mkdir(parents=True)
            binary.symlink_to(Path(sys.executable).resolve(strict=True))
            (root / "pyvenv.cfg").write_text(
                f"home = {Path(sys.executable).resolve(strict=True).parent}\n"
                "include-system-site-packages = false\n"
            )
            (site / "grabowski_nixos_isolated_marker.py").write_text("ready = True\n")
            wrapper = root / "bin/grabowski-operator"
            actual_check = (
                "import importlib.util,sys\n"
                f"assert sys.prefix == {str(root)!r}, repr(sys.prefix)\n"
                f"assert sys.executable == {str(wrapper)!r}, repr(sys.executable)\n"
                "assert importlib.util.find_spec('grabowski_nixos_isolated_marker') is not None\n"
            )
            launcher = (
                "import os,sys\n"
                "os.execve(sys.argv[1],[sys.argv[2],'-I','-B','-c',sys.argv[3]],os.environ)\n"
            )
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            observed = subprocess.run(
                [sys.executable, "-B", "-c", launcher,
                 str(binary), str(wrapper), actual_check],
                text=True, capture_output=True, check=False, timeout=20,
                env=environment,
            )
            self.assertEqual(observed.returncode, 0, observed.stderr)


if __name__ == "__main__":
    unittest.main()
