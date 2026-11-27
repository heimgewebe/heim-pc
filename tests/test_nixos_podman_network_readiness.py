"""Regression for the native Podman IPv4 readiness gate on the physical host."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "nixos/system/modules/containers.nix"


class PodmanNetworkReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "poll"
        self.state.write_text("0")
        self.source = MODULE.read_text()
        match = re.search(
            r'waitForPodmanIPv4 = pkgs\.writeShellScript "podman-wait-ipv4" \'\'\n(.*?)\n  \'\';',
            self.source,
            re.S,
        )
        self.assertIsNotNone(match, "Missing native Podman readiness script")
        script = match.group(1)
        # Run the actual shell body with deterministic synthetic interfaces.
        # The real Nix store command paths are checked in the Nix evaluation.
        programs = {
            "networkmanager": ("nmcli", """
import os, pathlib, sys
assert sys.argv[1:] == ["-t", "--escape", "no", "-f", "DEVICE,TYPE", "device", "status"]
poll = int(pathlib.Path(os.environ["POLL"]).read_text())
if os.environ.get("NM_FAIL_FIRST") == "1" and poll == 0:
    sys.exit(1)
print("tailscale0:tun", "lo:loopback", "enp-test:ethernet", "wlan-test:wifi", sep=chr(10))
"""),
            "iproute2": ("ip", """
import os, pathlib, sys
args = sys.argv[1:]
assert args[:5] == ["-4", "-o", "address", "show", "dev"]
assert args[6:] == ["scope", "global", "up"]
dev = args[5]
poll = int(pathlib.Path(os.environ["POLL"]).read_text())
if dev in ("tailscale0", "lo") or (
    dev == os.environ.get("READY_DEVICE") and poll >= int(os.environ.get("READY_AFTER", "0"))
):
    print(f"2: {dev} inet 192.0.2.2/24 scope global {dev}")
"""),
            "coreutils": ("sleep", """
import os, pathlib, sys
assert sys.argv[1:] == ["0.5"]
p = pathlib.Path(os.environ["POLL"])
count = int(p.read_text()) + 1
p.write_text(str(count))
if count >= 5:
    sys.exit(75)
"""),
        }
        for package, (name, body) in programs.items():
            cmd = self.root / name
            cmd.write_text(f"#!{sys.executable}\n" + body)
            cmd.chmod(0o700)
            script = script.replace("${pkgs." + package + "}/bin/" + name, str(cmd))
        script = script.replace("${pkgs.gnugrep}/bin/grep", "grep")
        self.assertNotIn("${pkgs.", script)
        self.script = self.root / "wait.sh"
        self.script.write_text(script)

    def run_gate(self, ready_device="", ready_after=0, nm_fail_first=False):
        env = {
            **os.environ,
            "POLL": str(self.state),
            "READY_DEVICE": ready_device,
            "READY_AFTER": str(ready_after),
            "NM_FAIL_FIRST": "1" if nm_fail_first else "0",
        }
        return subprocess.run(
            ["bash", str(self.script)],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )

    def test_existing_ipv4_address_requires_no_wait_or_default_route(self):
        r = self.run_gate("enp-test")
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual("0", self.state.read_text())
        self.assertIn("Physical IPv4 address available", r.stdout)

    def test_delayed_ipv4_address_waits_until_ready(self):
        r = self.run_gate("enp-test", ready_after=3)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual("3", self.state.read_text())

    def test_wifi_ipv4_address_is_also_supported(self):
        r = self.run_gate("wlan-test", ready_after=1)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual("1", self.state.read_text())

    def test_loopback_and_tailscale_do_not_count_as_physical_readiness(self):
        r = self.run_gate()
        self.assertEqual(75, r.returncode, r.stderr)
        self.assertEqual("", r.stderr)
        self.assertNotIn("Physical IPv4 address available", r.stdout)

    def test_transient_networkmanager_failure_retries(self):
        r = self.run_gate("enp-test", nm_fail_first=True)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual("1", self.state.read_text())

    def test_preserve_native_dependency_timeout_and_scope(self):
        block = self.source.split(
            "systemd.user.services.podman-user-wait-network-online =", 1
        )[1]
        self.assertIn('lib.mkIf (physicalHost && production && config.networking.networkmanager.enable)', block)
        self.assertIn('overrideStrategy = "asDropin";', block)
        self.assertIn("serviceConfig.ExecStartPost = waitForPodmanIPv4;", block)
        self.assertNotIn("serviceConfig.ExecStart =", block)
        self.assertNotIn("wantedBy", block)
        self.assertNotIn("TimeoutStartSec =", block)


if __name__ == "__main__":
    unittest.main()
