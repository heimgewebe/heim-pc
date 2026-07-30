from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest import mock

from scripts import tunnel_profile_diagnostics as diagnostics


PROFILE_TEMPLATE = """config_version: 1
control_plane:
  tunnel_id: \"{profile}-id\"
  api_key: \"file:/private/{secret}\"
health:
  listen_addr: \"{listen_addr}\"
admin_ui:
  open_browser: false
mcp:
  server_urls:
    - channel: main
      url: \"http://127.0.0.1:9999/mcp\"
"""


class TunnelProfileDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.profile_dir = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_profile(
        self,
        profile: str,
        listen_addr: str,
        *,
        secret: str = "do-not-print",
    ) -> Path:
        path = self.profile_dir / f"{profile}.yaml"
        path.write_text(
            PROFILE_TEMPLATE.format(
                profile=profile,
                listen_addr=listen_addr,
                secret=secret,
            ),
            encoding="utf-8",
        )
        return path

    def write_canonical_profiles(self) -> None:
        for profile, listen_addr in diagnostics.CANONICAL_LISTENERS.items():
            self.write_profile(profile, listen_addr)

    def test_diagnose_reports_duplicate_and_canonical_mismatch_without_secrets(
        self,
    ) -> None:
        self.write_profile("grabowski", "127.0.0.1:18080", secret="alpha-secret")
        self.write_profile("heim-pc-dashboard", "127.0.0.1:18081", secret="beta-secret")
        self.write_profile(
            "grabowski-johannes", "127.0.0.1:18081", secret="gamma-secret"
        )

        result = diagnostics.diagnose(self.profile_dir)
        encoded = json.dumps(result, sort_keys=True)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(
            result["duplicates"],
            [
                {
                    "listen_addr": "127.0.0.1:18081",
                    "profiles": ["grabowski-johannes", "heim-pc-dashboard"],
                }
            ],
        )
        self.assertEqual(
            result["canonical_mismatches"],
            [
                {
                    "profile": "grabowski-johannes",
                    "actual": "127.0.0.1:18081",
                    "expected": "127.0.0.1:18083",
                }
            ],
        )
        self.assertNotIn("alpha-secret", encoded)
        self.assertNotIn("beta-secret", encoded)
        self.assertNotIn("gamma-secret", encoded)

    def test_diagnose_passes_for_unique_canonical_assignments(self) -> None:
        self.write_canonical_profiles()

        result = diagnostics.diagnose(self.profile_dir)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["duplicates"], [])
        self.assertEqual(result["canonical_mismatches"], [])
        self.assertEqual(result["missing_known_profiles"], [])

    def test_repair_is_atomic_preserves_unrelated_content_and_mode(self) -> None:
        self.write_profile("grabowski", "127.0.0.1:18080")
        self.write_profile("heim-pc-dashboard", "127.0.0.1:18081")
        target = self.write_profile(
            "grabowski-johannes", "127.0.0.1:18081", secret="retained-secret"
        )
        target.chmod(0o640)

        with mock.patch.object(diagnostics, "endpoint_is_available", return_value=True):
            result = diagnostics.repair_profile(
                self.profile_dir,
                profile="grabowski-johannes",
                expected_current="127.0.0.1:18081",
                new_listen_addr="127.0.0.1:18083",
            )

        self.assertEqual(result["status"], "repaired")
        text = target.read_text(encoding="utf-8")
        self.assertIn('listen_addr: "127.0.0.1:18083"', text)
        self.assertIn("retained-secret", text)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertEqual(diagnostics.diagnose(self.profile_dir)["status"], "pass")

    def test_repair_rejects_stale_expected_value_without_writing(self) -> None:
        self.write_canonical_profiles()
        target = self.profile_dir / "grabowski-johannes.yaml"
        before = target.read_bytes()

        with self.assertRaisesRegex(
            diagnostics.TunnelProfileError, "changed since preflight"
        ):
            diagnostics.repair_profile(
                self.profile_dir,
                profile="grabowski-johannes",
                expected_current="127.0.0.1:18081",
                new_listen_addr="127.0.0.1:18083",
            )

        self.assertEqual(target.read_bytes(), before)

    def test_repair_rejects_listener_occupied_outside_profile_set(self) -> None:
        self.write_profile("grabowski", "127.0.0.1:18080")
        self.write_profile("heim-pc-dashboard", "127.0.0.1:18081")
        self.write_profile("grabowski-johannes", "127.0.0.1:19001")
        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        occupied.bind(("127.0.0.1", 0))
        desired = f"127.0.0.1:{occupied.getsockname()[1]}"
        try:
            with mock.patch.dict(
                diagnostics.CANONICAL_LISTENERS,
                {"grabowski-johannes": desired},
            ):
                with self.assertRaisesRegex(
                    diagnostics.TunnelProfileError, "already in use"
                ):
                    diagnostics.repair_profile(
                        self.profile_dir,
                        profile="grabowski-johannes",
                        expected_current="127.0.0.1:19001",
                        new_listen_addr=desired,
                    )
        finally:
            occupied.close()

    def test_symlink_profile_is_refused(self) -> None:
        real = self.profile_dir / "real.yaml"
        real.write_text(
            PROFILE_TEMPLATE.format(
                profile="real", listen_addr="127.0.0.1:19000", secret="hidden"
            ),
            encoding="utf-8",
        )
        os.symlink(real, self.profile_dir / "alias.yaml")

        with self.assertRaisesRegex(diagnostics.TunnelProfileError, "unsafe"):
            diagnostics.diagnose(self.profile_dir)

    def test_cli_error_output_does_not_echo_profile_contents(self) -> None:
        self.write_profile("grabowski", "not-an-endpoint", secret="never-echo-this")
        output = io.StringIO()

        with redirect_stdout(output):
            return_code = diagnostics.main(["--profile-dir", str(self.profile_dir)])

        self.assertEqual(return_code, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "error")
        self.assertNotIn("never-echo-this", output.getvalue())


if __name__ == "__main__":
    unittest.main()
