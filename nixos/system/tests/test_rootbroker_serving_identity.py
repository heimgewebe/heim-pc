
"""Regression: Rootbroker follows root-owned active ExecStart, never stale Nix pin."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "modules/grabowski-nixos-unit-authority.py"
spec = importlib.util.spec_from_file_location("broker_nixos_authority", FILE)
assert spec and spec.loader
authority = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority)

OLD = "/nix/store/" + "a" * 32 + "-grabowski-operator-0d70eb0f/bin/grabowski-operator"
NEW = "/nix/store/" + "b" * 32 + "-grabowski-operator-68c8bcde/bin/grabowski-operator"


def show(entry: str) -> bytes:
    return (
        "{ path=" + entry + " ; argv[]=" + entry
        + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
        + " ; pid=0 ; code=(null) ; status=0/0 }\n"
    ).encode()


class RootbrokerServingIdentityTests(TestCase):
    def _observe(self, reply, **settings):
        result = SimpleNamespace(
            stdout=reply, stderr=settings.get("stderr", b""),
            returncode=settings.get("returncode", 0),
        )
        with patch.object(authority.subprocess, "run", return_value=result) as run:
            with patch.object(authority, "_safe_nix_store_directory", return_value=True):
                with patch.object(authority, "_safe_dir", return_value=True):
                    with patch.object(authority, "_safe_file", return_value=True):
                        outcome = authority.expected_operator_argv()
        self.assertEqual(
            run.call_args.args[0],
            [
                "/run/current-system/sw/bin/systemctl", "--system", "show",
                "grabowski-operator.service", "--property=ExecStart", "--value",
                "--no-pager",
            ],
        )
        return outcome

    def test_accepts_live_release_even_when_generated_pin_is_old(self):
        result = self._observe(show(NEW))
        self.assertEqual(result[0], NEW)
        self.assertEqual(result[1:], (
            "-m", "grabowski_operator", "--transport", "streamable-http",
            "--host", "127.0.0.1", "--port", "18181",
        ))

    def test_rejects_spoofed_argv_and_second_execstart(self):
        with self.assertRaises(PermissionError):
            self._observe(show(NEW).replace(
                ("argv[]=" + NEW).encode(), ("argv[]=" + OLD).encode()
            ))
        with self.assertRaises(PermissionError):
            self._observe(show(NEW) + show(OLD))

    def test_rejects_untrusted_or_arbitrary_paths(self):
        for path in (
            "/tmp/grabowski-operator",
            "/nix/store/" + "c" * 32 + "-other-operator-0d70eb0f/bin/grabowski-operator",
            "/nix/store/" + "c" * 32 + "-grabowski-operator-0d70eb0f/bin/sh",
        ):
            with self.subTest(path=path), self.assertRaises(PermissionError):
                self._observe(show(path))

    def test_denies_failed_or_malformed_pid1_observation(self):
        for reply, kwargs in (
            (show(NEW), {"returncode": 1}),
            (show(NEW), {"stderr": b"permission denied"}),
            (b"not-systemd", {}),
            (b"\xff" + show(NEW), {}),
            (b"x" * 4097, {}),
            (b"", {}),
        ):
            with self.subTest(reply=reply[:20], settings=kwargs):
                with self.assertRaises(PermissionError):
                    self._observe(reply, **kwargs)

    def test_legacy_explicit_build_fixture_still_supported(self):
        with patch.object(authority, "_safe_nix_store_directory", return_value=True):
            with patch.object(authority, "_safe_dir", return_value=True):
                with patch.object(authority, "_safe_file", return_value=True):
                    with patch.object(authority.subprocess, "run") as run:
                        result = authority.expected_operator_argv(
                            environ={"GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT": OLD}
                        )
        run.assert_not_called()
        self.assertEqual(result[0], OLD)


if __name__ == "__main__":
    main()
