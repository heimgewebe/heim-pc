from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_docker_storage_hygiene",
    ROOT / "scripts" / "install_docker_storage_hygiene.py",
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallDockerStorageHygieneTests(unittest.TestCase):
    def test_plan_is_commit_bound_and_contains_docker_unit_pair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="install-docker-storage-") as temporary:
            base = Path(temporary)
            home = base / "home"
            home.mkdir()
            head = "a" * 40

            def committed_blob(_head: str, relative: str) -> bytes:
                return (ROOT / relative).read_bytes()

            with (
                patch.object(installer, "identity", return_value=(head, False)),
                patch.object(installer, "blob", side_effect=committed_blob),
            ):
                receipt = installer.install(
                    home, base / "releases", False, False, False, head
                )
        self.assertEqual(receipt["repository_head"], head)
        self.assertFalse(receipt["repository_dirty"])
        self.assertEqual(len(receipt["planned"]), 4)
        planned = {Path(item["path"]).name for item in receipt["planned"]}
        self.assertEqual(
            planned,
            {
                "docker_storage_hygiene.py",
                "docker-storage-hygiene.v1.json",
                "heim-pc-docker-storage-hygiene.service",
                "heim-pc-docker-storage-hygiene.timer",
            },
        )

    def test_safe_systemd_path_rejects_whitespace(self) -> None:
        with self.assertRaises(installer.InstallError):
            installer.safe_systemd(Path("/tmp/unsafe path"))

    def test_ensure_directory_creates_and_verifies_private_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="install-docker-storage-") as temporary:
            path = Path(temporary) / "state"
            first = installer.ensure_directory(path)
            second = installer.ensure_directory(path)
            self.assertEqual(first["action"], "created")
            self.assertEqual(second["action"], "verified")
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_ensure_directory_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="install-docker-storage-") as temporary:
            base = Path(temporary)
            link = base / "state"
            link.symlink_to(base / "elsewhere")
            with self.assertRaisesRegex(installer.InstallError, "symlink directory"):
                installer.ensure_directory(link)

    def test_atomic_install_rejects_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="install-docker-storage-") as temporary:
            base = Path(temporary)
            destination = base / "target"
            destination.symlink_to(base / "elsewhere")
            with self.assertRaisesRegex(installer.InstallError, "symlink target"):
                installer.atomic(destination, b"payload", 0o600)


if __name__ == "__main__":
    unittest.main()
