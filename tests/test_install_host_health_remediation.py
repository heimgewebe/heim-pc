from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "install_host_health_remediation",
    ROOT / "scripts/install_host_health_remediation.py",
)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def run_git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


@contextmanager
def committed_source():
    with tempfile.TemporaryDirectory() as directory:
        repository = Path(directory)
        for source_relative, _target_relative, _mode in installer.FILES:
            destination = repository / source_relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source_relative, destination)
        run_git(repository, "init", "-q")
        run_git(repository, "config", "user.name", "Test")
        run_git(repository, "config", "user.email", "test@example.invalid")
        run_git(repository, "add", ".")
        run_git(repository, "commit", "-q", "-m", "fixture")
        yield repository, run_git(repository, "rev-parse", "HEAD")


def install_fixture(
    source: Path,
    head: str,
    target: Path,
    *,
    apply: bool,
):
    return installer.install(
        source_root=source,
        target_root=target,
        apply=apply,
        expected_head=head,
    )


def merged_journald_values(cat_config: str) -> dict[str, str]:
    section: str | None = None
    values: dict[str, str] = {}
    for raw_line in cat_config.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == "Journal" and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


class InstallHostHealthRemediationTests(unittest.TestCase):
    def tearDown(self) -> None:
        installer.TRANSACTION_FAULT_HOOK = None

    def test_plan_has_no_side_effects_and_is_commit_bound(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            committed_wrapper = (
                source / "scripts/ensure_performance_profile.py"
            ).read_bytes()
            (source / "scripts/ensure_performance_profile.py").write_bytes(
                b"malicious mutable worktree bytes\n"
            )

            receipt = install_fixture(source, head, target, apply=False)

            self.assertFalse(receipt["apply"])
            self.assertFalse(receipt["valid"])
            self.assertTrue(receipt["repository_dirty"])
            self.assertEqual(list(target.iterdir()), [])
            wrapper = next(
                item
                for item in receipt["files"]
                if item["source"] == "scripts/ensure_performance_profile.py"
            )
            self.assertEqual(wrapper["source_sha256"], installer._sha256(committed_wrapper))
            self.assertNotEqual(
                wrapper["source_sha256"],
                installer._sha256(b"malicious mutable worktree bytes\n"),
            )
            self.assertFalse(
                receipt["source_binding"]["mutable_worktree_source_bytes_used"]
            )

    def test_apply_reads_expected_git_object_after_one_time_identity_check(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            committed = (source / "scripts/host_health_diagnostics.py").read_bytes()

            def identity_then_mutate(_root: Path):
                (source / "scripts/host_health_diagnostics.py").write_bytes(b"substituted\n")
                return head, False

            with mock.patch.object(
                installer, "repository_identity", side_effect=identity_then_mutate
            ):
                receipt = install_fixture(source, head, target, apply=True)

            installed = target / "usr/local/sbin/heim-pc-host-health"
            self.assertEqual(installed.read_bytes(), committed)
            self.assertNotEqual(installed.read_bytes(), b"substituted\n")
            self.assertEqual(receipt["repository_head"], head)

    def test_apply_requires_full_expected_head(self) -> None:
        with committed_source() as (source, _head), tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(installer.InstallError, "requires"):
                installer.install(
                    source_root=source,
                    target_root=Path(directory),
                    apply=True,
                    expected_head=None,
                )

    def test_apply_waits_for_exclusive_installer_lock(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            lock_path = target / installer.LOCK_RELATIVE
            lock_path.parent.mkdir(parents=True)
            lock_handle = lock_path.open("w+b")
            installer.fcntl.flock(lock_handle.fileno(), installer.fcntl.LOCK_EX)
            identity_reached = threading.Event()
            failures: list[BaseException] = []

            original_identity = installer.repository_identity

            def observed_identity(root: Path):
                identity_reached.set()
                return original_identity(root)

            def worker() -> None:
                try:
                    install_fixture(source, head, target, apply=True)
                except BaseException as exc:
                    failures.append(exc)

            with mock.patch.object(
                installer,
                "repository_identity",
                side_effect=observed_identity,
            ):
                thread = threading.Thread(target=worker)
                thread.start()
                self.assertFalse(identity_reached.wait(0.1))
                installer.fcntl.flock(lock_handle.fileno(), installer.fcntl.LOCK_UN)
                lock_handle.close()
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertTrue(identity_reached.is_set())
            self.assertEqual(failures, [])

    def test_apply_is_idempotent_and_verifies_modes_ownership_and_receipt(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            first = install_fixture(source, head, target, apply=True)
            second = install_fixture(source, head, target, apply=True)

            self.assertTrue(
                all(
                    item["action"] == "installed"
                    for item in first["files"]
                    if item["operation"] == "install"
                )
            )
            self.assertTrue(
                all(
                    item["action"] == "unchanged"
                    for item in second["files"]
                    if item["operation"] == "install"
                )
            )
            for _source, target_relative, mode in installer.FILES:
                installed = target / target_relative
                metadata = installed.stat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), mode)
                self.assertEqual(metadata.st_uid, os.geteuid())
                self.assertEqual(metadata.st_gid, os.getegid())
            receipt_path = target / installer.RECEIPT_RELATIVE
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted, second)
            self.assertTrue(persisted["transaction"]["partial_failure_rollback"])
            self.assertTrue(persisted["transaction"]["descriptor_relative_nofollow"])

    def test_migration_backs_up_and_removes_all_legacy_files(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            legacy: dict[str, bytes] = {
                "etc/systemd/journald.conf.d/50-heim-pc-retention.conf": b"[Journal]\nSystemMaxUse=512M\n",
                "etc/systemd/journald.conf.d/99-heim-pc-retention.conf": b"[Journal]\nSystemMaxUse=1G\n",
                "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf": (
                    b"[Service]\nExecStart=\nExecStart=/usr/local/sbin/heim-pc-set-performance-profile\n"
                ),
                "usr/local/sbin/heim-pc-set-performance-profile": b"#!/bin/sh\nexit 0\n",
                "etc/systemd/user/fluidsynth.service.d/10-interactive-user.conf": (
                    b"[Unit]\nConditionUser=alex\n"
                ),
                "etc/systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf": (
                    b"[Unit]\nConditionUser=!gdm\n"
                ),
            }
            for relative, data in legacy.items():
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            plan = install_fixture(source, head, target, apply=False)
            self.assertEqual(
                {
                    item["target"]: item["action"]
                    for item in plan["files"]
                    if item["operation"] == "remove_obsolete"
                },
                {
                    str(target / relative): "planned_removal"
                    for relative in legacy
                },
            )
            for relative, data in legacy.items():
                self.assertEqual((target / relative).read_bytes(), data)

            receipt = install_fixture(source, head, target, apply=True)
            removal_results = [
                item for item in receipt["files"] if item["operation"] == "remove_obsolete"
            ]
            self.assertEqual(
                {item["action"] for item in removal_results},
                {"removed"},
            )
            for item in removal_results:
                relative = str(Path(item["target"]).relative_to(target))
                self.assertFalse(Path(item["target"]).exists())
                self.assertEqual(Path(item["backup"]).read_bytes(), legacy[relative])
                backup_stat = Path(item["backup"]).stat()
                self.assertEqual(stat.S_IMODE(backup_stat.st_mode), 0o600)
                self.assertEqual(backup_stat.st_uid, os.geteuid())
                self.assertEqual(backup_stat.st_gid, os.getegid())

    def test_effective_systemd_composition_resets_legacy_values(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            cpu_legacy = (
                target
                / "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf"
            )
            cpu_legacy.parent.mkdir(parents=True)
            cpu_legacy.write_text(
                "[Service]\nExecStart=\nExecStart=/unsafe/profile\n",
                encoding="utf-8",
            )
            fluid_legacy = (
                target
                / "etc/systemd/user/fluidsynth.service.d/10-interactive-user.conf"
            )
            fluid_legacy.parent.mkdir(parents=True)
            fluid_legacy.write_text("[Unit]\nConditionUser=alex\n", encoding="utf-8")

            receipt = install_fixture(source, head, target, apply=True)
            composition = installer.verify_effective_composition(target)
            self.assertEqual(
                composition["cpu_governor"]["exec_start"],
                [installer.STRICT_PROFILE],
            )
            self.assertEqual(
                composition["fluidsynth"]["condition_user"],
                ["!gdm"],
            )
            self.assertEqual(receipt["effective_systemd_composition"], composition)
            cpu_reset = (
                target
                / "etc/systemd/system/cpu-governor.service.d/zz-heim-pc-strict-profile.conf"
            ).read_text(encoding="utf-8")
            fluid_reset = (
                target
                / "etc/systemd/user/fluidsynth.service.d/zz-heim-pc-gdm-guard.conf"
            ).read_text(encoding="utf-8")
            self.assertIn("ExecStart=\n", cpu_reset)
            self.assertIn("ConditionUser=\n", fluid_reset)
            self.assertNotIn("alex", fluid_reset)

    def test_later_conflicting_drop_in_fails_preflight_without_target_mutation(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            legacy = (
                target
                / "etc/systemd/user/fluidsynth.service.d/10-interactive-user.conf"
            )
            conflict = (
                target
                / "etc/systemd/user/service.d/zzz-foreign.conf"
            )
            legacy.parent.mkdir(parents=True)
            conflict.parent.mkdir(parents=True)
            legacy.write_text("[Unit]\nConditionUser=alex\n", encoding="utf-8")
            conflict.write_text("[Unit]\nConditionUser=alex\n", encoding="utf-8")

            with self.assertRaisesRegex(installer.InstallError, "ConditionUser"):
                install_fixture(source, head, target, apply=True)

            self.assertTrue(legacy.exists())
            self.assertEqual(
                conflict.read_text(encoding="utf-8"),
                "[Unit]\nConditionUser=alex\n",
            )
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse(
                (target / "usr/local/sbin/heim-pc-host-health").exists()
            )

    def test_partial_failure_rolls_back_targets_backups_and_receipt(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            cpu = target / "etc/systemd/system/cpu-governor.service"
            cpu.parent.mkdir(parents=True)
            original_cpu = b"[Service]\nExecStart=/original\n"
            cpu.write_bytes(original_cpu)
            legacy = (
                target
                / "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf"
            )
            legacy.parent.mkdir(parents=True)
            original_legacy = b"[Service]\nExecStart=/legacy\n"
            legacy.write_bytes(original_legacy)

            def fail_after_third(index: int, _relative: str) -> None:
                if index == 3:
                    raise RuntimeError("injected commit failure")

            installer.TRANSACTION_FAULT_HOOK = fail_after_third
            with self.assertRaisesRegex(installer.InstallError, "rolled back"):
                install_fixture(source, head, target, apply=True)

            self.assertEqual(cpu.read_bytes(), original_cpu)
            self.assertEqual(legacy.read_bytes(), original_legacy)
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            backup_root = target / installer.BACKUP_ROOT_RELATIVE
            self.assertFalse(backup_root.exists())
            self.assertFalse(
                (target / "usr/local/libexec/heim-pc/ensure-performance-profile").exists()
            )

    def test_staging_failure_removes_all_temporary_files(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            original_write_temp = installer._write_temp
            calls = 0

            def fail_third_stage(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("injected staging failure")
                return original_write_temp(*args, **kwargs)

            with mock.patch.object(
                installer,
                "_write_temp",
                side_effect=fail_third_stage,
            ):
                with self.assertRaisesRegex(installer.InstallError, "rolled back"):
                    install_fixture(source, head, target, apply=True)

            temporary_names = [
                path.name
                for path in target.rglob("*")
                if path.name.startswith(".")
                and (".stage." in path.name or ".rollback." in path.name)
            ]
            self.assertEqual(temporary_names, [])
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())

    def test_staged_name_substitution_is_detected_and_rolled_back(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            outside = target / "outside-payload"
            outside.write_bytes(b"outside")
            substituted = False

            def substitute_one_future_stage(index: int, _relative: str) -> None:
                nonlocal substituted
                if index != 1:
                    return
                candidates = [
                    path
                    for path in target.rglob("*")
                    if path.name.startswith(".") and ".stage." in path.name
                ]
                self.assertTrue(candidates)
                victim = candidates[0]
                victim.unlink()
                victim.symlink_to(outside)
                substituted = True

            installer.TRANSACTION_FAULT_HOOK = substitute_one_future_stage
            with self.assertRaisesRegex(installer.InstallError, "rolled back"):
                install_fixture(source, head, target, apply=True)

            self.assertTrue(substituted)
            self.assertEqual(outside.read_bytes(), b"outside")
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse(
                (target / "usr/local/sbin/heim-pc-host-health").exists()
            )

    def test_backup_collision_fails_full_preflight(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            legacy_relative = (
                "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf"
            )
            legacy = target / legacy_relative
            legacy.parent.mkdir(parents=True)
            legacy_data = b"legacy\n"
            legacy.write_bytes(legacy_data)
            collision = target / installer._backup_relative(legacy_relative, legacy_data)
            collision.parent.mkdir(parents=True)
            collision.write_bytes(b"different\n")

            with self.assertRaisesRegex(installer.InstallError, "backup collision"):
                install_fixture(source, head, target, apply=True)

            self.assertEqual(legacy.read_bytes(), legacy_data)
            self.assertFalse(
                (target / "etc/systemd/system/cpu-governor.service").exists()
            )

    def test_symlink_parent_and_target_are_rejected(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            outside = target / "outside"
            outside.mkdir()
            (target / "etc").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(installer.InstallError, "unsafe|directory"):
                install_fixture(source, head, target, apply=False)
            self.assertEqual(list(outside.iterdir()), [])

        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            outside = target / "outside"
            outside.write_bytes(b"outside")
            unit = target / "etc/systemd/system/cpu-governor.service"
            unit.parent.mkdir(parents=True)
            unit.symlink_to(outside)
            with self.assertRaisesRegex(installer.InstallError, "safely open"):
                install_fixture(source, head, target, apply=False)
            self.assertEqual(outside.read_bytes(), b"outside")

    def test_symlink_installer_lock_is_rejected(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            outside = target / "outside-lock"
            outside.write_bytes(b"outside")
            lock = target / installer.LOCK_RELATIVE
            lock.parent.mkdir(parents=True)
            lock.symlink_to(outside)
            with self.assertRaisesRegex(installer.InstallError, "Too many levels|safely"):
                install_fixture(source, head, target, apply=True)
            self.assertEqual(outside.read_bytes(), b"outside")

    def test_journald_drop_in_sorts_after_pop_and_wins_merged_cat_config(self) -> None:
        journald_path = ROOT / "systemd/journald.conf.d/zz-heim-pc-retention.conf"
        self.assertEqual(
            sorted(["pop.conf", journald_path.name]),
            ["pop.conf", journald_path.name],
        )
        cat_config = "\n".join(
            [
                "# /usr/lib/systemd/journald.conf.d/pop.conf",
                "[Journal]",
                "SystemMaxUse=1000M",
                "",
                f"# /etc/systemd/journald.conf.d/{journald_path.name}",
                journald_path.read_text(encoding="utf-8"),
            ]
        )
        self.assertEqual(
            merged_journald_values(cat_config),
            {
                "Storage": "persistent",
                "SystemMaxUse": "2G",
                "SystemKeepFree": "20G",
                "MaxRetentionSec": "14day",
            },
        )


if __name__ == "__main__":
    unittest.main()
