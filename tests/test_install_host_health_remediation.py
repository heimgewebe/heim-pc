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
    seed_fluidsynth_main_unit: bool = True,
):
    if not seed_fluidsynth_main_unit:
        return installer.install(
            source_root=source,
            target_root=target,
            apply=apply,
            expected_head=head,
        )

    original_overlay_bytes = installer._overlay_bytes

    def overlay_with_fixture_main_unit(
        root_fd: int,
        relative: str,
        overlay: dict[str, bytes | None],
    ) -> bytes | None:
        data = original_overlay_bytes(root_fd, relative, overlay)
        if data is None and relative == "usr/lib/systemd/user/fluidsynth.service":
            return b"[Unit]\nDescription=Fixture FluidSynth service\n"
        return data

    with mock.patch.object(
        installer,
        "_overlay_bytes",
        side_effect=overlay_with_fixture_main_unit,
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
            self.assertTrue(receipt["valid"])
            self.assertTrue(receipt["repository_dirty"])
            self.assertFalse(receipt["transaction"]["commit_point_reached"])
            self.assertFalse(receipt["transaction"]["committed"])
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
            self.assertTrue(receipt["source_binding"]["blob_objects_reverified"])
            self.assertEqual(receipt["source_binding"]["object_format"], "sha1")
            self.assertEqual(
                receipt["source_binding"]["files"][
                    "scripts/ensure_performance_profile.py"
                ]["git_object_id"],
                run_git(
                    source,
                    "rev-parse",
                    f"{head}:scripts/ensure_performance_profile.py",
                ),
            )

    def test_root_git_trusts_only_the_exact_resolved_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            completed = subprocess.CompletedProcess(
                ["git"], 0, stdout="head\n", stderr=""
            )
            with mock.patch.object(
                installer.os, "geteuid", return_value=0
            ), mock.patch.object(
                installer.subprocess, "run", return_value=completed
            ) as run:
                result = installer._git(
                    root, ["rev-parse", "--verify", "HEAD^{commit}"], text=True
                )

        self.assertIs(result, completed)
        command = run.call_args.args[0]
        self.assertEqual(
            command[:3], ["git", "-c", f"safe.directory={root}"]
        )
        self.assertEqual(
            command[3:], ["rev-parse", "--verify", "HEAD^{commit}"]
        )
        self.assertNotIn("--global", command)
        self.assertNotIn("safe.directory=*", command)
        self.assertEqual(run.call_args.kwargs["cwd"], root)

    def test_non_root_git_does_not_add_safe_directory_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            completed = subprocess.CompletedProcess(
                ["git"], 0, stdout="head\n", stderr=""
            )
            with mock.patch.object(
                installer.os, "geteuid", return_value=installer.FLUIDSYNTH_USER_UID
            ), mock.patch.object(
                installer.subprocess, "run", return_value=completed
            ) as run:
                installer._git(root, ["rev-parse", "HEAD"], text=True)

        self.assertEqual(run.call_args.args[0], ["git", "rev-parse", "HEAD"])

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

    def test_concurrent_worktree_source_mutation_cannot_change_committed_bytes(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            source_path = source / "scripts/host_health_diagnostics.py"
            committed = source_path.read_bytes()
            started = threading.Event()
            stop = threading.Event()
            worker: threading.Thread | None = None

            def mutate_source() -> None:
                started.set()
                generation = 0
                while not stop.is_set():
                    source_path.write_bytes(
                        f"mutable generation {generation}\n".encode()
                    )
                    generation += 1

            def identity_then_race(_root: Path):
                nonlocal worker
                worker = threading.Thread(target=mutate_source)
                worker.start()
                self.assertTrue(started.wait(1))
                return head, False

            try:
                with mock.patch.object(
                    installer,
                    "repository_identity",
                    side_effect=identity_then_race,
                ):
                    receipt = install_fixture(source, head, target, apply=True)
            finally:
                stop.set()
                if worker is not None:
                    worker.join(timeout=5)

            self.assertEqual(
                (target / "usr/local/sbin/heim-pc-host-health").read_bytes(),
                committed,
            )
            self.assertEqual(receipt["source_binding"]["commit"], head)

    def test_checkout_race_cannot_redirect_exact_commit_source(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            source_path = source / "scripts/host_health_diagnostics.py"
            committed = source_path.read_bytes()
            source_path.write_bytes(b"new checkout bytes\n")
            run_git(source, "add", "scripts/host_health_diagnostics.py")
            run_git(source, "commit", "-q", "-m", "other tree")
            other_head = run_git(source, "rev-parse", "HEAD")
            run_git(source, "checkout", "-q", head)

            def identity_then_checkout(_root: Path):
                run_git(source, "checkout", "-q", other_head)
                return head, False

            with mock.patch.object(
                installer,
                "repository_identity",
                side_effect=identity_then_checkout,
            ):
                receipt = install_fixture(source, head, target, apply=True)

            self.assertEqual(run_git(source, "rev-parse", "HEAD"), other_head)
            self.assertEqual(
                (target / "usr/local/sbin/heim-pc-host-health").read_bytes(),
                committed,
            )
            self.assertEqual(receipt["repository_head"], head)

    def test_mixed_or_corrupt_blob_source_is_rejected_before_target_mutation(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            original_git = installer._git
            blob_reads = 0

            def corrupt_second_blob(root: Path, argv: list[str], *, text: bool):
                nonlocal blob_reads
                result = original_git(root, argv, text=text)
                if argv[:2] == ["cat-file", "blob"]:
                    blob_reads += 1
                    if blob_reads == 2:
                        return subprocess.CompletedProcess(
                            result.args,
                            0,
                            stdout=b"bytes from a different source\n",
                            stderr=b"",
                        )
                return result

            with mock.patch.object(
                installer,
                "_git",
                side_effect=corrupt_second_blob,
            ):
                with self.assertRaisesRegex(
                    installer.InstallError,
                    "blob identity mismatch",
                ):
                    install_fixture(source, head, target, apply=True)

            self.assertEqual(list(target.rglob("*.service")), [])
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())

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
            self.assertTrue(
                persisted["transaction"]["rollback_fail_closed_before_commit_point"]
            )
            self.assertTrue(persisted["transaction"]["committed"])
            self.assertTrue(persisted["receipt_publication"]["complete"])
            self.assertTrue(persisted["transaction"]["descriptor_relative_nofollow"])

    def test_migration_backs_up_and_removes_all_legacy_files(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            legacy: dict[str, bytes] = {
                "etc/systemd/journald.conf.d/50-heim-pc-retention.conf": (
                    installer.KNOWN_JOURNALD_512M
                ),
                "etc/systemd/journald.conf.d/99-heim-pc-retention.conf": (
                    installer.KNOWN_JOURNALD_2G
                ),
                "etc/systemd/journald.conf.d/heim-pc-storage-hygiene.conf": (
                    installer.KNOWN_OBSOLETE_ASSETS[
                        "etc/systemd/journald.conf.d/heim-pc-storage-hygiene.conf"
                    ]["contents"][0]
                ),
                "etc/systemd/system/logrotate.timer.d/heim-pc-storage-hygiene.conf": (
                    installer.KNOWN_OBSOLETE_ASSETS[
                        "etc/systemd/system/logrotate.timer.d/"
                        "heim-pc-storage-hygiene.conf"
                    ]["contents"][0]
                ),
                "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf": (
                    b"[Service]\nExecStart=\nExecStart=/usr/local/sbin/heim-pc-set-performance-profile\n"
                ),
                "usr/local/sbin/heim-pc-set-performance-profile": (
                    installer.KNOWN_LEGACY_PROFILE_SCRIPT
                ),
                "etc/systemd/user/fluidsynth.service.d/10-interactive-user.conf": (
                    b"[Unit]\nConditionUser=alex\n"
                ),
                "etc/systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf": (
                    installer.KNOWN_OBSOLETE_ASSETS[
                        "etc/systemd/user/fluidsynth.service.d/"
                        "50-heim-pc-gdm-guard.conf"
                    ]["contents"][0]
                ),
                "etc/systemd/user/fluidsynth.service.d/zz-heim-pc-gdm-guard.conf": (
                    installer.KNOWN_OBSOLETE_ASSETS[
                        "etc/systemd/user/fluidsynth.service.d/"
                        "zz-heim-pc-gdm-guard.conf"
                    ]["contents"][0]
                ),
            }
            for relative, data in legacy.items():
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(installer.KNOWN_OBSOLETE_ASSETS[relative]["mode"])

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
                self.assertTrue(item["managed_preimage"]["verified"])
                self.assertEqual(Path(item["backup"]).read_bytes(), legacy[relative])
                backup_stat = Path(item["backup"]).stat()
                self.assertEqual(stat.S_IMODE(backup_stat.st_mode), 0o600)
                self.assertEqual(backup_stat.st_uid, os.geteuid())
                self.assertEqual(backup_stat.st_gid, os.getegid())

    def test_unknown_legacy_script_preimage_blocks_without_removal(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            legacy = target / "usr/local/sbin/heim-pc-set-performance-profile"
            legacy.parent.mkdir(parents=True)
            foreign = b"#!/bin/sh\nprintf 'foreign managed command\\n'\n"
            legacy.write_bytes(foreign)
            legacy.chmod(0o755)

            with self.assertRaisesRegex(
                installer.InstallError,
                "not the exact known managed preimage",
            ):
                install_fixture(source, head, target, apply=True)

            self.assertEqual(legacy.read_bytes(), foreign)
            self.assertEqual(stat.S_IMODE(legacy.stat().st_mode), 0o755)
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse(
                (target / "usr/local/libexec/heim-pc/ensure-performance-profile").exists()
            )

    def test_live_shaped_root_legacy_script_identity_is_exact(self) -> None:
        root_uid = installer.pwd.getpwnam("root").pw_uid
        root_gid = installer.grp.getgrnam("root").gr_gid
        self.assertEqual(len(installer.KNOWN_LEGACY_PROFILE_SCRIPT), 958)
        self.assertEqual(
            installer._sha256(installer.KNOWN_LEGACY_PROFILE_SCRIPT),
            "d23c8794153b45e402b979727bf6d544dd2fbc889946062a35a69edbbb5ed6cd",
        )
        known = {
            "exists": True,
            "data": installer.KNOWN_LEGACY_PROFILE_SCRIPT,
            "sha256": installer._sha256(installer.KNOWN_LEGACY_PROFILE_SCRIPT),
            "mode": 0o755,
            "uid": root_uid,
            "gid": root_gid,
        }
        identity = installer._validate_obsolete_preimage(
            "usr/local/sbin/heim-pc-set-performance-profile",
            known,
            target_root=Path("/"),
        )
        self.assertTrue(identity["verified"])
        self.assertTrue(identity["live_owner_required"])

        wrong_owner = {
            **known,
            "uid": installer.pwd.getpwnam("nobody").pw_uid,
            "gid": installer.grp.getgrnam("nogroup").gr_gid,
        }
        with self.assertRaisesRegex(installer.InstallError, "owner mismatch"):
            installer._validate_obsolete_preimage(
                "usr/local/sbin/heim-pc-set-performance-profile",
                wrong_owner,
                target_root=Path("/"),
            )

    def test_missing_fluidsynth_main_unit_blocks_before_receipt(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)

            with self.assertRaisesRegex(
                installer.InstallError,
                "loadable fluidsynth.service main unit is missing",
            ):
                install_fixture(
                    source,
                    head,
                    target,
                    apply=True,
                    seed_fluidsynth_main_unit=False,
                )

            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse(
                (
                    target
                    / "etc/systemd/user/fluidsynth.service.d/"
                    "zz-heim-pc-interactive-user.conf"
                ).exists()
            )

    def test_effective_systemd_composition_resets_legacy_values(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            distro_cpu = target / "usr/lib/systemd/system/cpu-governor.service"
            distro_cpu.parent.mkdir(parents=True)
            distro_cpu.write_text(
                "[Service]\nExecStart=/usr/bin/distribution-default\n",
                encoding="utf-8",
            )
            distro_fluid = target / "usr/lib/systemd/user/fluidsynth.service"
            distro_fluid.parent.mkdir(parents=True)
            distro_fluid.write_text(
                "[Unit]\nConditionUser=!root\n",
                encoding="utf-8",
            )
            cpu_legacy = (
                target
                / "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf"
            )
            cpu_legacy.parent.mkdir(parents=True)
            cpu_legacy.write_text(
                "[Service]\nExecStart=\n"
                "ExecStart=/usr/local/sbin/heim-pc-set-performance-profile\n",
                encoding="utf-8",
            )
            cpu_legacy.chmod(0o644)
            fluid_legacy = (
                target
                / "etc/systemd/user/fluidsynth.service.d/10-interactive-user.conf"
            )
            fluid_legacy.parent.mkdir(parents=True)
            fluid_legacy.write_text("[Unit]\nConditionUser=alex\n", encoding="utf-8")
            fluid_legacy.chmod(0o644)

            receipt = install_fixture(source, head, target, apply=True)
            composition = installer.verify_effective_composition(target)
            self.assertEqual(
                composition["cpu_governor"]["exec_start"],
                [installer.STRICT_PROFILE],
            )
            self.assertEqual(
                composition["fluidsynth"]["condition_user"],
                ["alex"],
            )
            self.assertEqual(
                composition["fluidsynth"]["exec_start"],
                [installer.FLUIDSYNTH_EXEC_START],
            )
            self.assertEqual(
                composition["fluidsynth"]["type"],
                installer.FLUIDSYNTH_SERVICE_TYPE,
            )
            self.assertEqual(
                composition["fluidsynth"]["notify_access"],
                installer.FLUIDSYNTH_NOTIFY_ACCESS,
            )
            self.assertEqual(
                composition["fluidsynth"]["user_unit_path_evidence"]["paths"],
                list(installer.FLUIDSYNTH_USER_UNIT_DIRS),
            )
            self.assertFalse(
                composition["fluidsynth"]["user_unit_path_evidence"][
                    "live_verified"
                ]
            )
            self.assertEqual(
                composition["fluidsynth"]["user_unit_path_evidence"][
                    "composition_paths"
                ],
                list(installer.FLUIDSYNTH_USER_UNIT_DIRS),
            )
            self.assertEqual(
                composition["fluidsynth"]["user_unit_path_evidence"][
                    "verified_symlink_aliases"
                ],
                [],
            )
            self.assertEqual(
                composition["fluidsynth"]["sdl_no_signal_handlers"],
                installer.FLUIDSYNTH_SDL_NO_SIGNAL_HANDLERS,
            )
            self.assertEqual(
                composition["fluidsynth"]["exec_stop"],
                installer.FLUIDSYNTH_EXEC_STOP,
            )
            self.assertEqual(
                composition["fluidsynth"]["kill_mode"],
                installer.FLUIDSYNTH_KILL_MODE,
            )
            self.assertEqual(
                composition["fluidsynth"]["kill_signal"],
                installer.FLUIDSYNTH_KILL_SIGNAL,
            )
            self.assertEqual(
                composition["fluidsynth"]["restart_kill_signal"],
                installer.FLUIDSYNTH_RESTART_KILL_SIGNAL,
            )
            self.assertEqual(
                composition["fluidsynth"]["timeout_stop_sec"],
                installer.FLUIDSYNTH_TIMEOUT_STOP_SEC,
            )
            self.assertEqual(
                composition["fluidsynth"]["send_sigkill"],
                installer.FLUIDSYNTH_SEND_SIGKILL,
            )
            self.assertEqual(
                composition["fluidsynth"]["final_kill_signal"],
                installer.FLUIDSYNTH_FINAL_KILL_SIGNAL,
            )
            self.assertEqual(
                composition["fluidsynth"]["shutdown_failure"],
                installer.FLUIDSYNTH_SHUTDOWN_FAILURE,
            )
            self.assertEqual(
                composition["fluidsynth"]["log_rate_limit_interval"],
                installer.FLUIDSYNTH_LOG_RATE_LIMIT_INTERVAL,
            )
            self.assertEqual(
                composition["fluidsynth"]["log_rate_limit_burst"],
                installer.FLUIDSYNTH_LOG_RATE_LIMIT_BURST,
            )
            self.assertIn(
                "usr/lib/systemd/user/fluidsynth.service",
                composition["fluidsynth"]["directive_sources"],
            )
            self.assertEqual(
                composition["fluidsynth"]["main_unit_sources"],
                ["usr/lib/systemd/user/fluidsynth.service"],
            )
            self.assertEqual(receipt["effective_systemd_composition"], composition)
            cpu_reset = (
                target
                / "etc/systemd/system/cpu-governor.service.d/zz-heim-pc-strict-profile.conf"
            ).read_text(encoding="utf-8")
            fluid_reset = (
                target
                / "etc/systemd/user/fluidsynth.service.d/"
                "zz-heim-pc-interactive-user.conf"
            ).read_text(encoding="utf-8")
            self.assertIn("ExecStart=\n", cpu_reset)
            self.assertIn("ConditionUser=\n", fluid_reset)
            self.assertIn("ConditionUser=alex", fluid_reset)
            self.assertIn("Type=notify", fluid_reset)
            self.assertIn("NotifyAccess=main", fluid_reset)
            self.assertIn("ExecStart=\n", fluid_reset)
            self.assertIn(installer.FLUIDSYNTH_EXEC_START, fluid_reset)
            self.assertIn(
                "/usr/bin/env SDL_NO_SIGNAL_HANDLERS=1 /usr/bin/fluidsynth",
                fluid_reset,
            )
            self.assertIn("ExecStop=\n", fluid_reset)
            self.assertIn("KillMode=control-group", fluid_reset)
            self.assertIn("KillSignal=SIGTERM", fluid_reset)
            self.assertIn("RestartKillSignal=SIGTERM", fluid_reset)
            self.assertIn("TimeoutStopSec=15s", fluid_reset)
            self.assertIn("SendSIGKILL=yes", fluid_reset)
            self.assertIn("FinalKillSignal=SIGKILL", fluid_reset)
            self.assertIn("LogRateLimitIntervalSec=30s", fluid_reset)
            self.assertIn("LogRateLimitBurst=200", fluid_reset)
            self.assertNotIn("!gdm", fluid_reset)

    def test_managed_fluidsynth_contract_overrides_earlier_shell_pipeline(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            distro = target / "usr/lib/systemd/user/fluidsynth.service"
            distro.parent.mkdir(parents=True)
            distro.write_text(
                "[Service]\n"
                "Type=notify\n"
                "NotifyAccess=main\n"
                f"ExecStart={installer.FLUIDSYNTH_EXEC_START}\n",
                encoding="utf-8",
            )
            observed_pipeline = (
                target
                / "etc/systemd/user/fluidsynth.service.d/no-tcp-shell.conf"
            )
            observed_pipeline.parent.mkdir(parents=True)
            observed_pipeline.write_text(
                "[Service]\n"
                "Type=simple\n"
                "NotifyAccess=none\n"
                "ExecStart=\n"
                "ExecStart=/bin/bash -c 'tail -f /dev/null | "
                "/usr/bin/fluidsynth $OTHER_OPTS $SOUND_FONT'\n",
                encoding="utf-8",
            )
            observed_preimage = observed_pipeline.read_bytes()

            receipt = install_fixture(source, head, target, apply=True)
            composition = receipt["effective_systemd_composition"]["fluidsynth"]

            self.assertEqual(composition["exec_start"], [installer.FLUIDSYNTH_EXEC_START])
            self.assertEqual(composition["type"], installer.FLUIDSYNTH_SERVICE_TYPE)
            self.assertEqual(
                composition["notify_access"],
                installer.FLUIDSYNTH_NOTIFY_ACCESS,
            )
            self.assertEqual(
                composition["sdl_no_signal_handlers"],
                installer.FLUIDSYNTH_SDL_NO_SIGNAL_HANDLERS,
            )
            self.assertEqual(
                composition["timeout_stop_sec"],
                installer.FLUIDSYNTH_TIMEOUT_STOP_SEC,
            )
            self.assertEqual(
                composition["log_rate_limit_interval"],
                installer.FLUIDSYNTH_LOG_RATE_LIMIT_INTERVAL,
            )
            self.assertEqual(
                composition["log_rate_limit_burst"],
                installer.FLUIDSYNTH_LOG_RATE_LIMIT_BURST,
            )
            self.assertIn(
                "etc/systemd/user/fluidsynth.service.d/"
                "zz-heim-pc-interactive-user.conf",
                composition["exec_start_directive_sources"],
            )
            self.assertEqual(observed_pipeline.read_bytes(), observed_preimage)

    def test_fluidsynth_contract_drift_between_json_and_enforced_constants_blocks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as directory:
            source = Path(source_directory)
            for source_relative, _target_relative, _mode in installer.FILES:
                destination = source / source_relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / source_relative, destination)
            config_path = source / "config/host-health-remediation.v1.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["deployment"]["fluidsynth_timeout_stop_sec"] = "90s"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            run_git(source, "init", "-q")
            run_git(source, "config", "user.name", "Test")
            run_git(source, "config", "user.email", "test@example.invalid")
            run_git(source, "add", ".")
            run_git(source, "commit", "-q", "-m", "drifted fixture")
            head = run_git(source, "rev-parse", "HEAD")
            target = Path(directory)

            with self.assertRaisesRegex(
                installer.InstallError,
                "committed deployment contract differs from installer constants",
            ):
                install_fixture(source, head, target, apply=True)

            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())

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
            legacy.chmod(0o644)
            conflict.write_text(
                "[Unit]\nConditionUser=\nConditionUser=alex\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                installer.InstallError,
                "unmanaged fluidsynth.service ConditionUser",
            ):
                install_fixture(source, head, target, apply=True)

            self.assertTrue(legacy.exists())
            self.assertEqual(
                conflict.read_text(encoding="utf-8"),
                "[Unit]\nConditionUser=\nConditionUser=alex\n",
            )
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse(
                (target / "usr/local/sbin/heim-pc-host-health").exists()
            )

    def test_later_shutdown_drop_in_fails_closed_without_target_mutation(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            conflict = target / "etc/systemd/user/service.d/zzz-foreign.conf"
            conflict.parent.mkdir(parents=True)
            conflict.write_text(
                "[Service]\nTimeoutStopSec=15s\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                installer.InstallError,
                "unmanaged fluidsynth.service shutdown directive",
            ):
                install_fixture(source, head, target, apply=True)

            self.assertEqual(
                conflict.read_text(encoding="utf-8"),
                "[Service]\nTimeoutStopSec=15s\n",
            )
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse(
                (target / "usr/local/sbin/heim-pc-host-health").exists()
            )

    def test_per_user_shutdown_drop_ins_fail_closed_without_target_mutation(
        self,
    ) -> None:
        conflict_dirs = (
            "home/alex/.config/systemd/user",
            "home/alex/.config/systemd/user.control",
            "run/user/1000/systemd/user.control",
        )
        for conflict_dir in conflict_dirs:
            with self.subTest(conflict_dir=conflict_dir), committed_source() as (
                source,
                head,
            ), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)
                conflict = (
                    target
                    / conflict_dir
                    / "fluidsynth.service.d/zzz-foreign.conf"
                )
                conflict.parent.mkdir(parents=True)
                conflict.write_text(
                    "[Service]\nTimeoutStopSec=90s\n",
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(
                    installer.InstallError,
                    "unmanaged fluidsynth.service shutdown directive",
                ):
                    install_fixture(source, head, target, apply=True)

                self.assertEqual(
                    conflict.read_text(encoding="utf-8"),
                    "[Service]\nTimeoutStopSec=90s\n",
                )
                self.assertFalse(
                    (target / installer.RECEIPT_RELATIVE).exists()
                )
                self.assertFalse(
                    (target / "usr/local/sbin/heim-pc-host-health").exists()
                )

    def test_per_user_drop_in_cannot_shadow_the_managed_drop_in(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            shadow = (
                target
                / "home/alex/.config/systemd/user/fluidsynth.service.d/"
                "zz-heim-pc-interactive-user.conf"
            )
            shadow.parent.mkdir(parents=True)
            shadow.write_text(
                "[Unit]\nConditionUser=\nConditionUser=alex\n"
                "[Service]\n"
                "Type=notify\n"
                "NotifyAccess=main\n"
                "ExecStart=\n"
                "ExecStart=/usr/bin/fluidsynth -is $OTHER_OPTS $SOUND_FONT\n"
                "ExecStop=\n"
                "KillMode=control-group\n"
                "KillSignal=SIGTERM\n"
                "RestartKillSignal=SIGTERM\n"
                "TimeoutStopSec=15s\n"
                "SendSIGKILL=yes\n"
                "FinalKillSignal=SIGKILL\n"
                "LogRateLimitIntervalSec=30s\n"
                "LogRateLimitBurst=200\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                installer.InstallError,
                "effective fluidsynth.service ExecStart",
            ):
                install_fixture(source, head, target, apply=True)

            self.assertIn(
                "ExecStart=/usr/bin/fluidsynth",
                shadow.read_text(encoding="utf-8"),
            )
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse(
                (target / "usr/local/sbin/heim-pc-host-health").exists()
            )

    def test_live_user_unit_path_probe_is_exact_and_drops_privileges(self) -> None:
        account = mock.Mock(
            pw_uid=installer.FLUIDSYNTH_USER_UID,
            pw_gid=installer.FLUIDSYNTH_USER_UID,
            pw_dir=installer.FLUIDSYNTH_USER_HOME,
        )
        output = "".join(
            f"/{relative}\n" for relative in installer.FLUIDSYNTH_USER_UNIT_DIRS
        )
        completed = subprocess.CompletedProcess(
            list(installer.FLUIDSYNTH_USER_UNIT_PATH_PROBE),
            0,
            stdout=output,
            stderr="",
        )
        with mock.patch.object(
            installer.pwd,
            "getpwnam",
            return_value=account,
        ), mock.patch.object(
            installer.os,
            "geteuid",
            return_value=0,
        ), mock.patch.object(
            installer.subprocess,
            "run",
            return_value=completed,
        ) as run:
            observed = installer._live_user_unit_dirs()

        self.assertEqual(observed, installer.FLUIDSYNTH_USER_UNIT_DIRS)
        self.assertEqual(run.call_args.kwargs["user"], 1000)
        self.assertEqual(run.call_args.kwargs["group"], 1000)
        self.assertEqual(run.call_args.kwargs["extra_groups"], [])
        self.assertEqual(
            run.call_args.kwargs["env"]["XDG_RUNTIME_DIR"],
            "/run/user/1000",
        )
        self.assertEqual(
            run.call_args.kwargs["env"]["XDG_CONFIG_DIRS"],
            installer.FLUIDSYNTH_XDG_CONFIG_DIRS,
        )
        self.assertEqual(
            run.call_args.kwargs["env"]["XDG_DATA_DIRS"],
            installer.FLUIDSYNTH_XDG_DATA_DIRS,
        )
        self.assertNotIn("SYSTEMD_UNIT_PATH", run.call_args.kwargs["env"])


    def test_live_user_unit_path_probe_ignores_caller_xdg_overrides(self) -> None:
        account = mock.Mock(
            pw_uid=installer.FLUIDSYNTH_USER_UID,
            pw_gid=installer.FLUIDSYNTH_USER_GID,
            pw_dir=installer.FLUIDSYNTH_USER_HOME,
        )
        output = "".join(
            f"/{relative}\n" for relative in installer.FLUIDSYNTH_USER_UNIT_DIRS
        )
        completed = subprocess.CompletedProcess(
            list(installer.FLUIDSYNTH_USER_UNIT_PATH_PROBE),
            0,
            stdout=output,
            stderr="",
        )
        with mock.patch.object(
            installer.pwd, "getpwnam", return_value=account
        ), mock.patch.object(
            installer.os, "geteuid", return_value=0
        ), mock.patch.dict(
            installer.os.environ,
            {
                "SYSTEMD_UNIT_PATH": "/tmp/hostile",
                "XDG_CONFIG_DIRS": "/tmp/config",
                "XDG_DATA_DIRS": "/tmp/data",
            },
            clear=False,
        ), mock.patch.object(
            installer.subprocess, "run", return_value=completed
        ) as run:
            observed = installer._live_user_unit_dirs()

        self.assertEqual(observed, installer.FLUIDSYNTH_USER_UNIT_DIRS)
        environment = run.call_args.kwargs["env"]
        self.assertNotIn("SYSTEMD_UNIT_PATH", environment)
        self.assertEqual(
            environment["XDG_CONFIG_DIRS"], installer.FLUIDSYNTH_XDG_CONFIG_DIRS
        )
        self.assertEqual(
            environment["XDG_DATA_DIRS"], installer.FLUIDSYNTH_XDG_DATA_DIRS
        )

    def test_composition_unit_dirs_skip_attested_symlink_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/xdg/systemd").mkdir(parents=True)
            (root / "etc/systemd/user").mkdir(parents=True)
            (root / "etc/xdg/systemd/user").symlink_to(
                "../../systemd/user", target_is_directory=True
            )
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                normalized, aliases = installer._composition_unit_dirs(
                    root_fd,
                    ("etc/xdg/systemd/user", "etc/systemd/user"),
                )
            finally:
                os.close(root_fd)

        self.assertEqual(normalized, ("etc/systemd/user",))
        self.assertEqual(
            aliases,
            [{"path": "etc/xdg/systemd/user", "target": "etc/systemd/user"}],
        )

    def test_composition_unit_dirs_reject_unattested_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc/xdg/systemd").mkdir(parents=True)
            (root / "tmp/outside").mkdir(parents=True)
            (root / "etc/xdg/systemd/user").symlink_to(
                "/tmp/outside", target_is_directory=True
            )
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    installer.InstallError, "outside the committed contract"
                ):
                    installer._composition_unit_dirs(
                        root_fd, ("etc/xdg/systemd/user", "etc/systemd/user")
                    )
            finally:
                os.close(root_fd)

    def test_live_user_unit_path_probe_rejects_path_drift(self) -> None:
        account = mock.Mock(
            pw_uid=installer.FLUIDSYNTH_USER_UID,
            pw_gid=installer.FLUIDSYNTH_USER_GID,
            pw_dir=installer.FLUIDSYNTH_USER_HOME,
        )
        completed = subprocess.CompletedProcess(
            list(installer.FLUIDSYNTH_USER_UNIT_PATH_PROBE),
            0,
            stdout="/home/alex/.config/systemd/user\n/etc/systemd/user\n",
            stderr="",
        )
        with mock.patch.object(
            installer.pwd,
            "getpwnam",
            return_value=account,
        ), mock.patch.object(
            installer.os,
            "geteuid",
            return_value=installer.FLUIDSYNTH_USER_UID,
        ), mock.patch.object(
            installer.subprocess,
            "run",
            return_value=completed,
        ):
            with self.assertRaisesRegex(
                installer.InstallError,
                "unit paths differ from the committed contract",
            ):
                installer._live_user_unit_dirs()

    def test_live_user_unit_path_drift_blocks_before_the_apply_lock(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            root_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(
                installer,
                "_open_root",
                return_value=root_fd,
            ), mock.patch.object(
                installer.os,
                "geteuid",
                return_value=0,
            ), mock.patch.object(
                installer,
                "_resolve_user_unit_dirs",
                side_effect=installer.InstallError(
                    "effective FluidSynth user unit paths differ"
                ),
            ), mock.patch.object(installer, "_open_lock") as open_lock:
                with self.assertRaisesRegex(
                    installer.InstallError,
                    "effective FluidSynth user unit paths differ",
                ):
                    installer.install(
                        source_root=source,
                        target_root=installer.DEFAULT_TARGET_ROOT,
                        apply=True,
                        expected_head=head,
                    )

            open_lock.assert_not_called()
            self.assertEqual(list(target.iterdir()), [])

    def test_user_unit_path_drift_after_writes_rolls_back_transaction(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            expected = installer.FLUIDSYNTH_USER_UNIT_DIRS
            initial_evidence = {
                "source": "test-preflight",
                "live_verified": True,
                "paths": list(expected),
            }
            changed = ("unexpected/systemd/user", *expected)
            changed_evidence = {
                "source": "test-post-write",
                "live_verified": True,
                "paths": list(changed),
            }

            with mock.patch.object(
                installer,
                "_resolve_user_unit_dirs",
                side_effect=(
                    (expected, initial_evidence),
                    (changed, changed_evidence),
                ),
            ):
                with self.assertRaisesRegex(
                    installer.InstallError,
                    "user unit paths changed during the target transaction",
                ):
                    install_fixture(source, head, target, apply=True)

            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            for _source_relative, target_relative, _mode in installer.FILES:
                self.assertFalse(target.joinpath(target_relative).exists())

    def test_unmanaged_cpu_drop_in_blocks_even_if_final_command_matches(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            conflict = (
                target
                / "run/systemd/system/cpu-governor.service.d/zzz-foreign.conf"
            )
            conflict.parent.mkdir(parents=True)
            conflict.write_text(
                "[Service]\nExecStart=\n"
                f"ExecStart={installer.STRICT_PROFILE}\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                installer.InstallError,
                "unmanaged cpu-governor.service ExecStart",
            ):
                install_fixture(source, head, target, apply=True)

            self.assertTrue(conflict.exists())
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
            original_legacy = (
                b"[Service]\nExecStart=\n"
                b"ExecStart=/usr/local/sbin/heim-pc-set-performance-profile\n"
            )
            legacy.write_bytes(original_legacy)
            legacy.chmod(0o644)

            def fail_after_third(index: int, _relative: str) -> None:
                if index == 3:
                    raise RuntimeError("injected commit failure")

            installer.TRANSACTION_FAULT_HOOK = fail_after_third
            with self.assertRaisesRegex(installer.InstallError, "before commit point"):
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
                with self.assertRaisesRegex(installer.InstallError, "before commit point"):
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
            with self.assertRaisesRegex(installer.InstallError, "before commit point"):
                install_fixture(source, head, target, apply=True)

            self.assertTrue(substituted)
            self.assertEqual(outside.read_bytes(), b"outside")
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse(
                (target / "usr/local/sbin/heim-pc-host-health").exists()
            )

    def test_target_parent_substitution_fails_closed_without_following_replacement(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            relative = "etc/heim-pc/host-health-remediation.v1.json"
            configured = target / relative
            configured.parent.mkdir(parents=True)
            original = b'{"preimage": true}\n'
            configured.write_bytes(original)
            detached_parent = target / "etc/heim-pc-detached"
            substitute = b'{"foreign": true}\n'
            substituted = False

            def substitute_parent(_index: int, committed_relative: str) -> None:
                nonlocal substituted
                if committed_relative != relative or substituted:
                    return
                configured.parent.rename(detached_parent)
                configured.parent.mkdir()
                configured.write_bytes(substitute)
                substituted = True

            installer.TRANSACTION_FAULT_HOOK = substitute_parent
            with self.assertRaisesRegex(
                installer.InstallError,
                "before commit point",
            ):
                install_fixture(source, head, target, apply=True)

            self.assertTrue(substituted)
            self.assertEqual(configured.read_bytes(), substitute)
            self.assertEqual(
                (detached_parent / configured.name).read_bytes(),
                original,
            )
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())

    def test_ownership_mismatch_readback_rolls_back_before_commit(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            relative = "usr/local/sbin/heim-pc-host-health"
            original_snapshot = installer._snapshot
            inject_mismatch = False

            def enable_mismatch(_index: int, committed_relative: str) -> None:
                nonlocal inject_mismatch
                if committed_relative == relative:
                    inject_mismatch = True

            def mismatched_snapshot(root_fd: int, observed_relative: str):
                snapshot = original_snapshot(root_fd, observed_relative)
                if (
                    inject_mismatch
                    and observed_relative == relative
                    and snapshot["exists"]
                ):
                    return {**snapshot, "uid": snapshot["uid"] + 1}
                return snapshot

            installer.TRANSACTION_FAULT_HOOK = enable_mismatch
            with mock.patch.object(
                installer,
                "_snapshot",
                side_effect=mismatched_snapshot,
            ):
                with self.assertRaisesRegex(
                    installer.InstallError,
                    "readback failed",
                ):
                    install_fixture(source, head, target, apply=True)

            self.assertFalse((target / relative).exists())
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())

    def test_cleanup_failure_before_commit_is_reported_after_fail_closed_rollback(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            cpu = target / "etc/systemd/system/cpu-governor.service"
            cpu.parent.mkdir(parents=True)
            original = b"[Service]\nExecStart=/original\n"
            cpu.write_bytes(original)

            def fail_after_first(index: int, _relative: str) -> None:
                if index == 1:
                    raise RuntimeError("injected pre-commit failure")

            original_unlink = installer.os.unlink
            cleanup_failed = False

            def fail_one_rollback_cleanup(path, *args, **kwargs):
                nonlocal cleanup_failed
                if ".rollback." in os.fspath(path) and not cleanup_failed:
                    cleanup_failed = True
                    raise PermissionError("injected pre-commit cleanup failure")
                return original_unlink(path, *args, **kwargs)

            installer.TRANSACTION_FAULT_HOOK = fail_after_first
            with mock.patch.object(
                installer.os,
                "unlink",
                side_effect=fail_one_rollback_cleanup,
            ):
                with self.assertRaisesRegex(
                    installer.InstallError,
                    "pre-commit cleanup failures",
                ):
                    install_fixture(source, head, target, apply=True)

            self.assertTrue(cleanup_failed)
            self.assertEqual(cpu.read_bytes(), original)
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertTrue(
                any(".rollback." in path.name for path in target.rglob("*"))
            )

    def test_cleanup_failure_after_commit_is_receipted_without_transaction_failure(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            cpu = target / "etc/systemd/system/cpu-governor.service"
            cpu.parent.mkdir(parents=True)
            cpu.write_bytes(b"[Service]\nExecStart=/original\n")
            original_unlink = installer.os.unlink
            cleanup_failed = False

            def fail_one_rollback_cleanup(path, *args, **kwargs):
                nonlocal cleanup_failed
                if ".rollback." in os.fspath(path) and not cleanup_failed:
                    cleanup_failed = True
                    raise PermissionError("injected post-commit cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with mock.patch.object(
                installer.os,
                "unlink",
                side_effect=fail_one_rollback_cleanup,
            ):
                receipt = install_fixture(source, head, target, apply=True)

            self.assertTrue(receipt["apply"])
            self.assertTrue(receipt["valid"])
            self.assertTrue(receipt["transaction"]["committed"])
            self.assertTrue(receipt["transaction"]["target_state_verified"])
            self.assertFalse(receipt["transaction"]["cleanup_complete"])
            self.assertEqual(len(receipt["transaction"]["residue"]), 1)
            self.assertIn(
                "injected post-commit cleanup failure",
                receipt["transaction"]["warnings"][0],
            )
            persisted = json.loads(
                (target / installer.RECEIPT_RELATIVE).read_text(encoding="utf-8")
            )
            self.assertEqual(persisted, receipt)

    def test_partial_post_commit_cleanup_records_only_exact_remaining_residue(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            seeded = [
                "etc/heim-pc/host-health-remediation.v1.json",
                "usr/local/libexec/heim-pc/ensure-performance-profile",
            ]
            for relative in seeded:
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"old:{relative}\n".encode())

            original_unlink = installer.os.unlink
            rollback_cleanup_calls = 0

            def fail_second_rollback_cleanup(path, *args, **kwargs):
                nonlocal rollback_cleanup_calls
                if ".rollback." in os.fspath(path):
                    rollback_cleanup_calls += 1
                    if rollback_cleanup_calls == 2:
                        raise PermissionError("injected partial cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with mock.patch.object(
                installer.os,
                "unlink",
                side_effect=fail_second_rollback_cleanup,
            ):
                receipt = install_fixture(source, head, target, apply=True)

            residue = receipt["transaction"]["residue"]
            self.assertGreaterEqual(rollback_cleanup_calls, 2)
            self.assertFalse(receipt["transaction"]["cleanup_complete"])
            self.assertEqual(len(residue), 1)
            remaining = [
                str(path)
                for path in target.rglob("*")
                if ".rollback." in path.name
            ]
            self.assertEqual(remaining, [residue[0]["path"]])

    def test_receipt_write_failure_reports_committed_verified_target_truth(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            original_write_temp = installer._write_temp

            def fail_receipt_stage(parent_fd, target_name, data, **kwargs):
                if target_name == Path(installer.RECEIPT_RELATIVE).name:
                    raise OSError("injected receipt write failure")
                return original_write_temp(parent_fd, target_name, data, **kwargs)

            with mock.patch.object(
                installer,
                "_write_temp",
                side_effect=fail_receipt_stage,
            ):
                outcome = install_fixture(source, head, target, apply=True)

            self.assertTrue(outcome["apply"])
            self.assertTrue(outcome["valid"])
            self.assertEqual(
                outcome["kind"],
                "heim_pc_host_health_remediation_committed_outcome",
            )
            self.assertTrue(outcome["transaction"]["committed"])
            self.assertTrue(outcome["transaction"]["target_state_verified"])
            self.assertFalse(outcome["receipt_publication"]["complete"])
            self.assertFalse(outcome["receipt_publication"]["fsynced"])
            self.assertIn(
                "receipt publication failed",
                "\n".join(outcome["warnings"]),
            )
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertEqual(
                (target / "usr/local/sbin/heim-pc-host-health").read_bytes(),
                (source / "scripts/host_health_diagnostics.py").read_bytes(),
            )
            with mock.patch.object(
                installer,
                "install",
                return_value=outcome,
            ), mock.patch.object(
                installer.sys,
                "argv",
                ["install_host_health_remediation.py", "--apply"],
            ), mock.patch("builtins.print"):
                self.assertEqual(installer.main(), 2)

    def test_receipt_parent_failure_cannot_escape_as_transaction_failure(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            original_open_parent = installer._open_parent

            def fail_receipt_parent(root_fd, relative, **kwargs):
                if (
                    relative == installer.RECEIPT_RELATIVE
                    and kwargs.get("create")
                ):
                    raise installer.InstallError("injected receipt parent failure")
                return original_open_parent(root_fd, relative, **kwargs)

            with mock.patch.object(
                installer,
                "_open_parent",
                side_effect=fail_receipt_parent,
            ):
                outcome = install_fixture(source, head, target, apply=True)

            self.assertTrue(outcome["apply"])
            self.assertEqual(
                outcome["kind"],
                "heim_pc_host_health_remediation_committed_outcome",
            )
            self.assertTrue(outcome["transaction"]["committed"])
            self.assertTrue(outcome["transaction"]["target_state_verified"])
            self.assertFalse(outcome["receipt_publication"]["complete"])
            self.assertIn(
                "injected receipt parent failure",
                outcome["receipt_publication"]["error"],
            )

    def test_receipt_parent_substitution_reports_incomplete_committed_outcome(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            original_replace = installer.os.replace
            receipt_parent = (target / installer.RECEIPT_RELATIVE).parent
            detached_parent = receipt_parent.with_name("host-health-detached")
            foreign_receipt = b'{"foreign": true}\n'
            substituted = False

            def substitute_after_receipt_replace(
                source_name,
                destination_name,
                *args,
                **kwargs,
            ):
                nonlocal substituted
                result = original_replace(
                    source_name,
                    destination_name,
                    *args,
                    **kwargs,
                )
                if (
                    os.fspath(destination_name)
                    == Path(installer.RECEIPT_RELATIVE).name
                    and ".stage." in os.fspath(source_name)
                    and not substituted
                ):
                    receipt_parent.rename(detached_parent)
                    receipt_parent.mkdir()
                    (receipt_parent / Path(installer.RECEIPT_RELATIVE).name).write_bytes(
                        foreign_receipt
                    )
                    substituted = True
                return result

            with mock.patch.object(
                installer.os,
                "replace",
                side_effect=substitute_after_receipt_replace,
            ):
                outcome = install_fixture(source, head, target, apply=True)

            self.assertTrue(substituted)
            self.assertTrue(outcome["transaction"]["committed"])
            self.assertTrue(outcome["transaction"]["target_state_verified"])
            self.assertEqual(
                outcome["kind"],
                "heim_pc_host_health_remediation_committed_outcome",
            )
            self.assertFalse(outcome["receipt_publication"]["complete"])
            self.assertIn(
                "exact readback failed",
                outcome["receipt_publication"]["error"],
            )
            self.assertEqual(
                (target / installer.RECEIPT_RELATIVE).read_bytes(),
                foreign_receipt,
            )
            self.assertTrue(
                (detached_parent / Path(installer.RECEIPT_RELATIVE).name).exists()
            )
            self.assertTrue(
                (target / "usr/local/sbin/heim-pc-host-health").exists()
            )

    def test_next_run_idempotently_recovers_exact_receipted_residue(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            cpu = target / "etc/systemd/system/cpu-governor.service"
            cpu.parent.mkdir(parents=True)
            cpu.write_bytes(b"[Service]\nExecStart=/original\n")
            original_unlink = installer.os.unlink
            cleanup_failed = False

            def fail_one_rollback_cleanup(path, *args, **kwargs):
                nonlocal cleanup_failed
                if ".rollback." in os.fspath(path) and not cleanup_failed:
                    cleanup_failed = True
                    raise PermissionError("injected recoverable cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with mock.patch.object(
                installer.os,
                "unlink",
                side_effect=fail_one_rollback_cleanup,
            ):
                first = install_fixture(source, head, target, apply=True)

            residue_path = Path(first["transaction"]["residue"][0]["path"])
            self.assertTrue(residue_path.exists())
            second = install_fixture(source, head, target, apply=True)
            recovery = second["transaction"]["previous_residue_recovery"]
            self.assertEqual(recovery["attempted"], 1)
            self.assertEqual(recovery["recovered"], [str(residue_path)])
            self.assertFalse(residue_path.exists())
            self.assertTrue(second["transaction"]["cleanup_complete"])

    def test_rollback_failure_is_exact_and_never_publishes_committed_receipt(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            relative = "etc/heim-pc/host-health-remediation.v1.json"
            configured = target / relative
            configured.parent.mkdir(parents=True)
            original = b'{"old": true}\n'
            configured.write_bytes(original)
            original_replace = installer.os.replace

            def fail_after_target(_index: int, committed_relative: str) -> None:
                if committed_relative == relative:
                    raise RuntimeError("injected verification-path failure")

            def fail_rollback_replace(source_name, destination_name, *args, **kwargs):
                if ".rollback." in os.fspath(source_name):
                    raise OSError("injected rollback failure")
                return original_replace(
                    source_name,
                    destination_name,
                    *args,
                    **kwargs,
                )

            installer.TRANSACTION_FAULT_HOOK = fail_after_target
            with mock.patch.object(
                installer.os,
                "replace",
                side_effect=fail_rollback_replace,
            ):
                with self.assertRaisesRegex(
                    installer.InstallError,
                    "rollback failures:.*injected rollback failure",
                ):
                    install_fixture(source, head, target, apply=True)

            self.assertNotEqual(configured.read_bytes(), original)
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertTrue(
                any(".rollback." in path.name for path in target.rglob("*"))
            )

    def test_receipt_contains_exact_committed_target_readback(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            receipt = install_fixture(source, head, target, apply=True)
            transaction = receipt["transaction"]

            self.assertEqual(transaction["commit_point"], installer.COMMIT_POINT)
            self.assertTrue(transaction["commit_point_reached"])
            self.assertTrue(transaction["committed"])
            self.assertTrue(transaction["target_state_verified"])
            self.assertTrue(transaction["cleanup_complete"])
            self.assertEqual(len(transaction["target_readback"]), len(installer.FILES) + len(installer.REMOVALS))
            for readback in transaction["target_readback"]:
                path = target / readback["target_relative"]
                if readback["exists"]:
                    metadata = path.stat()
                    self.assertEqual(
                        readback["sha256"],
                        installer._sha256(path.read_bytes()),
                    )
                    self.assertEqual(readback["mode"], oct(stat.S_IMODE(metadata.st_mode)))
                    self.assertEqual(readback["uid"], metadata.st_uid)
                    self.assertEqual(readback["gid"], metadata.st_gid)
                else:
                    self.assertFalse(path.exists())

    def test_unprivileged_root_plan_never_opens_apply_state_or_mutates_targets(
        self,
    ) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            legacy_relative = installer.REMOVALS[0]
            legacy = target / legacy_relative
            legacy.parent.mkdir(parents=True)
            legacy_data = installer.KNOWN_JOURNALD_512M
            legacy.write_bytes(legacy_data)
            legacy.chmod(0o644)
            (target / "usr/lib/systemd/system").mkdir(parents=True)
            (target / "usr/lib/systemd/user").mkdir(parents=True)
            (target / "usr/lib/systemd/user/fluidsynth.service").write_text(
                "[Unit]\nDescription=Fixture FluidSynth service\n",
                encoding="utf-8",
            )
            (target / "lib").symlink_to("usr/lib", target_is_directory=True)
            privileged = target / "var/lib/heim-pc"
            privileged.mkdir(parents=True)
            privileged.chmod(0)
            root_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)

            try:
                with mock.patch.object(
                    installer,
                    "_open_root",
                    return_value=root_fd,
                ), mock.patch.object(
                    installer.os,
                    "geteuid",
                    return_value=1000,
                ), mock.patch.object(
                    installer,
                    "_resolve_user_unit_dirs",
                    return_value=(
                        installer.FLUIDSYNTH_USER_UNIT_DIRS,
                        {
                            "source": "synthetic-root-plan-test",
                            "live_verified": False,
                            "paths": list(installer.FLUIDSYNTH_USER_UNIT_DIRS),
                        },
                    ),
                ), mock.patch.object(
                    installer,
                    "_open_lock",
                    side_effect=AssertionError("plan opened the apply lock"),
                ):
                    plan = installer.install(
                        source_root=source,
                        target_root=installer.DEFAULT_TARGET_ROOT,
                        apply=False,
                        expected_head=head,
                    )
            finally:
                privileged.chmod(0o755)

            self.assertTrue(plan["valid"])
            self.assertFalse(plan["apply"])
            self.assertEqual(plan["source_binding"]["commit"], head)
            self.assertFalse(plan["transaction"]["committed"])
            legacy_entry = next(
                item
                for item in plan["files"]
                if item["target"].endswith(legacy_relative)
            )
            self.assertFalse(legacy_entry["backup_metadata"]["available"])
            self.assertEqual(legacy.read_bytes(), legacy_data)
            self.assertFalse((target / installer.LOCK_RELATIVE).exists())
            self.assertFalse((target / installer.RECEIPT_RELATIVE).exists())
            self.assertFalse((target / installer.BACKUP_ROOT_RELATIVE).exists())
            self.assertFalse(
                any(
                    ".stage." in path.name or ".rollback." in path.name
                    for path in target.rglob("*")
                )
            )

    def test_apply_to_root_refuses_insufficient_privilege_before_lock(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            root_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(
                installer,
                "_open_root",
                return_value=root_fd,
            ), mock.patch.object(
                installer.os,
                "geteuid",
                return_value=1000,
            ), mock.patch.object(
                installer,
                "_open_lock",
            ) as open_lock:
                with self.assertRaisesRegex(installer.InstallError, "requires root"):
                    installer.install(
                        source_root=source,
                        target_root=installer.DEFAULT_TARGET_ROOT,
                        apply=True,
                        expected_head=head,
                    )
            open_lock.assert_not_called()
            self.assertEqual(list(target.iterdir()), [])

    def test_backup_collision_fails_full_preflight(self) -> None:
        with committed_source() as (source, head), tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            legacy_relative = (
                "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf"
            )
            legacy = target / legacy_relative
            legacy.parent.mkdir(parents=True)
            legacy_data = (
                b"[Service]\nExecStart=\n"
                b"ExecStart=/usr/local/sbin/heim-pc-set-performance-profile\n"
            )
            legacy.write_bytes(legacy_data)
            legacy.chmod(0o644)
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
                "SystemMaxUse": "512M",
                "RuntimeMaxUse": "256M",
                "SystemKeepFree": "20G",
                "MaxRetentionSec": "7day",
                "Compress": "yes",
            },
        )


if __name__ == "__main__":
    unittest.main()
