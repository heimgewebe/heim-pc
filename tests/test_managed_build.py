from __future__ import annotations

import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, call, patch

from scripts import managed_build


DOCKER_CLIENT_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "HOME": "/",
    "SYSTEMD_COLORS": "0",
}
INHERITED_DOCKER_ENVIRONMENT = {
    "PATH": "/untrusted/inherited-path",
    "HOME": "/untrusted/home",
    "DOCKER_HOST": "tcp://docker.invalid:2376",
    "DOCKER_CONTEXT": "untrusted-context",
    "DOCKER_CONFIG": "/untrusted/docker-config",
    "DOCKER_TLS": "1",
    "DOCKER_TLS_VERIFY": "1",
    "DOCKER_CERT_PATH": "/untrusted/docker-certs",
    "DOCKER_API_VERSION": "1.99",
    "DOCKER_CUSTOM_HEADERS": "X-Fixture=untrusted",
    "XDG_CONFIG_HOME": "/untrusted/config",
    "XDG_RUNTIME_DIR": "/untrusted/runtime",
    "SSH_AUTH_SOCK": "/untrusted/agent",
    "SSL_CERT_FILE": "/untrusted/ca.pem",
    "SSL_CERT_DIR": "/untrusted/certs",
    "HTTP_PROXY": "http://proxy.invalid:8080",
    "HTTPS_PROXY": "http://proxy.invalid:8080",
}


class ManagedBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy_path = (
            Path(__file__).resolve().parents[1]
            / "config"
            / "managed-build.v1.json"
        )
        self.policy = managed_build.load_policy(self.policy_path)
        self.docker_executable_patch = patch.object(
            managed_build, "_docker_executable", return_value="/usr/bin/docker"
        )
        self.docker_executable_patch.start()
        self.addCleanup(self.docker_executable_patch.stop)

    def make_git_repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "tests@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Managed Build Tests"],
            check=True,
        )
        (repo / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "fixture"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "https://secret-token@github.com/example/repository.git",
            ],
            check=True,
        )
        return repo

    def fixed_toolchain(self) -> dict[str, object]:
        return {"observations": {"fixture": "1"}, "sha256": "a" * 64}

    def trusted_nix_prepare_path(self) -> Path:
        return Path(managed_build.__file__).resolve().with_name("nixos_production_prepare.py")

    def make_nix_execution(self, root: Path):
        home = root / "home"
        home.mkdir()
        repo = self.make_git_repo(root)
        worker = self.trusted_nix_prepare_path()
        output = root / "artifact.json"
        command = [sys.executable, str(worker), "--managed-worker", "--repo", str(repo),
                   "--output", str(output), "--source-authority", "proof-only"]
        with patch.object(managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()):
            plan = managed_build.build_plan(
                self.policy, repo=repo, command=command, home=home,
                explicit_tool="nix", explicit_profile="nixos-production-prepare",
            )

        def runner(argv, **kwargs):
            output.write_text(json.dumps({
                "source_revision": plan["nix_guard"]["source_revision"],
                "nix_volume": plan["nix_guard"]["docker_volume"],
                "system_path": "/nix/store/" + "0" * 32 + "-nixos-system-heim-pc-test",
                "closure_manifest_sha256": "a" * 64,
                "closure_path_count": 1,
            }), encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0)

        return home, plan, command, runner

    def test_docker_binary_and_environment_are_fixed_for_all_observations_and_cleanup(self) -> None:
        self.docker_executable_patch.stop()
        managed_build._docker_executable.cache_clear()
        self.addCleanup(managed_build._docker_executable.cache_clear)
        executable = str(Path(sys.executable).resolve())
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        containers = ["c" * 64]
        volumes = {"fixture-source", "fixture-store"}
        observed = []

        def docker(argv, **kwargs):
            self.assertEqual(argv[0], executable)
            self.assertEqual(kwargs["env"], DOCKER_CLIENT_ENVIRONMENT)
            observed.append(argv[1:3])
            os.environ["PATH"] = "/untrusted/changed-after-first-docker-call"
            os.environ["DOCKER_HOST"] = "tcp://changed.invalid:2376"
            os.environ["DOCKER_CONTEXT"] = "changed-context"
            os.environ["DOCKER_CONFIG"] = "/untrusted/changed-config"
            if argv[1] == "--version":
                self.assertEqual(kwargs["timeout"], 5)
                output = "Docker fixture\n"
            elif argv[1] == "ps":
                self.assertEqual(kwargs["timeout"], 5)
                output = "\n".join(containers).encode("ascii")
            elif argv[1] == "rm":
                self.assertEqual(kwargs["timeout"], 5)
                self.assertEqual(argv[2:], ["--force", "c" * 64])
                containers.clear()
                output = b""
            elif argv[1:3] == ["volume", "ls"]:
                self.assertEqual(kwargs["timeout"], 5)
                output = "\n".join(sorted(volumes)).encode("ascii")
            elif argv[1:3] == ["volume", "rm"]:
                self.assertEqual(kwargs["timeout"], managed_build.NIX_VOLUME_REMOVE_TIMEOUT_SECONDS)
                self.assertEqual(kwargs["timeout"], 30.0)
                volumes.remove(argv[-1])
                output = b""
            else:
                self.fail(f"unexpected Docker call: {argv}")
            return subprocess.CompletedProcess(argv, 0, output, b"")

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, INHERITED_DOCKER_ENVIRONMENT),
            patch.object(managed_build.shutil, "which", return_value=sys.executable) as which,
            patch.object(managed_build.subprocess, "run", side_effect=docker),
            patch.object(managed_build.time, "sleep"),
        ):
            root = Path(directory)
            toolchain = managed_build._toolchain_digest("nix", [sys.executable], root)
            self.assertEqual(toolchain["observations"]["docker"], "rc=0\nDocker fixture")
            self.assertEqual(managed_build._nix_container_ids(label), ["c" * 64])
            self.assertEqual(managed_build._remove_exact_nix_containers(label), (1, True))
            managed_build._remove_failed_nix_outputs(
                ["--output", str(root / "artifact.json")],
                {"source_volume": "fixture-source", "docker_volume": "fixture-store"},
            )
            which.assert_called_once_with("docker", path="/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertFalse(volumes)
        self.assertEqual({tuple(item) for item in observed}, {
            ("--version",), ("ps", "--no-trunc"), ("rm", "--force"),
            ("volume", "ls"), ("volume", "rm"),
        })

    def test_nix_container_cleanup_accepts_verified_auto_remove_race(self) -> None:
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        container = "c" * 64
        failed_rm = subprocess.CompletedProcess(
            ["/usr/bin/docker", "rm", "--force", container],
            1,
            b"",
            f"Error response from daemon: No such container: {container}".encode("ascii"),
        )
        with (
            patch.object(
                managed_build, "_nix_container_ids",
                side_effect=[[container], [], [], []],
            ) as inventory,
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", return_value=failed_rm) as run,
            patch.object(managed_build.time, "sleep"),
        ):
            self.assertEqual(managed_build._remove_exact_nix_containers(label), (0, True))
        run.assert_called_once()
        self.assertGreaterEqual(inventory.call_count, 3)

    def test_nix_container_cleanup_timeout_can_be_resolved_by_verified_absence(self) -> None:
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        container_id = "c" * 64
        with (
            patch.object(
                managed_build, "_nix_container_ids",
                side_effect=[[container_id], [], []],
            ) as inventory,
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(
                managed_build.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(
                    ["/usr/bin/docker", "rm", "--force", container_id],
                    managed_build.NIX_CONTAINER_REMOVE_TIMEOUT_SECONDS,
                ),
            ) as run,
            patch.object(managed_build.time, "sleep"),
        ):
            self.assertEqual(managed_build._remove_exact_nix_containers(label), (0, True))
        run.assert_called_once()
        self.assertGreaterEqual(inventory.call_count, 3)

    def test_nix_container_cleanup_timeout_fails_closed_if_container_survives(self) -> None:
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        container_id = "c" * 64
        with (
            patch.object(
                managed_build, "_nix_container_ids",
                side_effect=[[container_id], [container_id], [container_id], [container_id]],
            ),
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(
                managed_build.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(
                    ["/usr/bin/docker", "rm", "--force", container_id],
                    managed_build.NIX_CONTAINER_REMOVE_TIMEOUT_SECONDS,
                ),
            ) as run,
            patch.object(managed_build.time, "sleep"),
        ):
            self.assertEqual(managed_build._remove_exact_nix_containers(label), (0, False))
        self.assertEqual(run.call_count, 3)

    def test_nix_container_cleanup_oserror_can_be_resolved_by_verified_absence(self) -> None:
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        container_id = "c" * 64
        with (
            patch.object(
                managed_build, "_nix_container_ids",
                side_effect=[[container_id], [], []],
            ),
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", side_effect=OSError("exec failed")),
            patch.object(managed_build.time, "sleep"),
        ):
            self.assertEqual(managed_build._remove_exact_nix_containers(label), (0, True))

    def test_nix_container_cleanup_accepts_exact_removal_in_progress_race(self) -> None:
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        container_id = "c" * 64
        failed_rm = subprocess.CompletedProcess(
            ["/usr/bin/docker", "rm", "--force", container_id],
            1,
            b"",
            (
                f"Error response from daemon: removal of container {container_id} "
                "is already in progress"
            ).encode("ascii"),
        )
        with (
            patch.object(
                managed_build, "_nix_container_ids",
                side_effect=[[container_id], [], []],
            ),
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", return_value=failed_rm),
            patch.object(managed_build.time, "sleep"),
        ):
            self.assertEqual(managed_build._remove_exact_nix_containers(label), (0, True))

    def test_nix_container_cleanup_counts_partial_individual_success(self) -> None:
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        first = "c" * 64
        second = "d" * 64
        outcomes = [
            subprocess.CompletedProcess(
                ["/usr/bin/docker", "rm", "--force", first], 0, b"", b""
            ),
            subprocess.CompletedProcess(
                ["/usr/bin/docker", "rm", "--force", second],
                1,
                b"",
                f"Error response from daemon: No such container: {second}".encode("ascii"),
            ),
        ]
        with (
            patch.object(
                managed_build, "_nix_container_ids",
                side_effect=[[first, second], [], []],
            ),
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", side_effect=outcomes) as run,
            patch.object(managed_build.time, "sleep"),
        ):
            self.assertEqual(managed_build._remove_exact_nix_containers(label), (1, True))
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["/usr/bin/docker", "rm", "--force", first],
                ["/usr/bin/docker", "rm", "--force", second],
            ],
        )

    def test_nix_container_cleanup_ambiguous_nonzero_is_fail_closed_even_if_absent(self) -> None:
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        container = "c" * 64
        failed_rm = subprocess.CompletedProcess(
            ["/usr/bin/docker", "rm", "--force", container],
            1,
            b"",
            b"error during connect: unexpected EOF",
        )
        with (
            patch.object(
                managed_build, "_nix_container_ids",
                side_effect=[[container], [], []],
            ) as inventory,
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", return_value=failed_rm),
        ):
            with self.assertRaisesRegex(
                managed_build.ManagedBuildError,
                "container removal outcome is ambiguous after nonzero exit",
            ):
                managed_build._remove_exact_nix_containers(label)
        self.assertEqual(inventory.call_count, 1)

    def test_nix_container_cleanup_fails_closed_when_rm_fails_and_container_survives(self) -> None:
        label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
        container = "c" * 64
        failed_rm = subprocess.CompletedProcess(
            ["/usr/bin/docker", "rm", "--force", container], 1, b"", b"still running"
        )
        with (
            patch.object(managed_build, "_nix_container_ids", return_value=[container]),
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", return_value=failed_rm) as run,
            patch.object(managed_build.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                managed_build.ManagedBuildError,
                "container removal outcome is ambiguous after nonzero exit",
            ):
                managed_build._remove_exact_nix_containers(label)
        self.assertEqual(run.call_count, 1)

    def test_nix_worker_monitor_and_timeout_cleanup_share_docker_environment(self) -> None:
        with patch.object(sys, "path", [str(managed_build.ROOT / "scripts"), *sys.path]):
            from scripts import nixos_production_prepare as prepare

        with tempfile.TemporaryDirectory() as directory:
            home, plan, command, _runner = self.make_nix_execution(Path(directory))
            guard = plan["nix_guard"]
            output = Path(managed_build._command_option_value(command, "--output"))
            process = Mock(pid=4343, returncode=None)
            process.poll.side_effect = lambda: process.returncode
            containers = []
            volumes = set()
            events = []
            worker_environments = []
            manager_environments = []
            real_run, real_popen = subprocess.run, subprocess.Popen

            def docker(argv, **kwargs):
                if argv[0] not in {"docker", "/usr/bin/docker"}:
                    return real_run(argv, **kwargs)
                self.assertEqual(kwargs["env"], DOCKER_CLIENT_ENVIRONMENT)
                if argv[0] == "docker":
                    worker_environments.append(kwargs["env"])
                else:
                    manager_environments.append(kwargs["env"])
                stdout = b""
                if argv[1:3] == ["volume", "create"]:
                    volumes.add(argv[-1])
                elif argv[1] == "run":
                    if argv[2] == "-d":
                        self.assertFalse(containers)
                        containers.append(("d" * 64, argv[argv.index("--label") + 1]))
                        stdout = ("d" * 64 + "\n").encode("ascii")
                        events.append("observer-container")
                    else:
                        self.assertEqual(argv[2], "--label")
                        self.assertEqual([cid for cid, _tag in containers], ["d" * 64])
                        containers.append(("c" * 64, argv[3]))
                        events.append("worker-container")
                elif argv[1] == "ps":
                    self.assertEqual(kwargs["timeout"], 5)
                    label = argv[-1].removeprefix("label=")
                    stdout = "\n".join(cid for cid, tag in containers if tag == label).encode("ascii")
                elif argv[1] == "rm":
                    self.assertEqual(kwargs["timeout"], 5)
                    self.assertEqual(argv[2], "--force")
                    self.assertIn(argv[3], {"c" * 64, "d" * 64})
                    containers[:] = [(cid, tag) for cid, tag in containers if cid != argv[3]]
                    events.append("container-removal" if argv[3] == "c" * 64 else "observer-removal")
                elif argv[1:3] == ["volume", "ls"]:
                    self.assertEqual(kwargs["timeout"], 5)
                    stdout = "\n".join(sorted(volumes)).encode("ascii")
                elif argv[1:3] == ["volume", "rm"]:
                    self.assertEqual(kwargs["timeout"], managed_build.NIX_VOLUME_REMOVE_TIMEOUT_SECONDS)
                    self.assertFalse(containers)
                    volumes.remove(argv[-1])
                    events.append("volume-removal")
                else:
                    self.fail(f"unexpected Docker call: {argv}")
                return subprocess.CompletedProcess(argv, 0, stdout, b"")

            def start_worker(argv, **kwargs):
                if argv != command:
                    return real_popen(argv, **kwargs)
                self.assertEqual(kwargs["env"]["DOCKER_HOST"], INHERITED_DOCKER_ENVIRONMENT["DOCKER_HOST"])
                self.assertEqual(kwargs["env"][prepare.MANAGED_WORKER_ENV], "1")
                # Exercise the real worker's Docker boundary without launching Docker.
                with patch.dict(os.environ, kwargs["env"], clear=True):
                    prepare.run(["docker", "volume", "create", guard["source_volume"]])
                    prepare.run(["docker", "volume", "create", guard["docker_volume"]])
                    prepare.run(["docker", "run", "--rm", "fixture-image"])
                output.write_text("rejected partial output\n", encoding="utf-8")
                return process

            def terminate(item):
                self.assertIs(item, process)
                process.returncode = -15
                events.append("terminate-worker")

            with (
                patch.dict(os.environ, {
                    **INHERITED_DOCKER_ENVIRONMENT, "PATH": os.environ.get("PATH", ""),
                }),
                patch.object(managed_build.subprocess, "run", side_effect=docker),
                patch.object(managed_build.subprocess, "Popen", side_effect=start_worker),
                patch.object(managed_build.time, "monotonic", side_effect=[
                    0.0, float(guard["runtime_budget_seconds"]["hard"]) + 1,
                ]),
                patch.object(managed_build.time, "sleep"),
                patch.object(managed_build, "_terminate_process_group", side_effect=terminate),
                patch.object(managed_build, "_bounded_store_scan", side_effect=lambda *_args, **_kwargs:
                    managed_build.scan_worktree_payloads(Path(guard["store_root"]), ["."])),
            ):
                returncode = managed_build.execute_plan(
                    self.policy, plan, command, home=home, runner=managed_build.subprocess.run,
                )

            self.assertEqual(returncode, 124)
            receipts = list((Path(plan["state_root"]) / "receipts").glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["returncode"], 124)
            self.assertTrue(receipt["nix_build"]["runtime_timeout_triggered"])
            self.assertTrue(receipt["nix_build"]["container_cleanup_verified"])
            self.assertEqual(receipt["nix_build"]["container_count_force_removed"], 1)
            self.assertEqual(events, [
                "observer-container", "worker-container", "terminate-worker", "container-removal", "observer-removal",
                "volume-removal", "volume-removal",
            ])
            self.assertEqual(len(worker_environments), 3)
            self.assertTrue(manager_environments)
            self.assertTrue(all(env == worker_environments[0] for env in manager_environments))
            self.assertFalse(containers)
            self.assertFalse(volumes)
            self.assertFalse(output.exists())
            self.assertFalse(managed_build._managed_nix_success_receipt_path(command).exists())
            self.assertFalse(Path(guard["lifecycle_fence_path"]).exists())

    def test_docker_resolution_fails_closed_without_trusted_executable(self) -> None:
        self.docker_executable_patch.stop()
        managed_build._docker_executable.cache_clear()
        self.addCleanup(managed_build._docker_executable.cache_clear)
        with (
            patch.object(managed_build.shutil, "which", return_value=None),
            patch.object(managed_build.subprocess, "run") as run,
            self.assertRaises(managed_build.ManagedBuildError),
        ):
            managed_build._nix_volume_exists("fixture")
        run.assert_not_called()

    def test_nix_volume_absence_requires_successful_exact_inventory(self) -> None:
        cases = [
            (0, b"", False),
            (0, b"fixture-extra\nother-fixture\n", False),
            (0, b"fixture\n", True),
            (1, b"", None),
            (125, b"", None),
            (0, b"\xff\n", None),
            (0, b"not a volume\n", None),
            (0, b"\n", None),
        ]
        for returncode, output, expected in cases:
            with self.subTest(returncode=returncode, output=output):
                def docker(argv, **kwargs):
                    self.assertEqual(argv[0], "/usr/bin/docker")
                    # Even an inspect error saying 'not found' is no absence proof.
                    if argv[1:3] == ["volume", "inspect"]:
                        return subprocess.CompletedProcess(argv, 1, b"", b"not found")
                    self.assertEqual(argv[1:], ["volume", "ls", "--format", "{{.Name}}"])
                    return subprocess.CompletedProcess(argv, returncode, output, b"daemon error")
                with patch.object(managed_build.subprocess, "run", side_effect=docker) as run:
                    if expected is None:
                        with self.assertRaises(managed_build.ManagedBuildError):
                            managed_build._nix_volume_exists("fixture")
                    else:
                        self.assertIs(managed_build._nix_volume_exists("fixture"), expected)
                    self.assertTrue(any(item.args[0][1:3] == ["volume", "ls"] for item in run.call_args_list))

    def test_nix_volume_cleanup_requires_successful_post_removal_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def docker(argv, **kwargs):
                if argv[1:3] == ["volume", "rm"]:
                    return subprocess.CompletedProcess(argv, 0, b"", b"")
                if argv[1:3] == ["volume", "inspect"]:
                    return subprocess.CompletedProcess(argv, 1, b"", b"permission denied")
                output = b"fixture-source\n" if run.call_count == 1 else b""
                return subprocess.CompletedProcess(argv, 0 if output else 1, output, b"")
            with patch.object(managed_build.subprocess, "run", side_effect=docker) as run:
                with self.assertRaisesRegex(managed_build.ManagedBuildError, "inventory"):
                    managed_build._remove_failed_nix_outputs(
                        ["--output", str(Path(directory) / "artifact.json")],
                        {"source_volume": "fixture-source", "docker_volume": "fixture-store"},
                    )
            self.assertEqual([item.args[0][1:3] for item in run.call_args_list],
                             [["volume", "ls"], ["volume", "rm"], ["volume", "ls"]])

    def test_nix_inventory_failure_blocks_worker_or_retains_failure_fence(self) -> None:
        for boundary in ("preflight", "cleanup"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                home, plan, command, _runner = self.make_nix_execution(Path(directory))
                worker = Mock(return_value=subprocess.CompletedProcess(command, 1))
                real_run = subprocess.run
                inventory_calls = 0

                def docker(argv, **kwargs):
                    nonlocal inventory_calls
                    if argv[0] != "/usr/bin/docker":
                        return real_run(argv, **kwargs)
                    self.assertEqual(argv[1:3], ["volume", "ls"])
                    inventory_calls += 1
                    failed = boundary == "preflight" or inventory_calls > 2
                    return subprocess.CompletedProcess(argv, 1 if failed else 0, b"", b"daemon unavailable")

                with patch.object(managed_build.subprocess, "run", side_effect=docker):
                    with self.assertRaisesRegex(managed_build.ManagedBuildError, "inventory"):
                        managed_build.execute_plan(self.policy, plan, command, home=home, runner=worker)
                self.assertEqual(worker.call_count, 0 if boundary == "preflight" else 1)
                self.assertEqual(Path(plan["nix_guard"]["lifecycle_fence_path"]).exists(), boundary == "cleanup")
                self.assertFalse(managed_build._managed_nix_success_receipt_path(command).exists())

    def test_nix_volume_removal_errors_preserve_cause_and_stop_cleanup(self) -> None:
        for error in (subprocess.TimeoutExpired("docker", 30), OSError("removal unavailable")):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                with patch.object(managed_build.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 0, b"fixture-source\n", b""), error,
                ]) as run:
                    with self.assertRaisesRegex(
                        managed_build.ManagedBuildError, "^failed to remove rejected managed Nix volume$"
                    ) as caught:
                        managed_build._remove_failed_nix_outputs(
                            ["--output", str(Path(directory) / "artifact.json")],
                            {"source_volume": "fixture-source", "docker_volume": "fixture-store"},
                        )
                self.assertIs(caught.exception.__cause__, error)
                self.assertEqual(run.call_args_list, [
                    call(["/usr/bin/docker", "volume", "ls", "--format", "{{.Name}}"],
                         env=DOCKER_CLIENT_ENVIRONMENT, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, check=False, timeout=5),
                    call(["/usr/bin/docker", "volume", "rm", "--force", "fixture-source"],
                         env=DOCKER_CLIENT_ENVIRONMENT,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                         timeout=managed_build.NIX_VOLUME_REMOVE_TIMEOUT_SECONDS),
                ])

    def test_main_reports_volume_removal_errors_and_retains_lifecycle_fence(self) -> None:
        for error in (subprocess.TimeoutExpired("docker", 30), OSError("removal unavailable")):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                home, plan, command, _runner = self.make_nix_execution(Path(directory))
                guard = plan["nix_guard"]
                fence = Path(guard["lifecycle_fence_path"])
                worker = Mock(return_value=subprocess.CompletedProcess(command, 1))
                real_run, real_execute = subprocess.run, managed_build.execute_plan
                docker_calls = []

                def docker(argv, **kwargs):
                    if argv[0] != "/usr/bin/docker":
                        return real_run(argv, **kwargs)
                    self.assertEqual(kwargs["env"], DOCKER_CLIENT_ENVIRONMENT)
                    docker_calls.append(argv[1:])
                    if argv[1:3] == ["volume", "rm"]:
                        self.assertEqual(argv[3:], ["--force", guard["source_volume"]])
                        self.assertEqual(kwargs["timeout"], managed_build.NIX_VOLUME_REMOVE_TIMEOUT_SECONDS)
                        raise error
                    self.assertEqual(argv[1:], ["volume", "ls", "--format", "{{.Name}}"])
                    self.assertEqual(kwargs["timeout"], 5)
                    output = (guard["source_volume"] + "\n").encode("ascii") if worker.called else b""
                    return subprocess.CompletedProcess(argv, 0, output, b"")

                def execute(policy, planned, argv, **kwargs):
                    return real_execute(policy, planned, argv, runner=worker, **kwargs)

                with (
                    patch.dict(os.environ, {
                        **INHERITED_DOCKER_ENVIRONMENT,
                        "HOME": str(home), "PATH": os.environ.get("PATH", ""),
                    }),
                    patch.object(managed_build, "build_plan", return_value=plan),
                    patch.object(managed_build, "execute_plan", side_effect=execute),
                    patch.object(managed_build.subprocess, "run", side_effect=docker),
                    patch.object(sys, "stderr", new_callable=io.StringIO) as stderr,
                ):
                    result = managed_build.main([
                        "--policy", str(self.policy_path), "run", "--repo", plan["repository_root"],
                        "--tool", "nix", "--profile", plan["profile"], "--", *command,
                    ])
                self.assertEqual(result, 2)
                self.assertEqual(json.loads(stderr.getvalue()), {
                    "schema_version": 1, "kind": "heim_pc.managed_build_error",
                    "error": "failed to remove rejected managed Nix volume",
                })
                worker.assert_called_once()
                self.assertEqual(docker_calls, [
                    ["volume", "ls", "--format", "{{.Name}}"],
                    ["volume", "ls", "--format", "{{.Name}}"],
                    ["volume", "ls", "--format", "{{.Name}}"],
                    ["volume", "rm", "--force", guard["source_volume"]],
                ])
                self.assertEqual(json.loads(fence.read_text())["source_revision"], guard["source_revision"])
                self.assertFalse(managed_build._managed_nix_success_receipt_path(command).exists())
                self.assertFalse(list((Path(plan["state_root"]) / "receipts").glob("*.json")))
                retry_worker = Mock()
                # Even a later empty volume inventory cannot authorize reuse.
                with patch.object(managed_build, "_nix_volume_exists", return_value=False):
                    with self.assertRaisesRegex(managed_build.ManagedBuildError, "fence requires reconciliation"):
                        real_execute(self.policy, plan, command, home=home, runner=retry_worker)
                retry_worker.assert_not_called()

    def test_nix_success_publication_and_fence_clear_failure_windows_are_recoverable(self) -> None:
        windows = (
            "managed-file-fsync", "managed-directory-fsync", "pending-create",
            "pending-file-fsync", "pending-directory-fsync", "success-create",
            "success-file-fsync", "success-directory-fsync", "fence-unlink",
            "recovery-link", "recovery-directory-fsync", "recovery-unlink",
            "recovery-retirement-fsync", "fence-directory-fsync",
            "persistent-success-directory-fsync", "persistent-fence-directory-fsync",
        )
        for window in windows:
            with self.subTest(window=window), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                home, plan, command, runner = self.make_nix_execution(root)
                fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
                recovery = managed_build._nix_recovery_fence_path(fence)
                pending = managed_build._nix_pending_completion_path(fence)
                success = managed_build._managed_nix_success_receipt_path(command)
                receipts = Path(plan["state_root"]) / "receipts"
                real_fsync, real_create = os.fsync, managed_build._atomic_create_json
                real_unlink, real_link = Path.unlink, os.link
                triggered = False
                pending_durable = False
                lifecycle_terminal = False

                def fail():
                    nonlocal triggered
                    triggered = True
                    raise OSError("injected durability failure")

                def fsync(fd):
                    nonlocal pending_durable, lifecycle_terminal
                    target = Path(os.readlink(f"/proc/self/fd/{fd}"))
                    is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
                    if not triggered or window.startswith("persistent-"):
                        if window == "managed-file-fsync" and not is_directory and target.parent == receipts:
                            fail()
                        if window == "managed-directory-fsync" and target == receipts:
                            fail()
                        if window == "pending-file-fsync" and target == pending:
                            fail()
                        if window == "pending-directory-fsync" and target == fence.parent and pending.exists():
                            fail()
                        if window == "success-file-fsync" and target == success:
                            self.assertTrue(lifecycle_terminal)
                            fail()
                        if window in {"success-directory-fsync", "persistent-success-directory-fsync"} and target == root and (success.exists() or triggered):
                            self.assertTrue(lifecycle_terminal)
                            fail()
                        if window == "recovery-directory-fsync" and target == fence.parent and recovery.exists():
                            self.assertTrue(fence.exists())
                            fail()
                        if window in {"fence-directory-fsync", "persistent-fence-directory-fsync"} and target == fence.parent and (not fence.exists() or triggered):
                            self.assertTrue(pending_durable)
                            fail()
                        if window == "recovery-retirement-fsync" and target == fence.parent and not fence.exists() and not recovery.exists():
                            self.assertTrue(pending_durable)
                            fail()
                    real_fsync(fd)
                    if target == fence.parent:
                        pending_durable |= pending.exists()
                        lifecycle_terminal = not fence.exists() and not recovery.exists()

                def create(path, payload):
                    if path == pending and window == "pending-create":
                        fail()
                    if path == success:
                        self.assertTrue(lifecycle_terminal)
                        self.assertTrue(pending_durable)
                        if window == "success-create":
                            fail()
                    return real_create(path, payload)

                def unlink(path, *args, **kwargs):
                    if path in (fence, recovery):
                        self.assertTrue(pending_durable)
                        self.assertFalse(success.exists())
                        if window == ("fence-unlink" if path == fence else "recovery-unlink") and not triggered:
                            fail()
                    return real_unlink(path, *args, **kwargs)

                def link(source, destination, **kwargs):
                    if window == "recovery-link" and Path(source) == fence:
                        fail()
                    return real_link(source, destination, **kwargs)

                with (
                    patch.object(managed_build, "_nix_volume_exists", return_value=False),
                    patch.object(managed_build.os, "fsync", side_effect=fsync),
                    patch.object(managed_build, "_atomic_create_json", side_effect=create),
                    patch.object(Path, "unlink", new=unlink),
                    patch.object(managed_build.os, "link", side_effect=link),
                ):
                    with self.assertRaises((OSError, managed_build.ManagedBuildError)):
                        managed_build.execute_plan(self.policy, plan, command, home=home, runner=runner)
                self.assertTrue(triggered)
                self.assertFalse(success.exists())
                self.assertFalse(list(receipts.glob("*.json")))
                anchor = next(path for path in (fence, recovery, pending) if path.exists())
                self.assertEqual(json.loads(anchor.read_text())["source_revision"], plan["nix_guard"]["source_revision"])
                Path(managed_build._command_option_value(command, "--output")).unlink()
                worker = Mock()
                with patch.object(managed_build, "_nix_volume_exists", return_value=False), self.assertRaisesRegex(managed_build.ManagedBuildError, "fence requires reconciliation"):
                    managed_build.execute_plan(self.policy, plan, command, home=home, runner=worker)
                worker.assert_not_called()

    def test_nix_recovery_fence_survives_failed_primary_restoration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, plan, command, runner = self.make_nix_execution(Path(directory))
            fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
            recovery = managed_build._nix_recovery_fence_path(fence)
            real_fsync, real_link = managed_build._fsync_directory, os.link

            def fsync(path):
                if path == fence.parent and not fence.exists():
                    raise OSError("primary removal fsync failed")
                return real_fsync(path)

            def link(source, destination, **kwargs):
                if Path(destination) == fence:
                    raise OSError("primary restoration failed")
                return real_link(source, destination, **kwargs)

            with (
                patch.object(managed_build, "_nix_volume_exists", return_value=False),
                patch.object(managed_build, "_fsync_directory", side_effect=fsync),
                patch.object(managed_build.os, "link", side_effect=link),
                self.assertRaisesRegex(OSError, "primary restoration failed"),
            ):
                managed_build.execute_plan(self.policy, plan, command, home=home, runner=runner)
            self.assertFalse(fence.exists())
            self.assertEqual(json.loads(recovery.read_text())["source_revision"], plan["nix_guard"]["source_revision"])
            self.assertFalse(managed_build._managed_nix_success_receipt_path(command).exists())
            self.assertFalse(list((Path(plan["state_root"]) / "receipts").glob("*.json")))
            Path(managed_build._command_option_value(command, "--output")).unlink()
            worker = Mock()
            with patch.object(managed_build, "_nix_volume_exists", return_value=False), self.assertRaisesRegex(managed_build.ManagedBuildError, "fence requires reconciliation"):
                managed_build.execute_plan(self.policy, plan, command, home=home, runner=worker)
            worker.assert_not_called()

    def test_nix_publication_failure_invalidates_receipts_even_when_unlink_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, plan, command, runner = self.make_nix_execution(Path(directory))
            success = managed_build._managed_nix_success_receipt_path(command)
            receipts = Path(plan["state_root"]) / "receipts"
            fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
            real_fsync, real_unlink = managed_build._fsync_directory, Path.unlink
            triggered = False

            def fsync(path):
                nonlocal triggered
                if path == success.parent and success.exists() and not triggered:
                    triggered = True
                    raise OSError("success directory fsync failed")
                return real_fsync(path)

            def unlink(path, *args, **kwargs):
                if path == success or path.parent == receipts:
                    raise OSError("receipt unlink failed")
                return real_unlink(path, *args, **kwargs)

            with (
                patch.object(managed_build, "_nix_volume_exists", return_value=False),
                patch.object(managed_build, "_fsync_directory", side_effect=fsync),
                patch.object(Path, "unlink", new=unlink),
                self.assertRaisesRegex(managed_build.ManagedBuildError, "invalidation was not durable"),
            ):
                managed_build.execute_plan(self.policy, plan, command, home=home, runner=runner)
            self.assertTrue(triggered)
            self.assertEqual(success.read_bytes(), b"")
            self.assertEqual([path.read_bytes() for path in receipts.glob("*.json")], [b""])
            self.assertTrue(managed_build._nix_pending_completion_path(fence).exists())
            self.assertFalse(fence.exists())

    def test_nix_resurrected_receipts_are_invalid_after_persistent_directory_fsync_failure(self) -> None:
        from scripts import nixos_production_install as installer

        for boundary in ("publication", "fence-removal-and-restoration"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                home, plan, command, runner = self.make_nix_execution(Path(directory))
                success = managed_build._managed_nix_success_receipt_path(command)
                receipts = Path(plan["state_root"]) / "receipts"
                fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
                recovery = managed_build._nix_recovery_fence_path(fence)
                pending = managed_build._nix_pending_completion_path(fence)
                expected_receipt_count = 2 if boundary == "publication" else 1
                real_directory_fsync = managed_build._fsync_directory
                real_fsync, real_unlink, real_link = os.fsync, Path.unlink, os.link
                held = {}
                durable_payloads = {}
                events = {}

                def directory_fsync(path):
                    trigger = (
                        boundary == "publication" and path == success.parent and success.exists()
                    ) or (
                        boundary == "fence-removal-and-restoration"
                        and path == fence.parent and not fence.exists()
                    )
                    if not held and trigger:
                        selected = [*receipts.glob("*.json")]
                        if boundary == "publication":
                            selected.insert(0, success)
                        else:
                            # The new state machine has not published any
                            # canonical success at this nonterminal boundary.
                            self.assertFalse(success.exists())
                        for receipt in selected:
                            held[receipt] = os.open(receipt, os.O_RDONLY | os.O_CLOEXEC)
                            valid = json.loads(os.pread(held[receipt], 65536, 0))
                            self.assertEqual(valid["returncode"], 0)
                            if receipt == success:
                                self.assertIs(valid["lifecycle_fence_cleared"], True)
                            events[receipt] = ["valid"]
                        self.assertEqual(len(held), expected_receipt_count)
                        raise OSError("publication completion failed")
                    if held and path in {success.parent, receipts}:
                        self.assertTrue(fence.exists() or recovery.exists() or pending.exists())
                        for receipt in held:
                            if receipt.parent == path:
                                events[receipt].append("directory-fsync-failed")
                        raise OSError("persistent receipt directory fsync failure")
                    return real_directory_fsync(path)

                def fsync(fd):
                    real_fsync(fd)
                    for receipt, retained_fd in held.items():
                        info, retained = os.fstat(fd), os.fstat(retained_fd)
                        if (info.st_dev, info.st_ino) == (retained.st_dev, retained.st_ino):
                            durable_payloads[receipt] = os.pread(retained_fd, 65536, 0)
                            self.assertEqual(durable_payloads[receipt], b"")
                            events[receipt].append("content-fsync")

                def unlink(path, *args, **kwargs):
                    if path in held:
                        self.assertEqual(events[path], ["valid", "content-fsync"])
                        self.assertEqual(path.stat().st_ino, os.fstat(held[path]).st_ino)
                        real_unlink(path, *args, **kwargs)
                        events[path].append("unlink")
                        return
                    return real_unlink(path, *args, **kwargs)

                def link(source, destination, **kwargs):
                    if boundary == "fence-removal-and-restoration" and Path(destination) == fence:
                        raise OSError("primary fence restoration failed")
                    return real_link(source, destination, **kwargs)

                try:
                    with (
                        patch.object(managed_build, "_nix_volume_exists", return_value=False),
                        patch.object(managed_build, "_fsync_directory", side_effect=directory_fsync),
                        patch.object(managed_build.os, "fsync", side_effect=fsync),
                        patch.object(Path, "unlink", new=unlink),
                        patch.object(managed_build.os, "link", side_effect=link),
                        self.assertRaisesRegex(managed_build.ManagedBuildError, "invalidation was not durable"),
                    ):
                        managed_build.execute_plan(self.policy, plan, command, home=home, runner=runner)
                    self.assertEqual(len(held), expected_receipt_count)
                    anchor = pending if boundary == "publication" else recovery
                    self.assertEqual(json.loads(anchor.read_text())["source_revision"], plan["nix_guard"]["source_revision"])
                    for receipt, fd in held.items():
                        self.assertEqual(events[receipt], ["valid", "content-fsync", "unlink", "directory-fsync-failed"])
                        self.assertFalse(receipt.exists())
                        self.assertEqual(os.fstat(fd).st_nlink, 0)
                        # Model crash resurrection from the last successfully
                        # fsynced content; also inspect the actual unlinked inode.
                        self.assertEqual(os.pread(fd, 65536, 0), durable_payloads[receipt])
                        receipt.write_bytes(durable_payloads[receipt])
                        receipt.chmod(0o600)
                        with self.assertRaises(json.JSONDecodeError):
                            json.loads(receipt.read_bytes())
                    with self.assertRaisesRegex(installer.ProductionInstallError, "cannot load"):
                        installer.load_managed_build_receipt(
                            success, {}, expected_policy_sha256=plan["policy_sha256"],
                            artifact_path=Path(managed_build._command_option_value(command, "--output")),
                        )
                    self.assertTrue(anchor.exists())
                finally:
                    for fd in held.values():
                        os.close(fd)

    def test_nix_receipt_invalidation_failures_do_not_skip_other_receipt(self) -> None:
        for operation in ("open", "fstat", "ftruncate", "fsync", "unlink", "truncate-no-effect", "unlink-no-effect"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                paths = [Path(directory) / name for name in ("public.json", "state.json")]
                for path in paths:
                    managed_build._atomic_create_json(path, {"returncode": 0, "lifecycle_fence_cleared": True})
                name = {"truncate-no-effect": "ftruncate", "unlink-no-effect": "unlink"}.get(operation, operation)
                owner = Path if name == "unlink" else managed_build.os
                real_operation = getattr(owner, name)
                fired = False

                def fail_once(*args, **kwargs):
                    nonlocal fired
                    if not fired:
                        fired = True
                        if operation.endswith("-no-effect"):
                            return None
                        raise OSError("unverifiable receipt invalidation")
                    return real_operation(*args, **kwargs)

                with (
                    patch.object(owner, name, new=fail_once),
                    self.assertRaisesRegex(managed_build.ManagedBuildError, "invalidation was not durable"),
                ):
                    managed_build._invalidate_nix_success_receipts(paths)
                self.assertTrue(fired)
                self.assertTrue(paths[0].exists())
                self.assertFalse(paths[1].exists())

    def test_nix_receipt_invalidation_rejects_unsafe_inodes_without_mutation(self) -> None:
        for kind in ("symlink", "hardlink", "directory", "fifo", "public-mode", "foreign-owner"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt, other = root / "receipt.json", root / "other.json"
                managed_build._atomic_create_json(other, {"unrelated": True})
                if kind == "symlink":
                    receipt.symlink_to(other)
                elif kind == "hardlink":
                    os.link(other, receipt)
                elif kind == "directory":
                    receipt.mkdir()
                elif kind == "fifo":
                    os.mkfifo(receipt)
                else:
                    managed_build._atomic_create_json(receipt, {"returncode": 0})
                    if kind == "public-mode":
                        receipt.chmod(0o666)
                uid = os.getuid() + (1 if kind == "foreign-owner" else 0)
                with (
                    patch.object(managed_build.os, "getuid", return_value=uid),
                    patch.object(managed_build.os, "ftruncate") as truncate,
                    patch.object(Path, "unlink") as unlink,
                    self.assertRaisesRegex(managed_build.ManagedBuildError, "invalidation was not durable"),
                ):
                    managed_build._invalidate_nix_success_receipts([receipt])
                truncate.assert_not_called()
                unlink.assert_not_called()
                self.assertEqual(json.loads(other.read_text()), {"unrelated": True})

    def test_nix_receipt_invalidation_rechecks_identity_and_absence_before_unlink(self) -> None:
        for boundary in ("open", "fsync", "absent", "rewrite"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt, replacement = root / "receipt.json", root / "replacement.json"
                payload = {"returncode": 0, "lifecycle_fence_cleared": True}
                if boundary != "absent":
                    managed_build._atomic_create_json(receipt, payload)
                managed_build._atomic_create_json(replacement, payload)
                real_open, real_fsync = os.open, os.fsync
                real_directory_fsync = managed_build._fsync_directory
                fired = False

                def replace():
                    nonlocal fired
                    fired = True
                    if boundary == "rewrite":
                        receipt.write_text(json.dumps(payload), encoding="utf-8")
                    else:
                        os.replace(replacement, receipt)

                def open_file(path, *args, **kwargs):
                    if boundary == "open" and Path(path) == receipt and not fired:
                        replace()
                    return real_open(path, *args, **kwargs)

                def fsync(fd):
                    real_fsync(fd)
                    if boundary in {"fsync", "rewrite"} and not fired:
                        replace()

                def directory_fsync(path):
                    if boundary == "absent" and not fired:
                        replace()
                    return real_directory_fsync(path)

                with (
                    patch.object(managed_build.os, "open", side_effect=open_file),
                    patch.object(managed_build.os, "fsync", side_effect=fsync),
                    patch.object(managed_build, "_fsync_directory", side_effect=directory_fsync),
                    patch.object(Path, "unlink") as unlink,
                    self.assertRaisesRegex(managed_build.ManagedBuildError, "invalidation was not durable"),
                ):
                    managed_build._invalidate_nix_success_receipts([receipt])
                self.assertTrue(fired)
                unlink.assert_not_called()
                self.assertEqual(json.loads(receipt.read_text()), payload)

    def test_nix_superseded_pending_journal_retirement_is_only_housekeeping(self) -> None:
        class PowerLoss(BaseException):
            pass

        for boundary in ("unlink-before", "unlink-after", "fsync-before", "fsync-after"):
            for error in (PowerLoss, OSError):
                with self.subTest(boundary=boundary, error=error.__name__), tempfile.TemporaryDirectory() as directory:
                    home, plan, command, runner = self.make_nix_execution(Path(directory))
                    fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
                    pending = managed_build._nix_pending_completion_path(fence)
                    recovery = managed_build._nix_recovery_fence_path(fence)
                    success_path = managed_build._managed_nix_success_receipt_path(command)
                    real_unlink, real_sync = Path.unlink, managed_build._fsync_directory
                    retired = False
                    durable_success = False
                    triggered = False

                    def fail():
                        nonlocal triggered
                        triggered = True
                        raise error("journal retirement interrupted")

                    def unlink(path, *args, **kwargs):
                        nonlocal retired
                        if path == pending:
                            self.assertTrue(durable_success)
                            self.assertFalse(fence.exists() or recovery.exists())
                            if boundary == "unlink-before":
                                fail()
                            real_unlink(path, *args, **kwargs)
                            retired = True
                            if boundary == "unlink-after":
                                fail()
                            return
                        return real_unlink(path, *args, **kwargs)

                    def sync(path):
                        nonlocal durable_success
                        if retired and path == pending.parent and boundary == "fsync-before":
                            fail()
                        real_sync(path)
                        if path == success_path.parent and success_path.exists():
                            durable_success = True
                        if retired and path == pending.parent and boundary == "fsync-after":
                            fail()

                    with (
                        patch.object(managed_build, "_nix_volume_exists", return_value=False),
                        patch.object(Path, "unlink", new=unlink),
                        patch.object(managed_build, "_fsync_directory", side_effect=sync),
                        patch.object(managed_build, "_invalidate_nix_success_receipts") as invalidate,
                    ):
                        if error is PowerLoss:
                            with self.assertRaises(PowerLoss):
                                managed_build.execute_plan(self.policy, plan, command, home=home, runner=runner)
                        else:
                            self.assertEqual(managed_build.execute_plan(self.policy, plan, command, home=home, runner=runner), 0)
                        invalidate.assert_not_called()
                    self.assertTrue(triggered)
                    success = json.loads(success_path.read_bytes())
                    self.assertTrue(success["lifecycle_fence_cleared"])
                    self.assertEqual(success["status"], "success")
                    self.assertFalse(fence.exists() or recovery.exists())
                    if pending.exists():
                        self.assertEqual(json.loads(pending.read_bytes())["success_receipt_sha256"], managed_build._sha256_json(success))

    def test_nix_fencing_is_rechecked_after_flock_acquisition(self) -> None:
        for kind in ("recovery", "pending"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home, plan, command, _runner = self.make_nix_execution(Path(directory))
                fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
                marker = (managed_build._nix_recovery_fence_path(fence) if kind == "recovery"
                          else managed_build._nix_pending_completion_path(fence))
                real_flock = managed_build.fcntl.flock
                captured = []

                def flock(fd, operation):
                    real_flock(fd, operation)
                    if operation & managed_build.fcntl.LOCK_EX:
                        captured.append(fd)
                        managed_build._atomic_create_json(marker, {"predecessor": "incomplete"})

                worker = Mock()
                with (
                    patch.object(managed_build, "_nix_volume_exists", return_value=False),
                    patch.object(managed_build.fcntl, "flock", side_effect=flock),
                    self.assertRaisesRegex(managed_build.ManagedBuildError, "fence requires reconciliation"),
                ):
                    managed_build.execute_plan(self.policy, plan, command, home=home, runner=worker)
                worker.assert_not_called()
                self.assertFalse(fence.exists())
                self.assertTrue(marker.exists())
                with self.assertRaises(OSError):
                    os.fstat(captured[0])

    def test_nix_directory_ancestry_is_durable_before_worker_and_journal_retirement(self) -> None:
        for stage in ("initial-fence", "success"):
            # Fail successive ancestor barriers, including an ancestor whose
            # mkdir was performed earlier by another part of this same run.
            for index in range(2 if stage == "success" else 3):
                with self.subTest(stage=stage, index=index), tempfile.TemporaryDirectory() as directory:
                    home, plan, command, runner = self.make_nix_execution(Path(directory))
                    fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
                    pending = managed_build._nix_pending_completion_path(fence)
                    success = managed_build._managed_nix_success_receipt_path(command)
                    watched = fence.parent if stage == "initial-fence" else success.parent
                    real_ancestors, real_sync = managed_build._fsync_directory_ancestors, managed_build._fsync_directory
                    active = False
                    synced = []
                    worker = Mock(side_effect=runner)

                    def ancestors(path):
                        nonlocal active
                        active = path == watched
                        try:
                            return real_ancestors(path)
                        finally:
                            active = False

                    def sync(path):
                        if active:
                            synced.append(path)
                            if len(synced) == index + 1:
                                raise OSError("ancestor durability failure")
                        return real_sync(path)

                    with (
                        patch.object(managed_build, "_nix_volume_exists", return_value=False),
                        patch.object(managed_build, "_fsync_directory_ancestors", side_effect=ancestors),
                        patch.object(managed_build, "_fsync_directory", side_effect=sync),
                        self.assertRaisesRegex(OSError, "ancestor durability failure"),
                    ):
                        managed_build.execute_plan(self.policy, plan, command, home=home, runner=worker)
                    self.assertEqual(synced, list(watched.parents)[:index + 1])
                    self.assertFalse(success.exists())
                    if stage == "initial-fence":
                        worker.assert_not_called()
                    else:
                        worker.assert_called_once()
                        self.assertTrue(pending.exists())
                        self.assertFalse(fence.exists() or managed_build._nix_recovery_fence_path(fence).exists())

    def test_nix_recovery_retirement_failure_prevents_success_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, plan, command, runner = self.make_nix_execution(Path(directory))
            fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
            recovery = managed_build._nix_recovery_fence_path(fence)
            real_unlink = Path.unlink

            def unlink(path, *args, **kwargs):
                if path == recovery:
                    self.assertFalse(fence.exists())
                    raise OSError("recovery anchor retirement failed")
                return real_unlink(path, *args, **kwargs)

            with (
                patch.object(managed_build, "_nix_volume_exists", return_value=False),
                patch.object(Path, "unlink", new=unlink),
                self.assertRaisesRegex(OSError, "recovery anchor retirement failed"),
            ):
                managed_build.execute_plan(self.policy, plan, command, home=home, runner=runner)
            self.assertTrue(recovery.exists())
            self.assertTrue(managed_build._nix_pending_completion_path(fence).exists())
            self.assertFalse(managed_build._managed_nix_success_receipt_path(command).exists())

    def test_nix_failed_build_restores_fence_if_clear_directory_fsync_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, plan, command, _runner = self.make_nix_execution(Path(directory))
            fence = Path(plan["nix_guard"]["lifecycle_fence_path"])
            real_fsync = managed_build._fsync_directory
            triggered = False

            def fsync(path):
                nonlocal triggered
                if path == fence.parent and not fence.exists() and not triggered:
                    triggered = True
                    raise OSError("fence clear fsync failed")
                return real_fsync(path)

            with (
                patch.object(managed_build, "_nix_volume_exists", return_value=False),
                patch.object(managed_build, "_fsync_directory", side_effect=fsync),
                self.assertRaises(OSError),
            ):
                managed_build.execute_plan(
                    self.policy, plan, command, home=home,
                    runner=Mock(return_value=subprocess.CompletedProcess(command, 1)),
                )
            self.assertTrue(triggered)
            self.assertEqual(json.loads(fence.read_text())["kind"], "heim_pc.managed_nix_active_fence")
            self.assertFalse(managed_build._managed_nix_success_receipt_path(command).exists())

    def test_repository_policy_loads(self) -> None:
        self.assertEqual(self.policy["schema_version"], 1)
        self.assertEqual(
            set(self.policy["tools"]),
            {"cargo", "node", "python", "nix", "playwright"},
        )
        self.assertFalse(self.policy["automatic_cleanup_authorized"])

    def test_policy_rejects_automatic_cleanup_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            data = json.loads(self.policy_path.read_text(encoding="utf-8"))
            data["automatic_cleanup_authorized"] = True
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(managed_build.PolicyError, "must remain false"):
                managed_build.load_policy(path)

    def test_policy_rejects_duplicate_executable_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            data = json.loads(self.policy_path.read_text(encoding="utf-8"))
            data["tools"]["playwright"]["executables"].append("node")
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(managed_build.PolicyError, "duplicate executable"):
                managed_build.load_policy(path)

    def test_repository_identity_is_shared_by_linked_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self.make_git_repo(root)
            linked = root / "linked"
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "linked-fixture",
                    str(linked),
                    "HEAD",
                ],
                check=True,
            )

            primary = managed_build.repository_facts(repo)
            secondary = managed_build.repository_facts(linked)

            self.assertEqual(
                primary["repository_identity_sha256"],
                secondary["repository_identity_sha256"],
            )
            self.assertEqual(primary["git_common_dir"], secondary["git_common_dir"])
            self.assertNotIn("secret-token", json.dumps(primary))

    def test_cargo_plan_is_external_and_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            (repo / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            environment_before = os.environ.copy()

            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                first = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                )
                second = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                )

            cargo_target = Path(first["environment"]["CARGO_TARGET_DIR"])
            self.assertEqual(first["profile"], "test")
            self.assertEqual(first["cache_key"], second["cache_key"])
            self.assertNotEqual(first["generated_at"], "")
            self.assertTrue(cargo_target.is_relative_to(home))
            self.assertFalse(cargo_target.is_relative_to(repo))
            self.assertFalse(cargo_target.exists())
            self.assertEqual(os.environ, environment_before)

    def test_lockfile_or_profile_change_changes_cache_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            lockfile = repo / "Cargo.lock"
            lockfile.write_text("version = 3\n", encoding="utf-8")
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                dev = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "check"],
                    home=home,
                )
                release = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "check", "--release"],
                    home=home,
                )
                lockfile.write_text("version = 4\n", encoding="utf-8")
                changed = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "check"],
                    home=home,
                )

            self.assertNotEqual(dev["cache_key"], release["cache_key"])
            self.assertNotEqual(dev["cache_key"], changed["cache_key"])

    def test_environment_resolver_reuses_identity_without_scanning_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            (repo / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            environment_before = os.environ.copy()

            with (
                patch.object(managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()),
                patch.object(managed_build, "scan_worktree_payloads") as scan,
            ):
                resolved = managed_build.resolve_environment(
                    self.policy,
                    repo=repo,
                    command=["cargo"],
                    home=home,
                    explicit_tool="cargo",
                    explicit_profile="test",
                )
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                planned = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                )

            scan.assert_not_called()
            self.assertEqual(resolved["kind"], "heim_pc.managed_build_environment")
            self.assertEqual(resolved["cache_key"], planned["cache_key"])
            self.assertEqual(resolved["environment"], planned["environment"])
            self.assertEqual(resolved["profile"], "test")
            self.assertFalse(Path(resolved["cache_path"]).exists())
            self.assertEqual(os.environ, environment_before)

    def test_prepare_environment_creates_only_secure_external_cache_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            (repo / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                prepared = managed_build.prepare_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="operator-task",
                )

            target = Path(prepared["environment"]["CARGO_TARGET_DIR"])
            self.assertEqual(prepared["kind"], "heim_pc.managed_build_environment_prepared")
            self.assertTrue(target.is_dir())
            self.assertTrue(target.is_relative_to(home / ".cache/heim-pc/managed-builds/cargo"))
            self.assertFalse(target.is_relative_to(repo))
            self.assertIn(str(target), prepared["prepared_paths"])
            binding_path = Path(prepared["binding_receipt"]["path"])
            self.assertTrue(binding_path.is_file())
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            self.assertEqual(binding["kind"], "heim_pc.managed_build_binding_receipt")
            self.assertEqual(binding["tool"], "cargo")
            self.assertEqual(binding["cache_key"], prepared["cache_key"])
            self.assertEqual(binding["cache_path"], prepared["cache_path"])
            lifecycle_lock = Path(prepared["lifecycle_lock_path"])
            self.assertEqual(binding["lifecycle_lock_path"], str(lifecycle_lock))
            self.assertEqual(lifecycle_lock.name, f"{prepared['cache_key']}.lock")
            self.assertIn(str(lifecycle_lock.parent), prepared["prepared_paths"])
            self.assertEqual(
                binding["repository_identity_sha256"],
                prepared["repository_identity_sha256"],
            )
            self.assertNotIn("command", binding)

    def test_prepare_environment_rejects_symlinked_cache_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            (repo / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()
            (home / ".cache").symlink_to(outside, target_is_directory=True)
            with (
                patch.object(managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()),
                self.assertRaisesRegex(managed_build.ManagedBuildError, "not a real directory"),
            ):
                managed_build.prepare_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="operator-task",
                )

    def test_environment_resolver_separates_lockfile_toolchain_and_profile_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            lockfile = repo / "Cargo.lock"
            lockfile.write_text("version = 3\n", encoding="utf-8")
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                first = managed_build.resolve_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="operator-task",
                )
                other_profile = managed_build.resolve_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="release",
                )
                lockfile.write_text("version = 4\n", encoding="utf-8")
                other_lock = managed_build.resolve_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="operator-task",
                )
            with patch.object(
                managed_build, "_toolchain_digest",
                return_value={"observations": {"fixture": "2"}, "sha256": "b" * 64},
            ):
                other_toolchain = managed_build.resolve_environment(
                    self.policy, repo=repo, command=["cargo"], home=home,
                    explicit_tool="cargo", explicit_profile="operator-task",
                )

            self.assertNotEqual(first["cache_key"], other_profile["cache_key"])
            self.assertNotEqual(first["cache_key"], other_lock["cache_key"])
            self.assertNotEqual(other_lock["cache_key"], other_toolchain["cache_key"])

    def test_node_python_and_playwright_are_explicitly_classified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                node = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["npm", "test"],
                    home=home,
                )
                python = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["python3", "-m", "pytest"],
                    home=home,
                )
                playwright = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["npx", "playwright", "test"],
                    home=home,
                )

            self.assertEqual(node["tool"], "node")
            self.assertIn("NPM_CONFIG_CACHE", node["environment"])
            self.assertEqual(python["tool"], "python")
            self.assertIn("UV_CACHE_DIR", python["environment"])
            self.assertEqual(playwright["tool"], "playwright")
            self.assertIn("PLAYWRIGHT_BROWSERS_PATH", playwright["environment"])
            self.assertIn("PNPM_STORE_DIR", playwright["environment"])

    def test_nix_prepare_worker_has_real_nix_guard_and_identity_bound_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            for relative, content in (
                ("flake.lock", "{}\n"),
                ("nixos/production/contract-v1.json", "{}\n"),
                ("scripts/nixos_production_install.py", "# fixture\n"),
                ("scripts/nixos_production_prepare.py", "# fixture\n"),
            ):
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "nix fixture"], check=True)
            output = root / "artifact.json"
            command = [
                sys.executable, str(self.trusted_nix_prepare_path()),
                "--managed-worker", "--repo", str(repo),
                "--output", str(output), "--source-authority", "proof-only",
            ]
            with patch.object(managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()):
                plan = managed_build.build_plan(
                    self.policy, repo=repo, command=command, home=home,
                    explicit_tool="nix", explicit_profile="nixos-production-prepare",
                )
            guard = plan["nix_guard"]
            revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            self.assertEqual(plan["tool"], "nix")
            self.assertEqual(guard["source_revision"], revision)
            self.assertEqual(guard["docker_volume"], f"heim-pc-nixos-production-{revision[:12]}")
            self.assertEqual(guard["lock_mode"], "flock-exclusive-nonblocking")
            self.assertEqual(guard["store_budget_bytes"], self.policy["nix_store_budget_bytes"])
            self.assertEqual(guard["runtime_budget_seconds"], self.policy["nix_runtime_budget_seconds"])
            self.assertTrue(Path(guard["store_root"]).is_relative_to(home / ".cache/heim-pc/managed-builds/nix"))

    def test_nix_managed_receipt_binds_exact_artifact_closure_and_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            for relative, content in (
                ("flake.lock", "{}\n"),
                ("nixos/production/contract-v1.json", "{}\n"),
                ("scripts/nixos_production_install.py", "# fixture\n"),
                ("scripts/nixos_production_prepare.py", "# fixture\n"),
            ):
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "nix fixture"], check=True)
            output = root / "artifact.json"
            command = [
                sys.executable, str(self.trusted_nix_prepare_path()),
                "--managed-worker", "--repo", str(repo),
                "--output", str(output), "--source-authority", "proof-only",
            ]
            with patch.object(managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()):
                plan = managed_build.build_plan(
                    self.policy, repo=repo, command=command, home=home,
                    explicit_tool="nix", explicit_profile="nixos-production-prepare",
                )
            guard = plan["nix_guard"]
            closure = "/nix/store/" + "0" * 32 + "-nixos-system-heim-pc-test"
            def runner(argv, **kwargs):
                self.assertEqual(kwargs["env"]["HEIM_PC_NIXOS_PRODUCTION_PREPARE_MANAGED"], "1")
                store = Path(kwargs["env"]["HEIM_PC_MANAGED_NIX_STORE_ROOT"])
                (store / "payload").write_bytes(b"store")
                output.write_text(json.dumps({
                    "source_revision": guard["source_revision"],
                    "nix_volume": guard["docker_volume"],
                    "system_path": closure,
                    "closure_manifest_sha256": "a" * 64,
                    "closure_path_count": 1,
                }) + "\n", encoding="utf-8")
                return subprocess.CompletedProcess(argv, 0)
            with patch.object(managed_build, "_nix_volume_exists", return_value=False):
                rc = managed_build.execute_plan(self.policy, plan, command, home=home, runner=runner)
            self.assertEqual(rc, 0)
            receipts = list((home / ".local/state/heim-pc/managed-builds/receipts").glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
            nix = receipt["nix_build"]
            self.assertEqual(nix["source_revision"], guard["source_revision"])
            self.assertEqual(nix["docker_volume"], guard["docker_volume"])
            self.assertEqual(nix["system_closure"], closure)
            self.assertEqual(nix["closure_manifest_sha256"], "a" * 64)
            self.assertGreaterEqual(nix["store_allocated_bytes_after"], 5)
            self.assertFalse(nix["store_budget_stop_triggered"])
            self.assertFalse(nix["runtime_timeout_triggered"])
            self.assertTrue(nix["container_cleanup_verified"])
            self.assertEqual(nix["lock_mode"], "flock-exclusive-nonblocking")
            success_path = Path(str(output) + managed_build.NIX_RECEIPT_SUFFIX)
            success = json.loads(success_path.read_text(encoding="utf-8"))
            self.assertEqual(success["kind"], "heim_pc.nixos_managed_build_success_receipt")
            self.assertEqual(success["artifact_json_sha256"], managed_build._sha256_json(json.loads(output.read_text())))
            self.assertEqual(success["artifact_file_sha256"], managed_build._sha256_file(output))
            self.assertTrue(success["container_cleanup_verified"])
            self.assertTrue(success["lifecycle_fence_cleared"])
            self.assertFalse(Path(guard["lifecycle_fence_path"]).exists())

    def test_nix_production_reuses_bounded_final_store_scan_without_second_sync_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            for relative, content in (
                ("flake.lock", "{}\n"),
                ("nixos/production/contract-v1.json", "{}\n"),
                ("scripts/nixos_production_install.py", "# fixture\n"),
                ("scripts/nixos_production_prepare.py", "# fixture\n"),
            ):
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "nix fixture"], check=True)
            output = root / "artifact.json"
            command = [
                sys.executable, str(self.trusted_nix_prepare_path()),
                "--managed-worker", "--repo", str(repo),
                "--output", str(output), "--source-authority", "proof-only",
            ]
            with patch.object(managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()):
                plan = managed_build.build_plan(
                    self.policy, repo=repo, command=command, home=home,
                    explicit_tool="nix", explicit_profile="nixos-production-prepare",
                )
            guard = plan["nix_guard"]
            store_root = Path(guard["store_root"])
            final_scan = {"allocated_bytes": 9, "error_count": 0, "entries": []}
            store_scan_calls = 0

            def scan(path, payloads):
                nonlocal store_scan_calls
                if Path(path) == store_root:
                    store_scan_calls += 1
                    if store_scan_calls > 1:
                        raise AssertionError("production performed a second synchronous Nix store scan")
                    return {"allocated_bytes": 1, "error_count": 0, "entries": []}
                return {"allocated_bytes": 0, "error_count": 0, "entries": []}

            def guarded(argv, *, root, environment, guard):
                closure = "/nix/store/" + "0" * 32 + "-nixos-system-heim-pc-test"
                output.write_text(json.dumps({
                    "source_revision": guard["source_revision"],
                    "nix_volume": guard["docker_volume"],
                    "system_path": closure,
                    "closure_manifest_sha256": "a" * 64,
                    "closure_path_count": 1,
                }) + "\n", encoding="utf-8")
                return subprocess.CompletedProcess(list(argv), 0), {
                    "container_label_sha256": "0" * 64,
                    "container_orphan_detected": False,
                    "container_count_force_removed": 0,
                    "container_cleanup_verified": True,
                    "store_stop_threshold_bytes": int(guard["store_stop_threshold_bytes"]),
                    "store_hard_limit_bytes": int(guard["store_budget_bytes"]["hard"]),
                    "store_max_observed_bytes": final_scan["allocated_bytes"],
                    "store_budget_stop_triggered": False,
                    "store_scan_error_detected": False,
                    "store_scan_timeout_detected": False,
                    "store_final_scan": final_scan,
                    "runtime_timeout_triggered": False,
                }

            with (
                patch.object(managed_build, "scan_worktree_payloads", side_effect=scan),
                patch.object(managed_build, "_run_nix_worker_guarded", side_effect=guarded),
                patch.object(managed_build, "_nix_volume_exists", return_value=False),
            ):
                rc = managed_build.execute_plan(self.policy, plan, command, home=home)

            self.assertEqual(rc, 0)
            self.assertEqual(store_scan_calls, 1)
            receipts = list((home / ".local/state/heim-pc/managed-builds/receipts").glob("*.json"))
            self.assertEqual(len(receipts), 1)
            nix = json.loads(receipts[0].read_text(encoding="utf-8"))["nix_build"]
            self.assertEqual(nix["store_allocated_bytes_after"], 9)
            self.assertEqual(nix["store_scan_error_count_after"], 0)

    def test_nix_store_hard_budget_blocks_before_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            for relative, content in (
                ("flake.lock", "{}\n"),
                ("nixos/production/contract-v1.json", "{}\n"),
                ("scripts/nixos_production_install.py", "# fixture\n"),
                ("scripts/nixos_production_prepare.py", "# fixture\n"),
            ):
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "nix fixture"], check=True)
            output = root / "artifact.json"
            command = [
                sys.executable, str(self.trusted_nix_prepare_path()),
                "--managed-worker", "--repo", str(repo),
                "--output", str(output), "--source-authority", "proof-only",
            ]
            policy = json.loads(json.dumps(self.policy))
            policy["nix_store_budget_bytes"] = {"warning": 1, "hard": 2}
            with patch.object(managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()):
                resolved = managed_build.resolve_environment(
                    policy, repo=repo, command=command, home=home,
                    explicit_tool="nix", explicit_profile="nixos-production-prepare",
                )
                store = Path(resolved["environment"]["HEIM_PC_MANAGED_NIX_STORE_ROOT"])
                store.mkdir(parents=True)
                (store / "full").write_bytes(b"xx")
                plan = managed_build.build_plan(
                    policy, repo=repo, command=command, home=home,
                    explicit_tool="nix", explicit_profile="nixos-production-prepare",
                )
            self.assertTrue(plan["guard"]["blocked"])
            runner = Mock()
            with self.assertRaisesRegex(managed_build.ManagedBuildError, "hard budget"):
                managed_build.execute_plan(policy, plan, command, home=home, runner=runner)
            runner.assert_not_called()

    def test_terminate_process_group_kills_surviving_group_after_leader_exit(self) -> None:
        class Process:
            pid = 4141

            def poll(self):
                return 0

        process = Process()
        with (
            patch.object(managed_build, '_process_group_exists', return_value=True),
            patch.object(
                managed_build, '_wait_for_process_group_exit', side_effect=[False, True]
            ) as wait_for_group,
            patch.object(managed_build.os, 'killpg') as killpg,
        ):
            managed_build._terminate_process_group(process)

        self.assertEqual(
            killpg.call_args_list,
            [call(process.pid, signal.SIGTERM), call(process.pid, signal.SIGKILL)],
        )
        self.assertEqual(wait_for_group.call_count, 2)

    def test_terminate_process_group_fails_closed_if_group_survives_sigkill(self) -> None:
        class Process:
            pid = 4142

            def poll(self):
                return 0

        process = Process()
        with (
            patch.object(managed_build, '_process_group_exists', return_value=True),
            patch.object(
                managed_build, '_wait_for_process_group_exit', side_effect=[False, False]
            ),
            patch.object(managed_build.os, 'killpg') as killpg,
        ):
            with self.assertRaisesRegex(
                managed_build.ManagedBuildError, 'process group cleanup could not be verified'
            ):
                managed_build._terminate_process_group(process)

        self.assertEqual(
            killpg.call_args_list,
            [call(process.pid, signal.SIGTERM), call(process.pid, signal.SIGKILL)],
        )

    def test_nix_normal_leader_exit_still_quiesces_surviving_process_group(self) -> None:
        class Process:
            pid = 4199
            returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        process = Process()
        guard = {
            "source_revision": "e" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "e" * 12,
            "store_root": "/tmp/managed-nix-store-normal-exit-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 10, "hard": 20},
        }
        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 0, "entries": []},
            ),
            patch.object(
                managed_build, "_bounded_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 0, "entries": []},
            ),
            patch.object(managed_build, "_process_group_exists", return_value=True),
            patch.object(managed_build, "_wait_for_process_group_exit", return_value=True) as wait_for_group,
            patch.object(managed_build.os, "killpg") as killpg,
            patch.object(managed_build, "_nix_container_ids", return_value=[]),
            patch.object(managed_build, "_remove_exact_nix_containers", return_value=(0, True)),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )

        self.assertEqual(result.returncode, 0)
        self.assertTrue(telemetry["container_cleanup_verified"])
        killpg.assert_called_once_with(process.pid, signal.SIGTERM)
        wait_for_group.assert_called_once()

    def test_nix_live_store_scan_uses_root_observer_but_final_scan_is_strict(self) -> None:
        class Process:
            pid = 4198
            returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        process = Process()
        guard = {
            "source_revision": "9" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "9" * 12,
            "store_root": "/tmp/managed-nix-store-live-scan-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 10, "hard": 20},
        }
        final_scan_modes = []

        def final_scan(_store_root, *, timeout_seconds, tolerate_vanished_entries=False):
            final_scan_modes.append(tolerate_vanished_entries)
            return {"allocated_bytes": 1, "error_count": 0, "entries": []}

        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 0, "entries": []},
            ) as live_scan,
            patch.object(managed_build, "_bounded_store_scan", side_effect=final_scan),
            patch.object(managed_build, "_terminate_process_group"),
            patch.object(managed_build, "_remove_exact_nix_containers", return_value=(0, True)),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )

        self.assertEqual(result.returncode, 0)
        live_scan.assert_called_once()
        self.assertEqual(live_scan.call_args.args, ("d" * 64,))
        self.assertRegex(live_scan.call_args.kwargs["label"], managed_build.NIX_LIVE_SCAN_LABEL_RE)
        self.assertGreater(live_scan.call_args.kwargs["timeout_seconds"], 0)
        self.assertLessEqual(
            live_scan.call_args.kwargs["timeout_seconds"],
            managed_build.NIX_STORE_FINAL_SCAN_TIMEOUT_SECONDS,
        )
        self.assertEqual(final_scan_modes, [False])
        self.assertFalse(telemetry["store_scan_error_detected"])

    def test_live_store_scanner_image_pin_matches_production_installer(self) -> None:
        from scripts import nixos_production_install as installer

        self.assertEqual(managed_build.PINNED_NIX_IMAGE, installer.PINNED_NIX_IMAGE)

    def test_live_store_monitor_interval_is_two_seconds(self) -> None:
        self.assertEqual(managed_build.NIX_STORE_MONITOR_INTERVAL_SECONDS, 2.0)

    def test_live_store_find_parser_is_incremental_and_deduplicates_hardlinks(self) -> None:
        observation = managed_build._parse_live_store_find_output(
            [b"1 10 ", b"2\n1 11 3\n1 ", b"10 2\n"]
        )
        self.assertEqual(
            observation,
            {"allocated_bytes": 5 * 512, "error_count": 0, "entries": []},
        )
        # A single bytes object remains a supported internal convenience and must
        # not be iterated as integers.
        self.assertEqual(
            managed_build._parse_live_store_find_output(b"1 12 4\n")["allocated_bytes"],
            4 * 512,
        )

    def test_live_store_find_parser_fails_closed_on_bad_rows_and_bounds(self) -> None:
        bad_cases = [
            ([b"not three fields\n"], "malformed"),
            ([b"1 2 \xff\n"], "malformed"),
            ([b"1 2 3"], "partial terminal row"),
            ([], "no filesystem rows"),
        ]
        for chunks, message in bad_cases:
            with self.subTest(chunks=chunks, message=message):
                with self.assertRaisesRegex(managed_build.ManagedBuildError, message):
                    managed_build._parse_live_store_find_output(chunks)
        with patch.object(managed_build, "NIX_LIVE_SCAN_MAX_ROW_BYTES", 4):
            with self.assertRaisesRegex(managed_build.ManagedBuildError, "row bound"):
                managed_build._parse_live_store_find_output([b"1 2 3\n"])
        with patch.object(managed_build, "NIX_LIVE_SCAN_MAX_OUTPUT_BYTES", 5):
            with self.assertRaisesRegex(managed_build.ManagedBuildError, "output bound"):
                managed_build._parse_live_store_find_output([b"1 2 3\n"])

    def test_bounded_live_store_scan_uses_reused_observer_exec(self) -> None:
        observer_id = "d" * 64
        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        process = Mock()
        expected = {
            "allocated_bytes": 5 * 512,
            "error_count": 0,
            "entries": [],
            "stderr_bytes": 7,
        }
        with (
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "Popen", return_value=process) as popen,
            patch.object(
                managed_build, "_capture_live_store_scan_output", return_value=expected
            ) as capture,
        ):
            observation = managed_build._bounded_live_store_scan(
                observer_id, label=label, timeout_seconds=3
            )

        self.assertEqual(observation, expected)
        argv = popen.call_args.args[0]
        self.assertEqual(
            argv,
            [
                "/usr/bin/docker", "exec", "-e", "LC_ALL=C", "-e", "LANG=C",
                observer_id, managed_build.NIX_LIVE_SCAN_FIND, "/subject", "-xdev",
                "-ignore_readdir_race", "-printf", "%D %i %b\n",
            ],
        )
        self.assertNotIn("run", argv)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.PIPE)
        capture.assert_called_once_with(process, label=label, timeout_seconds=3)

    def test_bounded_live_store_scan_propagates_capture_failure_and_timeout(self) -> None:
        observer_id = "d" * 64
        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        for failure in (
            managed_build.ManagedBuildError("scanner failed"),
            managed_build.StoreScanTimeout("synthetic timeout"),
        ):
            with self.subTest(failure=type(failure).__name__):
                with (
                    patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
                    patch.object(managed_build.subprocess, "Popen", return_value=Mock()),
                    patch.object(
                        managed_build, "_capture_live_store_scan_output", side_effect=failure
                    ),
                ):
                    with self.assertRaises(type(failure)):
                        managed_build._bounded_live_store_scan(
                            observer_id, label=label, timeout_seconds=0.01
                        )

    def test_start_live_store_observer_uses_pinned_hardened_container_once(self) -> None:
        container_id = "d" * 64
        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        completed = subprocess.CompletedProcess(
            ["docker"], 0, stdout=(container_id + "\n").encode("ascii"), stderr=b""
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", return_value=completed) as run,
            patch.object(
                managed_build, "_live_store_scan_container_ids", return_value=[container_id]
            ) as inventory,
        ):
            result = managed_build._start_live_store_scan_observer(
                Path(directory), label=label, worker_timeout_seconds=20
            )
            root = directory

        self.assertEqual(result, container_id)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/docker", "run", "-d", "--rm"])
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--security-opt") + 1], "no-new-privileges")
        self.assertEqual(argv[argv.index("--user") + 1], "0:0")
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertEqual(argv[argv.index("--cap-add") + 1], "DAC_READ_SEARCH")
        self.assertEqual(argv[argv.index("--label") + 1], label)
        self.assertEqual(argv[argv.index("-v") + 1], f"{root}:/subject:ro")
        self.assertEqual(argv[argv.index("--entrypoint") + 1], managed_build.NIX_LIVE_SCAN_SLEEP)
        self.assertIn(managed_build.PINNED_NIX_IMAGE, argv)
        self.assertGreater(int(argv[-1]), 20 + managed_build.NIX_LIVE_SCAN_OBSERVER_MARGIN_SECONDS)
        inventory.assert_called_once_with(label)

    def test_start_live_store_observer_rejects_unsafe_root_and_inventory_mismatch(self) -> None:
        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "bind-safe"):
            managed_build._start_live_store_scan_observer(
                Path("/tmp/store:unsafe"), label=label, worker_timeout_seconds=20
            )
        completed = subprocess.CompletedProcess(
            ["docker"], 0, stdout=("d" * 64 + "\n").encode("ascii"), stderr=b""
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", return_value=completed),
            patch.object(managed_build, "_live_store_scan_container_ids", return_value=[]),
        ):
            with self.assertRaisesRegex(managed_build.ManagedBuildError, "inventory"):
                managed_build._start_live_store_scan_observer(
                    Path(directory), label=label, worker_timeout_seconds=20
                )

    def test_live_store_scan_capture_accepts_bounded_stderr_on_success(self) -> None:
        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        process = subprocess.Popen(
            [
                sys.executable, "-c",
                "import sys; sys.stdout.write('1 10 2\\n'); sys.stderr.write('docker warning\\n')",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        observation = managed_build._capture_live_store_scan_output(
            process, label=label, timeout_seconds=3
        )
        self.assertEqual(observation["allocated_bytes"], 2 * 512)
        self.assertEqual(observation["stderr_bytes"], len(b"docker warning\n"))
        self.assertIsNotNone(process.poll())

    def test_live_store_scan_capture_nonzero_exit_fails_and_cleans_observer(self) -> None:
        label = "heim-pc.managed-nix-scan=" + "e" * 64 + "-" + "f" * 12
        process = subprocess.Popen(
            [
                sys.executable, "-c",
                "import sys; sys.stdout.write('1 10 2\\n'); "
                "sys.stderr.write(\"find: '/subject/private': Not a directory\\n\"); "
                "raise SystemExit(3)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with patch.object(
            managed_build, "_cleanup_live_store_scan_container", return_value=True
        ) as cleanup:
            with self.assertRaisesRegex(managed_build.ManagedBuildError, "scan failed") as caught:
                managed_build._capture_live_store_scan_output(
                    process, label=label, timeout_seconds=3
                )
        message = str(caught.exception)
        self.assertIn("exit=3", message)
        self.assertIn("stderr_classes=not-a-directory", message)
        self.assertIn("observer_cleanup_verified=true", message)
        self.assertNotIn("/subject/private", message)
        self.assertNotIn("stderr_bytes=", message)
        self.assertNotIn("stderr_sha256=", message)
        cleanup.assert_called_once_with(label)
        self.assertIsNotNone(process.poll())

    def test_live_store_scan_failure_detail_classifies_suffix_without_disclosing_paths(self) -> None:
        private_path = b"/subject/nix/store/Permission denied"
        stderr = (
            b"find: '" + private_path + b"': Not a directory\n"
            b"find: '/subject/child': Permission denied\n"
        )
        detail = managed_build._live_store_scan_failure_detail(1, stderr)
        self.assertEqual(
            detail, "exit=1 stderr_classes=not-a-directory,permission-denied"
        )
        self.assertNotIn(private_path.decode(), detail)
        self.assertNotIn("find:", detail)
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "requires a nonzero"):
            managed_build._live_store_scan_failure_detail(0, stderr)

    def test_live_store_scan_failure_detail_has_bounded_known_vocabulary(self) -> None:
        stderr = b"find: /subject/private: No such file or directory\n"
        detail = managed_build._live_store_scan_failure_detail(1, stderr)
        self.assertEqual(detail, "exit=1 stderr_classes=not-found")
        self.assertNotIn("/subject/private", detail)

    def test_live_store_scan_failure_preserves_safe_detail_when_observer_cleanup_fails(self) -> None:
        label = "heim-pc.managed-nix-scan=" + "e" * 64 + "-" + "f" * 12
        process = subprocess.Popen(
            [
                sys.executable, "-c",
                "import sys; sys.stdout.write('1 10 2\\n'); "
                "sys.stderr.write(\"find: '/subject/private': Not a directory\\n\"); "
                "raise SystemExit(3)",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        with patch.object(
            managed_build, "_cleanup_live_store_scan_container", return_value=False
        ):
            with self.assertRaises(managed_build.LiveStoreScanFailure) as caught:
                managed_build._capture_live_store_scan_output(
                    process, label=label, timeout_seconds=3
                )
        message = str(caught.exception)
        self.assertIn("exit=3 stderr_classes=not-a-directory", message)
        self.assertIn("observer_cleanup_verified=false", message)
        self.assertNotIn("/subject/private", message)

    def test_live_store_scan_capture_enforces_stdout_and_stderr_bounds(self) -> None:
        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        cases = [
            ("import sys,time; sys.stdout.buffer.write(b'x'*4096); sys.stdout.flush(); time.sleep(10)",
             "NIX_LIVE_SCAN_MAX_OUTPUT_BYTES", 32, "output bound"),
            ("import sys,time; sys.stdout.write('1 2 3\\n'); sys.stdout.flush(); sys.stderr.buffer.write(b'x'*4096); sys.stderr.flush(); time.sleep(10)",
             "NIX_LIVE_SCAN_MAX_STDERR_BYTES", 32, "stderr bound"),
        ]
        for program, constant, bound, message in cases:
            with self.subTest(message=message):
                process = subprocess.Popen(
                    [sys.executable, "-c", program],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                with (
                    patch.object(managed_build, constant, bound),
                    patch.object(
                        managed_build, "_cleanup_live_store_scan_container", return_value=True
                    ) as cleanup,
                ):
                    with self.assertRaisesRegex(managed_build.ManagedBuildError, message):
                        managed_build._capture_live_store_scan_output(
                            process, label=label, timeout_seconds=3
                        )
                cleanup.assert_called_once_with(label)
                self.assertIsNotNone(process.poll())

    def test_live_store_scan_capture_timeout_requires_verified_cleanup(self) -> None:
        label = "heim-pc.managed-nix-scan=" + "c" * 64 + "-" + "d" * 12
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with patch.object(
            managed_build, "_cleanup_live_store_scan_container", return_value=True
        ) as cleanup:
            with self.assertRaises(managed_build.StoreScanTimeout):
                managed_build._capture_live_store_scan_output(
                    process, label=label, timeout_seconds=0.02
                )
        cleanup.assert_called_once_with(label)
        self.assertIsNotNone(process.poll())

    def test_live_store_scan_capture_baseexception_closes_pipes_and_quiesces_observer(self) -> None:
        class PowerLoss(BaseException):
            pass

        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        interruption = PowerLoss("capture interrupted")
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        stdout = os.fdopen(stdout_read, "rb")
        stderr = os.fdopen(stderr_read, "rb")
        process = Mock(pid=5152, returncode=None, stdout=stdout, stderr=stderr)
        process.poll.return_value = None
        selector = Mock()
        selector.register.return_value = None
        selector.get_map.return_value = {
            stdout.fileno(): Mock(fileobj=stdout),
            stderr.fileno(): Mock(fileobj=stderr),
        }
        selector.select.side_effect = interruption

        try:
            with (
                patch.object(managed_build.selectors, "DefaultSelector", return_value=selector),
                patch.object(managed_build, "_quiesce_live_store_scan_observer") as quiesce,
            ):
                with self.assertRaises(PowerLoss) as caught:
                    managed_build._capture_live_store_scan_output(
                        process, label=label, timeout_seconds=3
                    )

            self.assertIs(caught.exception, interruption)
            quiesce.assert_called_once_with(process, label)
            self.assertTrue(stdout.closed)
            self.assertTrue(stderr.closed)
            selector.close.assert_called_once()
        finally:
            stdout.close()
            stderr.close()
            os.close(stdout_write)
            os.close(stderr_write)

    def test_live_store_scan_cleanup_requires_repeated_absence(self) -> None:
        with (
            patch.object(
                managed_build, "_live_store_scan_container_ids", side_effect=[[], []]
            ) as inventory,
            patch.object(managed_build.time, "sleep") as sleep,
        ):
            self.assertTrue(
                managed_build._cleanup_live_store_scan_container(
                    "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
                )
            )
        self.assertEqual(inventory.call_count, 2)
        sleep.assert_called_once_with(0.1)

    def test_live_store_scan_cleanup_rejects_ambiguous_nonzero_remove(self) -> None:
        container_id = "d" * 64
        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        result = subprocess.CompletedProcess(
            ["docker", "rm"], 1, stdout=b"unexpected\n", stderr=b"daemon error\n"
        )
        with (
            patch.object(managed_build, "_live_store_scan_container_ids", return_value=[container_id]),
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(managed_build.subprocess, "run", return_value=result),
        ):
            with self.assertRaisesRegex(managed_build.ManagedBuildError, "ambiguous"):
                managed_build._cleanup_live_store_scan_container(label)

    def test_live_store_scan_cleanup_timeout_needs_repeated_absence(self) -> None:
        container_id = "d" * 64
        label = "heim-pc.managed-nix-scan=" + "a" * 64 + "-" + "b" * 12
        with (
            patch.object(
                managed_build, "_live_store_scan_container_ids",
                side_effect=[[container_id], [], []],
            ) as inventory,
            patch.object(managed_build, "_docker_executable", return_value="/usr/bin/docker"),
            patch.object(
                managed_build.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(["docker", "rm"], 5),
            ),
            patch.object(managed_build.time, "sleep"),
        ):
            self.assertTrue(managed_build._cleanup_live_store_scan_container(label))
        self.assertEqual(inventory.call_count, 3)

    def test_nix_observer_startup_failure_cleans_before_worker_start(self) -> None:
        guard = {
            "source_revision": "8" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "8" * 12,
            "store_root": "/tmp/managed-nix-store-observer-startup-failure-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 10, "hard": 20},
        }
        startup_error = managed_build.ManagedBuildError("observer startup inventory mismatch")
        with (
            patch.object(managed_build, "_start_live_store_scan_observer", side_effect=startup_error),
            patch.object(managed_build.subprocess, "Popen") as worker_start,
            patch.object(
                managed_build, "_remove_exact_nix_containers", return_value=(0, True)
            ) as build_cleanup,
            patch.object(
                managed_build, "_cleanup_live_store_scan_container", return_value=True
            ) as observer_cleanup,
        ):
            with self.assertRaises(managed_build.ManagedBuildError) as caught:
                managed_build._run_nix_worker_guarded(
                    ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
                )

        self.assertIs(caught.exception, startup_error)
        worker_start.assert_not_called()
        build_cleanup.assert_called_once()
        build_label = build_cleanup.call_args.args[0]
        build_cleanup.assert_called_once_with(build_label)
        self.assertRegex(build_label, managed_build.NIX_CONTAINER_LABEL_RE)
        observer_cleanup.assert_called_once()
        observer_label = observer_cleanup.call_args.args[0]
        observer_cleanup.assert_called_once_with(observer_label)
        self.assertRegex(observer_label, managed_build.NIX_LIVE_SCAN_LABEL_RE)
        self.assertEqual(build_label.rsplit("-", 1)[1], observer_label.rsplit("-", 1)[1])

    def test_nix_worker_reuses_one_observer_for_multiple_samples(self) -> None:
        class Process:
            pid = 5151
            returncode = None

            def __init__(self):
                self.poll_count = 0

            def poll(self):
                self.poll_count += 1
                if self.poll_count >= 2:
                    self.returncode = 0
                return self.returncode

            def wait(self, timeout=None):
                self.returncode = 0
                return 0

        process = Process()
        guard = {
            "source_revision": "8" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "8" * 12,
            "store_root": "/tmp/managed-nix-store-observer-reuse-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 10, "hard": 20},
        }
        observer_id = "d" * 64
        samples = [
            {"allocated_bytes": 1, "error_count": 0, "entries": [], "stderr_bytes": 3},
            {"allocated_bytes": 2, "error_count": 0, "entries": [], "stderr_bytes": 7},
        ]
        with (
            patch.object(
                managed_build, "_start_live_store_scan_observer", return_value=observer_id
            ) as start_observer,
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan", side_effect=samples
            ) as live_scan,
            patch.object(
                managed_build, "_bounded_store_scan",
                return_value={"allocated_bytes": 2, "error_count": 0, "entries": []},
            ),
            patch.object(managed_build, "_terminate_process_group"),
            patch.object(managed_build, "_remove_exact_nix_containers", return_value=(0, True)),
            patch.object(
                managed_build, "_cleanup_live_store_scan_container", return_value=True
            ) as observer_cleanup,
            patch.object(managed_build.time, "sleep") as sleep,
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )

        self.assertEqual(result.returncode, 0)
        start_observer.assert_called_once()
        self.assertEqual(live_scan.call_count, 2)
        self.assertEqual([item.args[0] for item in live_scan.call_args_list], [observer_id, observer_id])
        labels = [item.kwargs["label"] for item in live_scan.call_args_list]
        self.assertEqual(labels[0], labels[1])
        sleep.assert_called_once_with(2.0)
        observer_cleanup.assert_called_once_with(labels[0])
        self.assertEqual(telemetry["store_scan_max_stderr_bytes"], 7)
        self.assertTrue(telemetry["observer_cleanup_verified"])

    def test_bounded_store_scan_toleration_is_an_explicit_internal_helper_flag(self) -> None:
        completed = subprocess.CompletedProcess(
            ["scan"],
            0,
            stdout=b'{"allocated_bytes":1,"entries":[],"error_count":0}',
            stderr=b"",
        )
        with patch.object(managed_build.subprocess, "run", return_value=completed) as run:
            observation = managed_build._bounded_store_scan(
                Path("/tmp/store"),
                timeout_seconds=1,
                tolerate_vanished_entries=True,
            )

        self.assertEqual(observation["error_count"], 0)
        self.assertEqual(
            run.call_args.args[0][-1],
            managed_build.INTERNAL_NIX_STORE_SCAN_TOLERATE_VANISHED,
        )
        self.assertEqual(
            managed_build._internal_nix_store_scan_main(
                [managed_build.INTERNAL_NIX_STORE_SCAN_OPERATION, "/tmp/store", "--unexpected"]
            ),
            2,
        )

    def test_nix_verified_auto_remove_race_does_not_become_orphan_failure(self) -> None:
        class Process:
            pid = 4200
            returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        process = Process()
        guard = {
            "source_revision": "1" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "1" * 12,
            "store_root": "/tmp/managed-nix-store-auto-remove-race-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 10, "hard": 20},
        }
        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 0, "entries": []},
            ),
            patch.object(
                managed_build, "_bounded_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 0, "entries": []},
            ),
            patch.object(managed_build, "_terminate_process_group"),
            patch.object(managed_build, "_remove_exact_nix_containers", return_value=(0, True)),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )

        self.assertEqual(result.returncode, 0)
        self.assertFalse(telemetry["container_orphan_detected"])
        self.assertEqual(telemetry["container_count_force_removed"], 0)
        self.assertTrue(telemetry["container_cleanup_verified"])

    def test_nix_successful_force_remove_is_telemetry_not_orphan_failure(self) -> None:
        class Process:
            pid = 4201
            returncode = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        process = Process()
        guard = {
            "source_revision": "2" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "2" * 12,
            "store_root": "/tmp/managed-nix-store-force-remove-race-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 10, "hard": 20},
        }
        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 0, "entries": []},
            ),
            patch.object(
                managed_build, "_bounded_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 0, "entries": []},
            ),
            patch.object(managed_build, "_terminate_process_group"),
            patch.object(managed_build, "_remove_exact_nix_containers", return_value=(1, True)),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )

        self.assertEqual(result.returncode, 0)
        self.assertFalse(telemetry["container_orphan_detected"])
        self.assertEqual(telemetry["container_count_force_removed"], 1)
        self.assertTrue(telemetry["container_cleanup_verified"])

    def test_nix_running_store_monitor_terminates_before_hard_and_cleans_container(self) -> None:
        class Process:
            pid = 4242
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.returncode is None:
                    self.returncode = -15
                return self.returncode

        process = Process()
        events = []
        guard = {
            "source_revision": "a" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "a" * 12,
            "store_root": "/tmp/managed-nix-store-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 10, "hard": 20},
        }

        def terminate(item):
            events.append("terminate-process-group")
            item.returncode = -15

        def remove(label):
            events.append("remove-exact-container")
            return 1, True

        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan",
                return_value={"allocated_bytes": 70, "error_count": 0, "entries": []},
            ),
            patch.object(
                managed_build, "_bounded_store_scan",
                return_value={"allocated_bytes": 70, "error_count": 0, "entries": []},
            ),
            patch.object(managed_build, "_terminate_process_group", side_effect=terminate),
            patch.object(managed_build, "_nix_container_ids", return_value=["a" * 64]),
            patch.object(managed_build, "_remove_exact_nix_containers", side_effect=remove),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )
        self.assertEqual(result.returncode, 75)
        self.assertTrue(telemetry["store_budget_stop_triggered"])
        self.assertTrue(telemetry["container_cleanup_verified"])
        self.assertLess(guard["store_stop_threshold_bytes"], guard["store_budget_bytes"]["hard"])
        self.assertEqual(events, ["terminate-process-group", "remove-exact-container"])

    def test_nix_runtime_timeout_terminates_worker_then_container(self) -> None:
        class Process:
            pid = 4343
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.returncode is None:
                    self.returncode = -15
                return self.returncode

        process = Process()
        events = []
        guard = {
            "source_revision": "b" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "b" * 12,
            "store_root": "/tmp/managed-nix-store-timeout-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 1, "hard": 1},
        }

        def terminate(item):
            events.append("terminate-process-group")
            item.returncode = -15

        def remove(label):
            events.append("remove-exact-container")
            return 0, True

        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 0, "entries": []},
            ),
            patch.object(managed_build.time, "monotonic", side_effect=[0.0, 2.0]),
            patch.object(managed_build, "_terminate_process_group", side_effect=terminate),
            patch.object(managed_build, "_nix_container_ids", return_value=[]),
            patch.object(managed_build, "_remove_exact_nix_containers", side_effect=remove),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )
        self.assertEqual(result.returncode, 124)
        self.assertTrue(telemetry["runtime_timeout_triggered"])
        self.assertTrue(telemetry["container_cleanup_verified"])
        self.assertEqual(events, ["terminate-process-group", "remove-exact-container"])

    def test_nix_runtime_timeout_dominates_final_store_scan_timeout(self) -> None:
        class Process:
            pid = 4344
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.returncode is None:
                    self.returncode = -15
                return self.returncode

        process = Process()
        events = []
        guard = {
            "source_revision": "c" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "c" * 12,
            "store_root": "/tmp/managed-nix-store-runtime-final-scan-timeout-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 1, "hard": 1},
        }

        def terminate(item):
            events.append("terminate-process-group")
            item.returncode = -15

        def remove(label):
            events.append("remove-exact-container")
            return 0, True

        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_store_scan",
                side_effect=managed_build.StoreScanTimeout("synthetic final scan timeout"),
            ),
            patch.object(managed_build.time, "monotonic", side_effect=[0.0, 2.0]),
            patch.object(managed_build, "_terminate_process_group", side_effect=terminate),
            patch.object(managed_build, "_nix_container_ids", return_value=[]),
            patch.object(managed_build, "_remove_exact_nix_containers", side_effect=remove),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )
        self.assertEqual(result.returncode, 124)
        self.assertTrue(telemetry["runtime_timeout_triggered"])
        self.assertTrue(telemetry["store_scan_timeout_detected"])
        self.assertIsNone(telemetry["store_final_scan"])
        self.assertTrue(telemetry["container_cleanup_verified"])
        self.assertEqual(events, ["terminate-process-group", "remove-exact-container"])

    def test_nix_store_scan_error_stops_worker_and_retains_error_telemetry(self) -> None:
        class Process:
            pid = 4393
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.returncode is None:
                    self.returncode = -15
                return self.returncode

        process = Process()
        events = []
        guard = {
            "source_revision": "d" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "d" * 12,
            "store_root": "/tmp/managed-nix-store-scan-error-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 10, "hard": 20},
        }

        def terminate(item):
            events.append("terminate-process-group")
            item.returncode = -15

        def remove(label):
            events.append("remove-exact-container")
            return 0, True

        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 1, "entries": []},
            ),
            patch.object(
                managed_build, "_bounded_store_scan",
                return_value={"allocated_bytes": 1, "error_count": 1, "entries": []},
            ),
            patch.object(managed_build, "_terminate_process_group", side_effect=terminate),
            patch.object(managed_build, "_nix_container_ids", return_value=[]),
            patch.object(managed_build, "_remove_exact_nix_containers", side_effect=remove),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded(
                ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
            )

        self.assertEqual(result.returncode, 77)
        self.assertTrue(telemetry["store_scan_error_detected"])
        self.assertTrue(telemetry["container_cleanup_verified"])
        self.assertEqual(events, ["terminate-process-group", "remove-exact-container"])

    def test_nix_live_scan_failure_preserves_safe_detail_if_outer_cleanup_fails(self) -> None:
        class Process:
            pid = 4433
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.returncode is None:
                    self.returncode = -15
                return self.returncode

        process = Process()
        guard = {
            "source_revision": "e" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "e" * 12,
            "store_root": "/tmp/managed-nix-store-live-failure-cleanup-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 1, "hard": 2},
        }

        def terminate(item):
            item.returncode = -15

        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan",
                side_effect=managed_build.LiveStoreScanFailure(
                    "exit=1 stderr_classes=not-a-directory",
                    observer_cleanup_verified=True,
                ),
            ),
            patch.object(managed_build, "_terminate_process_group", side_effect=terminate),
            patch.object(managed_build, "_remove_exact_nix_containers", return_value=(0, False)),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=False),
        ):
            with self.assertRaises(managed_build.LiveStoreScanFailure) as caught:
                managed_build._run_nix_worker_guarded(
                    ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
                )
        message = str(caught.exception)
        self.assertIn("exit=1 stderr_classes=not-a-directory", message)
        self.assertIn("observer_cleanup_verified=true", message)
        self.assertIn("exceptional_cleanup_verified=false", message)
        self.assertNotIn("/subject/", message)

    def test_nix_monitor_exception_still_terminates_worker_and_exact_container(self) -> None:
        class Process:
            pid = 4444
            returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.returncode is None:
                    self.returncode = -15
                return self.returncode

        process = Process()
        events = []
        guard = {
            "source_revision": "c" * 40,
            "docker_volume": "heim-pc-nixos-production-" + "c" * 12,
            "store_root": "/tmp/managed-nix-store-exception-test",
            "store_stop_threshold_bytes": 64,
            "store_budget_bytes": {"warning": 64, "hard": 96},
            "runtime_budget_seconds": {"warning": 1, "hard": 2},
        }

        def terminate(item):
            events.append("terminate-process-group")
            item.returncode = -15

        def remove(label):
            events.append("remove-exact-container")
            return 1, True

        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(
                managed_build, "_bounded_live_store_scan",
                side_effect=RuntimeError("synthetic monitor failure"),
            ),
            patch.object(managed_build, "_terminate_process_group", side_effect=terminate),
            patch.object(managed_build, "_remove_exact_nix_containers", side_effect=remove),
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic monitor failure"):
                managed_build._run_nix_worker_guarded(
                    ["python3", "worker.py"], root=Path("/tmp"), environment={}, guard=guard
                )
        self.assertEqual(events, ["terminate-process-group", "remove-exact-container"])

    def test_bounded_store_scan_timeout_is_fail_closed(self) -> None:
        with patch.object(managed_build.subprocess, "run", side_effect=subprocess.TimeoutExpired(["scan"], 0.01)):
            with self.assertRaises(managed_build.StoreScanTimeout):
                managed_build._bounded_store_scan(Path("/tmp/store"), timeout_seconds=0.01)

    def test_nix_store_scan_timeout_stops_worker_and_exact_container(self) -> None:
        class Process:
            pid = 4499
            returncode = None
            def poll(self): return self.returncode
            def wait(self, timeout=None):
                if self.returncode is None: self.returncode = -15
                return self.returncode
        process = Process(); events = []
        guard = {"source_revision": "f" * 40, "docker_volume": "heim-pc-nixos-production-" + "f" * 12, "store_root": "/tmp/managed-nix-store-scan-timeout-test", "store_stop_threshold_bytes": 64, "store_budget_bytes": {"warning": 64, "hard": 96}, "runtime_budget_seconds": {"warning": 10, "hard": 20}}
        def terminate(item): events.append("terminate-process-group"); item.returncode = -15
        def remove(label): events.append("remove-exact-container"); return 0, True
        with (
            patch.object(managed_build, "_start_live_store_scan_observer", return_value="d" * 64),
            patch.object(managed_build, "_cleanup_live_store_scan_container", return_value=True),
            patch.object(managed_build.subprocess, "Popen", return_value=process),
            patch.object(managed_build, "_bounded_live_store_scan", side_effect=managed_build.StoreScanTimeout("synthetic slow scan")),
            patch.object(managed_build, "_bounded_store_scan", return_value={"allocated_bytes": 1, "error_count": 0, "entries": []}),
            patch.object(managed_build, "_terminate_process_group", side_effect=terminate),
            patch.object(managed_build, "_nix_container_ids", return_value=[]),
            patch.object(managed_build, "_remove_exact_nix_containers", side_effect=remove),
        ):
            result, telemetry = managed_build._run_nix_worker_guarded([sys.executable, "worker.py"], root=Path("/tmp"), environment={}, guard=guard)
        self.assertEqual(result.returncode, 77)
        self.assertTrue(telemetry["store_scan_error_detected"])
        self.assertTrue(telemetry["store_scan_timeout_detected"])
        self.assertEqual(events, ["terminate-process-group", "remove-exact-container"])

    def test_nix_explicit_tool_rejects_arbitrary_python_or_direct_nix(self) -> None:
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "reserved"):
            managed_build.classify_tool(
                self.policy, ["python3", "-c", "print('no')"], explicit_tool="nix"
            )
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "reserved"):
            managed_build.classify_tool(
                self.policy, ["nix", "build"], explicit_tool="nix"
            )
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "unsupported"):
            managed_build.classify_tool(self.policy, ["nix", "build"])

    def test_nix_profile_rejects_same_basename_untrusted_interpreter(self) -> None:
        command = ["/tmp/python3", "/tmp/nixos_production_prepare.py", "--managed-worker", "--repo", "/tmp", "--output", "/tmp/a", "--source-authority", "proof-only"]
        self.assertFalse(managed_build._is_nix_prepare_worker(command))
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "exact current Python"):
            managed_build._require_nix_prepare_worker_binding(command, Path("/tmp"), "nixos-production-prepare")

    def test_nix_profile_allows_separate_source_repo_but_rejects_untrusted_prepare_script(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "historical-source"
            repo.mkdir()
            output = root / "artifact.json"
            trusted_script = Path(managed_build.__file__).resolve().with_name(
                "nixos_production_prepare.py"
            )
            command = [
                sys.executable, str(trusted_script),
                "--managed-worker", "--repo", str(repo),
                "--output", str(output), "--source-authority", "proof-only",
            ]
            managed_build._require_nix_prepare_worker_binding(
                command, repo, "nixos-production-prepare"
            )

            untrusted = list(command)
            untrusted[1] = str(repo / "scripts" / "nixos_production_prepare.py")
            with self.assertRaisesRegex(managed_build.ManagedBuildError, "canonical trusted prepare script"):
                managed_build._require_nix_prepare_worker_binding(
                    untrusted, repo, "nixos-production-prepare"
                )

    def test_nix_profile_rejects_token_smuggled_python_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            script = repo / "scripts/nixos_production_prepare.py"
            script.parent.mkdir(parents=True)
            script.write_text("# fixture\n", encoding="utf-8")
            output = root / "artifact.json"
            command = [
                sys.executable, "-c", "print('payload')", str(script),
                "--managed-worker", "--repo", str(repo),
                "--output", str(output), "--source-authority", "proof-only",
            ]
            self.assertFalse(managed_build._is_nix_prepare_worker(command))
            with self.assertRaisesRegex(managed_build.ManagedBuildError, "exact canonical managed-worker argv"):
                managed_build._require_nix_prepare_worker_binding(
                    command, repo, "nixos-production-prepare"
                )

    def test_real_storage_inventory_scan_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self.make_git_repo(root)
            target = repo / "target"
            target.mkdir()
            (target / "payload.bin").write_bytes(b"payload")

            observation = managed_build.scan_worktree_payloads(repo, ["target"])

            self.assertGreaterEqual(observation["allocated_bytes"], 7)
            self.assertEqual(len(observation["entries"]), 1)
            self.assertEqual(observation["entries"][0]["relative_path"], "target")
            self.assertGreaterEqual(observation["entries"][0]["logical_bytes"], 7)

    def test_nix_toolchain_digest_separates_historical_source_from_trusted_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "historical-source"
            (repo / "nixos/production").mkdir(parents=True)
            (repo / "scripts").mkdir()
            for relative, content in (
                ("flake.nix", "# historical flake\n"),
                ("flake.lock", "{}\n"),
                ("nixos/production/contract-v1.json", "{}\n"),
                ("scripts/managed_build.py", "# historical untrusted tool\n"),
                ("scripts/nixos_production_install.py", "# historical untrusted tool\n"),
                ("scripts/nixos_production_prepare.py", "# historical untrusted tool\n"),
            ):
                (repo / relative).write_text(content, encoding="utf-8")

            with patch.object(managed_build, "_run_readonly", return_value="rc=0\nDocker fixture"):
                digest = managed_build._toolchain_digest("nix", [sys.executable], repo)

            trusted_root = Path(managed_build.__file__).resolve().parents[1]
            self.assertEqual(
                digest["observations"]["nix_source_contract_files"],
                managed_build._files_digest(
                    repo, ["flake.nix", "flake.lock", "nixos/production/contract-v1.json"]
                )["sha256"],
            )
            self.assertEqual(
                digest["observations"]["nix_trusted_tool_files"],
                managed_build._files_digest(
                    trusted_root, [
                        "scripts/managed_build.py",
                        "scripts/nixos_production_install.py",
                        "scripts/nixos_production_prepare.py",
                    ],
                )["sha256"],
            )
            self.assertNotEqual(
                digest["observations"]["nix_trusted_tool_files"],
                managed_build._files_digest(
                    repo, [
                        "scripts/managed_build.py",
                        "scripts/nixos_production_install.py",
                        "scripts/nixos_production_prepare.py",
                    ],
                )["sha256"],
            )

    def test_toolchain_probe_uses_resolved_cargo_and_sibling_rustc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            cargo = bin_dir / "cargo"
            rustc = bin_dir / "rustc"
            for executable in (cargo, rustc):
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o755)
            calls: list[list[str]] = []

            def observe(argv: list[str], *, cwd: Path, timeout_seconds: int = 5) -> str:
                calls.append(argv)
                return "rc=0\nfixture"

            with patch.object(managed_build, "_run_readonly", side_effect=observe):
                digest = managed_build._toolchain_digest(
                    "cargo",
                    [str(cargo), "test"],
                    root,
                )

            self.assertEqual(calls[0], [str(cargo), "--version"])
            self.assertEqual(calls[1], [str(rustc.absolute()), "-Vv"])
            self.assertNotIn("unavailable", json.dumps(digest))

    def test_budget_boundaries_are_inclusive(self) -> None:
        budget = {"warning": 2, "hard": 5}
        self.assertEqual(managed_build._status(1, budget), "ok")
        self.assertEqual(managed_build._status(2, budget), "warning")
        self.assertEqual(managed_build._status(4, budget), "warning")
        self.assertEqual(managed_build._status(5, budget), "hard_limit")

    def test_hard_limit_blocks_without_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            hard = self.policy["managed_worktree_budget_bytes"]["hard"]
            with (
                patch.object(
                    managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
                ),
                patch.object(
                    managed_build,
                    "scan_worktree_payloads",
                    return_value={"allocated_bytes": hard, "entries": []},
                ),
            ):
                plan = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                )

            self.assertTrue(plan["guard"]["blocked"])
            self.assertEqual(plan["guard"]["status"], "blocked")

    def test_explicit_unexpired_pin_allows_hard_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            managed_build.create_pin(
                self.policy,
                repo=repo,
                tool="cargo",
                reason="large one-off verification",
                ttl_hours=1,
                home=home,
                now_epoch=100,
            )
            hard = self.policy["managed_worktree_budget_bytes"]["hard"]
            with (
                patch.object(
                    managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
                ),
                patch.object(
                    managed_build,
                    "scan_worktree_payloads",
                    return_value={"allocated_bytes": hard, "entries": []},
                ),
            ):
                plan = managed_build.build_plan(
                    self.policy,
                    repo=repo,
                    command=["cargo", "test"],
                    home=home,
                    now_epoch=200,
                )

            self.assertFalse(plan["guard"]["blocked"])
            self.assertEqual(plan["guard"]["status"], "hard_limit")
            self.assertEqual(plan["guard"]["pin"]["reason"], "large one-off verification")

    def test_expired_pin_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            result = managed_build.create_pin(
                self.policy,
                repo=repo,
                tool="cargo",
                reason="expired fixture",
                ttl_hours=1,
                home=home,
                now_epoch=100,
            )
            facts = managed_build.repository_facts(repo)

            self.assertIsNone(
                managed_build.read_pin(
                    Path(result["path"]).parents[1],
                    facts["repository_identity_sha256"],
                    "cargo",
                    now_epoch=4000,
                )
            )

    def test_execute_plan_refuses_blocked_plan_before_runner(self) -> None:
        runner = Mock()
        plan = {
            "guard": {"blocked": True},
        }
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "blocked"):
            managed_build.execute_plan(
                self.policy,
                plan,
                ["cargo", "test"],
                home=Path("/tmp"),
                runner=runner,
            )
        runner.assert_not_called()

    def test_execute_plan_sets_child_environment_and_writes_bounded_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            repo = self.make_git_repo(root)
            policy = json.loads(json.dumps(self.policy))
            policy["max_receipts"] = 2
            with patch.object(
                managed_build, "_toolchain_digest", return_value=self.fixed_toolchain()
            ):
                plan = managed_build.build_plan(
                    policy,
                    repo=repo,
                    command=[sys.executable, "--version"],
                    home=home,
                    explicit_tool="python",
                )
            captured: dict[str, object] = {}

            def runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                captured["argv"] = argv
                captured["environment"] = kwargs["env"]
                captured["cwd"] = kwargs["cwd"]
                return subprocess.CompletedProcess(argv, 0)

            returncode = managed_build.execute_plan(
                policy,
                plan,
                [sys.executable, "--version"],
                home=home,
                runner=runner,
            )

            receipts = list((home / ".local/state/heim-pc/managed-builds/receipts").glob("*.json"))
            self.assertEqual(returncode, 0)
            self.assertEqual(captured["cwd"], repo)
            child_environment = captured["environment"]
            self.assertEqual(
                child_environment["PIP_CACHE_DIR"],
                plan["environment"]["PIP_CACHE_DIR"],
            )
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["returncode"], 0)
            self.assertNotIn("argv", receipt["command"])
            self.assertFalse(receipt["automatic_cleanup_authorized"])

    def test_secure_directory_rejects_symlink_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            (home / ".cache").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(managed_build.ManagedBuildError, "not a real directory"):
                managed_build._ensure_secure_directory(
                    home / ".cache/heim-pc/managed-builds",
                    home,
                )

    def test_policy_bound_executable_resolution_uses_home_tool_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            cargo = home / ".cargo/bin/cargo"
            cargo.parent.mkdir(parents=True)
            cargo.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            cargo.chmod(0o755)

            command = managed_build._normalized_command(
                ["cargo", "test"],
                policy=self.policy,
                home=home,
            )

            self.assertEqual(command[0], str(cargo.absolute()))
            self.assertEqual(command[1:], ["test"])

    def test_policy_bound_executable_resolution_rejects_explicit_path(self) -> None:
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "without a path"):
            managed_build._normalized_command(
                ["/tmp/cargo", "test"],
                policy=self.policy,
                home=Path("/tmp"),
            )

    def test_policy_rejects_root_executable_search_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            data = json.loads(self.policy_path.read_text(encoding="utf-8"))
            data["executable_search_paths"] = ["/"]
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(managed_build.PolicyError, "absolute or"):
                managed_build.load_policy(path)

    def test_invalid_explicit_tool_executable_pair_fails_closed(self) -> None:
        with self.assertRaisesRegex(managed_build.ManagedBuildError, "not allowed"):
            managed_build.classify_tool(
                self.policy,
                ["cargo", "test"],
                explicit_tool="python",
            )

    def test_trim_receipts_keeps_newest_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for index in range(4):
                path = root / f"{index}.json"
                path.write_text("{}\n", encoding="utf-8")
                os.utime(path, ns=(index + 1, index + 1))
                paths.append(path)

            managed_build._trim_receipts(root, 2)

            self.assertEqual(
                sorted(path.name for path in root.glob("*.json")),
                ["2.json", "3.json"],
            )


class NixCompletionCrashTests(unittest.TestCase):
    def test_every_completion_syscall_prefix_preserves_the_consumer_invariant(self) -> None:
        """Model unsynced names/content surviving OR reverting, without recovery handlers."""
        from itertools import product
        from scripts import nixos_production_install as installer

        class PowerLoss(BaseException):
            pass

        # Unlike an exception injected into execute_plan, a stop in this helper
        # cannot invoke its receipt-invalidation/primary-restoration handler.
        boundaries = (
            "pending-open", "pending-write", "pending-file-fsync", "pending-close",
            "pending-directory-fsync", "recovery-link", "recovery-directory-fsync",
            "primary-unlink", "primary-directory-fsync", "recovery-unlink",
            "recovery-retirement-fsync", "success-open", "success-partial-write",
            "success-write", "success-file-fsync", "success-close", "success-directory-fsync",
        )
        scenarios = [(None, "after", PowerLoss)] + [
            (boundary, when, error)
            for boundary in boundaries for when in ("before", "after")
            for error in (PowerLoss, OSError)
        ]
        for stop, when, error in scenarios:
            with self.subTest(stop=stop, when=when, error=error.__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fence = root / "state" / "identity.active.json"
                pending = managed_build._nix_pending_completion_path(fence)
                recovery = managed_build._nix_recovery_fence_path(fence)
                artifact_path = root / "output" / "artifact.json"
                artifact_path.parent.mkdir()
                success_path = installer.managed_build_receipt_path(artifact_path)
                revision = "a" * 40
                artifact = {
                    "schema_version": 1, "kind": "heim_pc.nixos_production_install_artifact",
                    "source_revision": revision,
                    "system_path": "/nix/store/" + "0" * 32 + "-nixos-system-heim-pc-test",
                    "nix_volume": "heim-pc-nixos-production-" + revision[:12],
                    "nix_image": installer.PINNED_NIX_IMAGE,
                    "profile": "heim-pc-storage-target", "source_authority": "proof-only",
                    "source_bundle_sha256": "b" * 64,
                    "closure_manifest_sha256": "c" * 64, "closure_path_count": 1,
                }
                artifact_path.write_text(json.dumps(artifact))
                success = {
                    "schema_version": 1, "kind": installer.MANAGED_BUILD_RECEIPT_KIND,
                    "status": "success", "returncode": 0, "tool": "nix",
                    "profile": "nixos-production-prepare", "source_revision": revision,
                    "docker_volume": artifact["nix_volume"],
                    "store_root": "/home/fixture/.cache/heim-pc/managed-builds/nix/" + "1" * 64 + "/nix-store",
                    "system_closure": artifact["system_path"],
                    "closure_manifest_sha256": artifact["closure_manifest_sha256"], "closure_path_count": 1,
                    "managed_plan_sha256": "2" * 64, "managed_policy_sha256": "3" * 64,
                    "managed_receipt_sha256": "4" * 64,
                    "artifact_file_sha256": managed_build._sha256_file(artifact_path),
                    "artifact_json_sha256": managed_build._sha256_json(artifact),
                    "store_stop_threshold_bytes": 100, "store_hard_limit_bytes": 200,
                    "store_max_observed_bytes": 1, "store_budget_stop_triggered": False,
                    "store_scan_error_detected": False, "runtime_timeout_triggered": False,
                    "container_cleanup_verified": True, "lifecycle_fence_cleared": True,
                }
                managed_build._atomic_create_json(fence, {"source_revision": revision})
                paths = (fence, recovery, pending, success_path)
                real_open, real_write, real_close = os.open, os.write, os.close
                real_fsync, real_link, real_unlink = os.fsync, os.link, Path.unlink
                durable_names = {fence: fence.stat().st_ino}
                durable_content = {fence.stat().st_ino: fence.read_bytes()}
                opened = set()
                visited = []
                stopped = False
                partial_written = False

                def accepted(data):
                    if data is None:
                        return False
                    try:
                        installer.validate_managed_build_receipt(
                            json.loads(data), artifact, expected_policy_sha256=success["managed_policy_sha256"],
                            artifact_file_sha256=success["artifact_file_sha256"],
                        )
                    except (ValueError, installer.ProductionInstallError):
                        return False
                    return True

                self.assertTrue(accepted(json.dumps(success).encode()))

                def check_invariant():
                    # Enumerate independent persistence of unsynced directory
                    # entries and inode bytes, including partial canonical JSON.
                    # Never assume state and output share a filesystem or that
                    # close / unlink / write supplies a durability barrier.
                    options = []
                    for path in paths:
                        inodes = {durable_names.get(path)}
                        if path.exists():
                            inodes.add(path.stat().st_ino)
                        else:
                            inodes.add(None)
                        variants = set()
                        for inode in inodes:
                            if inode is None:
                                variants.add(None)
                            else:
                                variants.add(durable_content.get(inode, b""))
                                if path.exists() and path.stat().st_ino == inode:
                                    variants.add(path.read_bytes())
                        options.append(variants)
                    for primary, anchor, journal, canonical in product(*options):
                        if accepted(canonical):
                            self.assertIsNone(primary, "consumer-valid success precedes durable primary retirement")
                            self.assertIsNone(anchor, "consumer-valid success precedes durable recovery retirement")
                        else:
                            self.assertTrue(any(x is not None for x in (primary, anchor, journal)),
                                            "crash loses every fence/journal before authoritative success")
                    if success_path.exists() and accepted(success_path.read_bytes()):
                        loaded = installer.load_managed_build_receipt(
                            success_path, artifact, expected_policy_sha256=success["managed_policy_sha256"],
                            artifact_path=artifact_path,
                        )
                        self.assertEqual(loaded, success)

                def event(label, operation, durable=None):
                    nonlocal stopped
                    if stopped:
                        return operation()
                    check_invariant()
                    if stop == label and when == "before":
                        stopped = True
                        raise error("injected stop before " + label)
                    result = operation()
                    if durable is not None:
                        durable()
                    visited.append(label)
                    check_invariant()
                    if stop == label and when == "after":
                        stopped = True
                        raise error("injected stop after " + label)
                    return result

                def name(path):
                    return "pending" if path == pending else "success"

                def open_file(path, flags, *args, **kwargs):
                    def operation():
                        fd = real_open(path, flags, *args, **kwargs)
                        opened.add(fd)
                        return fd
                    if Path(path) in (pending, success_path):
                        return event(name(Path(path)) + "-open", operation)
                    return operation()

                def write(fd, data):
                    nonlocal partial_written
                    path = Path(os.readlink(f"/proc/self/fd/{fd}"))
                    label = name(path) + "-write"
                    if path == success_path and not partial_written:
                        partial_written = True
                        data = data[:len(data) // 2]
                        label = "success-partial-write"
                    return event(label, lambda: real_write(fd, data))

                def fsync(fd):
                    path = Path(os.readlink(f"/proc/self/fd/{fd}"))
                    if stat.S_ISDIR(os.fstat(fd).st_mode):
                        if path not in (fence.parent, success_path.parent):
                            # Ancestry failures are exercised separately; J must
                            # still exist throughout these publication barriers.
                            self.assertTrue(pending.exists())
                            return real_fsync(fd)
                        if path == success_path.parent:
                            label = "success-directory-fsync"
                        elif fence.exists():
                            label = "recovery-directory-fsync" if recovery.exists() else "pending-directory-fsync"
                        else:
                            label = "primary-directory-fsync" if recovery.exists() else "recovery-retirement-fsync"
                        def durable():
                            for entry in paths:
                                if entry.parent == path:
                                    durable_names.pop(entry, None)
                                    if entry.exists():
                                        durable_names[entry] = entry.stat().st_ino
                    else:
                        label = name(path) + "-file-fsync"
                        def durable():
                            durable_content[os.fstat(fd).st_ino] = path.read_bytes()
                    return event(label, lambda: real_fsync(fd), durable)

                def close(fd):
                    path = Path(os.readlink(f"/proc/self/fd/{fd}"))
                    def operation():
                        real_close(fd)
                        opened.discard(fd)
                    if path in (pending, success_path):
                        return event(name(path) + "-close", operation)
                    return operation()

                def link(source, destination, **kwargs):
                    return event("recovery-link", lambda: real_link(source, destination, **kwargs))

                def unlink(path, *args, **kwargs):
                    return event("primary-unlink" if path == fence else "recovery-unlink",
                                 lambda: real_unlink(path, *args, **kwargs))

                try:
                    with (
                        patch.object(managed_build.os, "open", side_effect=open_file),
                        patch.object(managed_build.os, "write", side_effect=write),
                        patch.object(managed_build.os, "fsync", side_effect=fsync),
                        patch.object(managed_build.os, "close", side_effect=close),
                        patch.object(managed_build.os, "link", side_effect=link),
                        patch.object(Path, "unlink", new=unlink),
                        patch.object(managed_build, "_invalidate_nix_success_receipts") as invalidate,
                    ):
                        if stop is None:
                            managed_build._publish_nix_success(success_path, fence, success)
                        else:
                            with self.assertRaises(error):
                                managed_build._publish_nix_success(success_path, fence, success)
                            self.assertTrue(stopped)
                        invalidate.assert_not_called()
                    check_invariant()
                    if stop is None:
                        self.assertEqual(tuple(visited), boundaries)
                        self.assertTrue(pending.exists())
                        # Consumer acceptance with a superseded journal is
                        # intentional; neither active nor recovery may remain.
                        self.assertTrue(accepted(success_path.read_bytes()))
                        self.assertFalse(fence.exists() or recovery.exists())
                finally:
                    for fd in opened:
                        real_close(fd)


if __name__ == "__main__":
    unittest.main()
