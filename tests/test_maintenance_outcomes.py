from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


outcomes = _load("maintenance_outcomes", "scripts/maintenance_outcomes.py")
installer = _load("install_maintenance_outcomes", "scripts/install_maintenance_outcomes.py")


def _policy(producers: list[dict[str, object]]) -> dict[str, object]:
    normalized = [
        {
            **producer,
            "success_evidence": producer.get(
                "success_evidence", "systemd-service-result"
            ),
        }
        for producer in producers
    ]
    return {
        "schema_version": 1,
        "kind": outcomes.POLICY_KIND,
        "task_id": "TEST-T001",
        "producers": normalized,
    }


class MaintenanceOutcomeTests(unittest.TestCase):
    def test_policy_rejects_duplicate_producer_ids(self) -> None:
        producer = {
            "id": "duplicate",
            "unit": "duplicate.service",
            "timer_unit": "duplicate.timer",
            "max_age_seconds": 600,
            "owner_component": "test",
            "evidence_paths": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(_policy([producer, producer])), encoding="utf-8")
            with self.assertRaisesRegex(outcomes.OutcomeError, "duplicate"):
                outcomes._validate_policy(path)

    def test_policy_rejects_secret_or_unbounded_evidence_paths(self) -> None:
        producer = {
            "id": "unsafe-evidence",
            "unit": "unsafe-evidence.service",
            "timer_unit": None,
            "max_age_seconds": 600,
            "owner_component": "test",
            "evidence_paths": ["$HOME/.ssh/id_ed25519"],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(_policy([producer])), encoding="utf-8")
            with self.assertRaisesRegex(outcomes.OutcomeError, "evidence_paths"):
                outcomes._validate_policy(path)

    def test_policy_rejects_unknown_success_evidence(self) -> None:
        producer = {
            "id": "bad-success",
            "unit": "bad-success.service",
            "timer_unit": None,
            "max_age_seconds": 600,
            "owner_component": "test",
            "success_evidence": "semantic-success",
            "evidence_paths": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(_policy([producer])), encoding="utf-8")
            with self.assertRaisesRegex(outcomes.OutcomeError, "success_evidence"):
                outcomes._validate_policy(path)

    def test_main_emits_compact_artifact_bound_success_receipt(self) -> None:
        artifact = {
            "schema_version": 1,
            "kind": outcomes.ARTIFACT_KIND,
            "generated_at_unix": 2000,
            "artifact_sha256": "a" * 64,
            "summary": {
                "producer_count": 1,
                "status_counts": {
                    "observed": 1,
                    "stale": 0,
                    "failed": 0,
                    "unknown": 0,
                    "not-applicable": 0,
                },
                "attention_count": 0,
                "automatic_repair_authorized": False,
            },
            "producers": [{"id": "noisy", "detail": "x" * 5000}],
        }
        argv = [
            "maintenance_outcomes.py",
            "--policy",
            "/tmp/maintenance-policy.json",
            "--output",
            "/tmp/maintenance-outcomes.json",
        ]
        with (
            mock.patch.object(outcomes, "collect", return_value=artifact),
            mock.patch.object(outcomes.sys, "argv", argv),
            mock.patch("builtins.print") as printer,
        ):
            returncode = outcomes.main()

        self.assertEqual(returncode, 0)
        self.assertEqual(printer.call_count, 1)
        encoded = printer.call_args.args[0]
        payload = json.loads(encoded)
        self.assertEqual(payload["kind"], "heim_pc_maintenance_outcomes_run_receipt")
        self.assertEqual(payload["artifact_sha256"], "a" * 64)
        self.assertEqual(payload["generated_at_unix"], 2000)
        self.assertEqual(payload["summary"], artifact["summary"])
        self.assertNotIn("producers", payload)
        self.assertLess(len(encoded.encode("utf-8")), 1024)

    def test_collect_classifies_success_failure_and_deduplicates_same_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            output_path = root / "state/outcomes.json"
            bureau_root = root / "bureau"
            bureau_root.mkdir()
            policy_path.write_text(
                json.dumps(
                    _policy(
                        [
                            {
                                "id": "healthy",
                                "unit": "healthy.service",
                                "timer_unit": "healthy.timer",
                                "max_age_seconds": 500,
                                "owner_component": "test",
                                "evidence_paths": [],
                            },
                            {
                                "id": "failed",
                                "unit": "failed.service",
                                "timer_unit": "failed.timer",
                                "max_age_seconds": 500,
                                "owner_component": "test",
                                "evidence_paths": [],
                                "bureau_binding": {"candidate_id": "candidate-test"},
                            },
                        ]
                    )
                ),
                encoding="utf-8",
            )
            failed_invocation = {"value": "failed-1"}
            failed_exit = {"value": "failed-exit-1"}

            def fake_show(unit: str, properties):
                if unit.endswith(".timer"):
                    return (
                        {
                            "LoadState": "loaded",
                            "ActiveState": "active",
                            "SubState": "waiting",
                            "UnitFileState": "enabled",
                            "LastTriggerUSec": "timer-last",
                            "NextElapseUSecRealtime": "timer-next",
                            "FragmentPath": f"/units/{unit}",
                        },
                        None,
                    )
                if unit == "healthy.service":
                    return (
                        {
                            "LoadState": "loaded",
                            "ActiveState": "inactive",
                            "SubState": "dead",
                            "Result": "success",
                            "ExecMainCode": "1",
                            "ExecMainStatus": "0",
                            "ExecMainStartTimestamp": "healthy-start",
                            "ExecMainExitTimestamp": "healthy-exit",
                            "InvocationID": "healthy-1",
                            "FragmentPath": "/units/healthy.service",
                            "UnitFileState": "static",
                        },
                        None,
                    )
                return (
                    {
                        "LoadState": "loaded",
                        "ActiveState": "failed",
                        "SubState": "failed",
                        "Result": "exit-code",
                        "ExecMainCode": "1",
                        "ExecMainStatus": "1",
                        "ExecMainStartTimestamp": "failed-start",
                        "ExecMainExitTimestamp": failed_exit["value"],
                        "InvocationID": failed_invocation["value"],
                        "FragmentPath": "/units/failed.service",
                        "UnitFileState": "static",
                    },
                    None,
                )

            timestamps = {
                "healthy-start": 1800,
                "healthy-exit": 1900,
                "failed-start": 1800,
                "failed-exit-1": 1910,
                "failed-exit-2": 1970,
                "timer-last": 1900,
                "timer-next": 2500,
            }

            journal_calls: list[tuple[str, str | None, int | None, int | None]] = []

            def fake_journal(
                unit: str,
                invocation_id: str | None,
                *,
                started_at_unix: int | None,
                terminal_at_unix: int | None,
            ):
                journal_calls.append((unit, invocation_id, started_at_unix, terminal_at_unix))
                if unit == "failed.service":
                    return (
                        [
                            {
                                "message": '{"error":"managed residue is not empty; refusing cleanup: /home/alex/build/12345"}',
                                "invocation_id": invocation_id,
                                "timestamp_unix": 1910,
                            }
                        ],
                        None,
                    )
                return [], None

            with (
                mock.patch.object(outcomes, "_systemd_show", side_effect=fake_show),
                mock.patch.object(outcomes, "_timestamp_to_epoch", side_effect=lambda value: timestamps.get(value)),
                mock.patch.object(outcomes, "_journal_entries", side_effect=fake_journal),
                mock.patch.object(
                    outcomes,
                    "_bureau_status",
                    return_value={
                        "state": "observed",
                        "candidate_id": "candidate-test",
                        "candidate_status": "active",
                        "event_id": 7,
                    },
                ),
            ):
                first = outcomes.collect(
                    policy_path=policy_path,
                    output_path=output_path,
                    bureau_root=bureau_root,
                    home=root,
                    now_unix=2000,
                )
                second = outcomes.collect(
                    policy_path=policy_path,
                    output_path=output_path,
                    bureau_root=bureau_root,
                    home=root,
                    now_unix=2010,
                )
                failed_invocation["value"] = "failed-2"
                failed_exit["value"] = "failed-exit-2"
                third = outcomes.collect(
                    policy_path=policy_path,
                    output_path=output_path,
                    bureau_root=bureau_root,
                    home=root,
                    now_unix=2020,
                )

            first_by_id = {item["id"]: item for item in first["producers"]}
            second_by_id = {item["id"]: item for item in second["producers"]}
            third_by_id = {item["id"]: item for item in third["producers"]}
            self.assertEqual(first_by_id["healthy"]["status"], "observed")
            self.assertEqual(first_by_id["healthy"]["failure_messages"], [])
            self.assertEqual(first_by_id["failed"]["status"], "failed")
            self.assertEqual(first_by_id["failed"]["consecutive_failures"], 1)
            self.assertEqual(second_by_id["failed"]["consecutive_failures"], 1)
            self.assertEqual(third_by_id["failed"]["consecutive_failures"], 2)
            self.assertEqual(
                first_by_id["failed"]["failure_fingerprint"],
                third_by_id["failed"]["failure_fingerprint"],
            )
            self.assertIn("$HOME", first_by_id["failed"]["failure_messages"][0])
            self.assertEqual(first_by_id["failed"]["bureau"]["candidate_status"], "active")
            self.assertFalse(first["summary"]["automatic_repair_authorized"])
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)
            self.assertEqual(len(journal_calls), 3)
            self.assertTrue(all(call[0] == "failed.service" for call in journal_calls))
            self.assertEqual(journal_calls[0][2:], (1800, 1910))

    def test_journal_entries_are_failure_filtered_and_run_bounded(self) -> None:
        entry = {
            "MESSAGE": '{"error":"managed residue is not empty"}',
            "_SYSTEMD_INVOCATION_ID": "run-1",
            "__REALTIME_TIMESTAMP": "1910000000",
        }
        completed = mock.Mock(returncode=0, stdout=json.dumps(entry) + "\n", stderr="")
        with mock.patch.object(outcomes, "_run", return_value=completed) as run:
            entries, error = outcomes._journal_entries(
                "failed.service",
                "run-1",
                started_at_unix=1800,
                terminal_at_unix=1910,
            )
        self.assertIsNone(error)
        self.assertEqual(entries[0]["message"], '{"error":"managed residue is not empty"}')
        argv = run.call_args.args[0]
        self.assertIn("--grep", argv)
        self.assertIn("--case-sensitive=no", argv)
        self.assertEqual(argv[argv.index("--since") + 1], "@1799")
        self.assertEqual(argv[argv.index("--until") + 1], "@1911")

    def test_failure_messages_prioritize_structured_error_fragments(self) -> None:
        messages, normalized = outcomes._failure_messages(
            [
                {"message": '      "error": "managed build residue is not empty; refusing cleanup: /home/alex/build",', "invocation_id": "run-1", "timestamp_unix": 1},
                {"message": '  "prune_failed": 0,', "invocation_id": "run-1", "timestamp_unix": 1},
                {"message": "service: Failed with result exit-code", "invocation_id": "run-1", "timestamp_unix": 1},
            ]
        )
        self.assertIn("managed build residue", messages[0])
        self.assertIn("$HOME", messages[0])
        self.assertEqual(len(messages), len(normalized))

    def test_stale_success_and_evidence_hash_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / ".local/state/heim-pc/test/evidence.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text('{"ok":true}\n', encoding="utf-8")
            unsafe = evidence.parent / "unsafe"
            unsafe.symlink_to(evidence)
            policy_path = root / "policy.json"
            output_path = root / "out.json"
            policy_path.write_text(
                json.dumps(
                    _policy(
                        [
                            {
                                "id": "stale",
                                "unit": "stale.service",
                                "timer_unit": None,
                                "max_age_seconds": 60,
                                "owner_component": "test",
                                "evidence_paths": [
                                    "$HOME/.local/state/heim-pc/test/evidence.json",
                                    "$HOME/.local/state/heim-pc/test/unsafe",
                                ],
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )
            properties = {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "SubState": "dead",
                "Result": "success",
                "ExecMainCode": "1",
                "ExecMainStatus": "0",
                "ExecMainStartTimestamp": "start",
                "ExecMainExitTimestamp": "exit",
                "InvocationID": "stale-1",
                "FragmentPath": "/units/stale.service",
                "UnitFileState": "static",
            }
            with (
                mock.patch.object(outcomes, "_systemd_show", return_value=(properties, None)),
                mock.patch.object(outcomes, "_timestamp_to_epoch", side_effect=lambda value: {"start": 1, "exit": 100}.get(value)),
                mock.patch.object(outcomes, "_journal_entries", return_value=([], None)),
            ):
                result = outcomes.collect(
                    policy_path=policy_path,
                    output_path=output_path,
                    bureau_root=root,
                    home=root,
                    now_unix=200,
                )
            producer = result["producers"][0]
            self.assertEqual(producer["status"], "stale")
            self.assertTrue(producer["slo"]["breached"])
            self.assertEqual(producer["evidence"][0]["state"], "observed")
            self.assertEqual(producer["evidence"][1]["state"], "unsafe-or-non-regular")

    def test_evidence_rejects_foreign_owned_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / ".local/state/heim-pc/test/evidence.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text('{"ok":true}\n', encoding="utf-8")
            metadata = list(evidence.stat())
            metadata[4] = os.getuid() + 1
            foreign = os.stat_result(metadata)

            with mock.patch.object(outcomes.os, "fstat", return_value=foreign):
                result = outcomes._evidence_status(
                    ["$HOME/.local/state/heim-pc/test/evidence.json"],
                    home=root,
                )

            self.assertEqual(result[0]["state"], "foreign-owner")
            self.assertEqual(result[0]["owner_uid"], os.getuid() + 1)
            self.assertNotIn("sha256", result[0])

    def test_bureau_binding_uses_exact_candidate_assessment(self) -> None:
        payload = {
            "result": {
                "status": "assessed",
                "candidate_id": "candidate-1",
                "candidate_status": "active",
                "event_id": 42,
                "decision": "merge",
            }
        }
        completed = mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
        with mock.patch.object(outcomes, "_run", return_value=completed) as run:
            result = outcomes._bureau_status(
                {"candidate_id": "candidate-1", "task_id": "TASK-T001"},
                bureau_root=Path("/tmp/bureau"),
            )
        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["event_id"], 42)
        argv = run.call_args.args[0]
        self.assertIn("operator-candidate-assess", argv)
        self.assertNotIn("live-list", argv)
        self.assertEqual(argv[-2:], ["--task-id", "TASK-T001"])


    def test_bureau_binding_rejects_unbound_assessment_identity(self) -> None:
        payload = {
            "result": {
                "status": "assessed",
                "candidate_id": "candidate-other",
                "candidate_status": "active",
                "event_id": 42,
            }
        }
        completed = mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
        with mock.patch.object(outcomes, "_run", return_value=completed):
            result = outcomes._bureau_status(
                {"candidate_id": "candidate-1"}, bureau_root=Path("/tmp/bureau")
            )
        self.assertEqual(result["state"], "unknown")
        self.assertIn("identity-bound", result["error"])

    def test_previous_artifact_digest_mismatch_blocks_state_reuse(self) -> None:
        previous = {
            "schema_version": 1,
            "kind": outcomes.ARTIFACT_KIND,
            "producers": [],
            "artifact_sha256": "0" * 64,
        }
        with self.assertRaisesRegex(outcomes.OutcomeError, "digest does not match"):
            outcomes._previous_map(previous)

    def test_corrupt_previous_artifact_blocks_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            output_path = root / "state/outcomes.json"
            output_path.parent.mkdir()
            output_path.write_text("{broken", encoding="utf-8")
            policy_path.write_text(
                json.dumps(
                    _policy(
                        [
                            {
                                "id": "healthy",
                                "unit": "healthy.service",
                                "timer_unit": None,
                                "max_age_seconds": 600,
                                "owner_component": "test",
                                "evidence_paths": [],
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(outcomes.OutcomeError, "cannot read JSON"):
                outcomes.collect(
                    policy_path=policy_path,
                    output_path=output_path,
                    bureau_root=root,
                    home=root,
                    now_unix=2000,
                )
            self.assertEqual(output_path.read_text(encoding="utf-8"), "{broken")

    def test_missing_declared_evidence_requires_review_attention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            output_path = root / "out.json"
            policy_path.write_text(
                json.dumps(
                    _policy(
                        [
                            {
                                "id": "missing-evidence",
                                "unit": "missing-evidence.service",
                                "timer_unit": None,
                                "max_age_seconds": 600,
                                "owner_component": "test",
                                "evidence_paths": [
                                    "$HOME/.local/state/heim-pc/test/missing.json"
                                ],
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )
            properties = {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "SubState": "dead",
                "Result": "success",
                "ExecMainCode": "1",
                "ExecMainStatus": "0",
                "ExecMainStartTimestamp": "start",
                "ExecMainExitTimestamp": "exit",
                "InvocationID": "run-1",
                "FragmentPath": "/units/missing-evidence.service",
                "UnitFileState": "static",
            }
            with (
                mock.patch.object(outcomes, "_systemd_show", return_value=(properties, None)),
                mock.patch.object(
                    outcomes,
                    "_timestamp_to_epoch",
                    side_effect=lambda value: {"start": 1800, "exit": 1900}.get(value),
                ),
            ):
                result = outcomes.collect(
                    policy_path=policy_path,
                    output_path=output_path,
                    bureau_root=root,
                    home=root,
                    now_unix=2000,
                )
            producer = result["producers"][0]
            self.assertEqual(producer["status"], "observed")
            self.assertEqual(producer["success_evidence"], "systemd-service-result")
            self.assertEqual(producer["evidence"][0]["state"], "missing")
            self.assertEqual(producer["attention"]["state"], "review")
            self.assertEqual(producer["attention"]["reason"], "evidence-unavailable")

    def test_inactive_declared_timer_requires_attention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            output_path = root / "out.json"
            policy_path.write_text(
                json.dumps(
                    _policy(
                        [
                            {
                                "id": "timer-off",
                                "unit": "timer-off.service",
                                "timer_unit": "timer-off.timer",
                                "max_age_seconds": 600,
                                "owner_component": "test",
                                "evidence_paths": [],
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )

            def fake_show(unit: str, properties):
                if unit.endswith(".timer"):
                    return (
                        {
                            "LoadState": "loaded",
                            "ActiveState": "inactive",
                            "SubState": "dead",
                            "UnitFileState": "disabled",
                            "LastTriggerUSec": "exit",
                            "NextElapseUSecRealtime": "",
                            "FragmentPath": "/units/timer-off.timer",
                        },
                        None,
                    )
                return (
                    {
                        "LoadState": "loaded",
                        "ActiveState": "inactive",
                        "SubState": "dead",
                        "Result": "success",
                        "ExecMainCode": "1",
                        "ExecMainStatus": "0",
                        "ExecMainStartTimestamp": "start",
                        "ExecMainExitTimestamp": "exit",
                        "InvocationID": "run-1",
                        "FragmentPath": "/units/timer-off.service",
                        "UnitFileState": "static",
                    },
                    None,
                )

            with (
                mock.patch.object(outcomes, "_systemd_show", side_effect=fake_show),
                mock.patch.object(
                    outcomes,
                    "_timestamp_to_epoch",
                    side_effect=lambda value: {"start": 1800, "exit": 1900}.get(value),
                ),
            ):
                result = outcomes.collect(
                    policy_path=policy_path,
                    output_path=output_path,
                    bureau_root=root,
                    home=root,
                    now_unix=2000,
                )
            producer = result["producers"][0]
            self.assertEqual(producer["status"], "observed")
            self.assertEqual(producer["timer"]["health"], "not-ready")
            self.assertEqual(producer["attention"]["state"], "required")
            self.assertEqual(producer["attention"]["reason"], "timer-not-active")



class MaintenanceOutcomeInstallerTests(unittest.TestCase):
    def _blob(self, relative_path: str) -> bytes:
        return (ROOT / relative_path).read_bytes()

    def test_install_plan_is_commit_bound_and_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            release_root = Path(directory) / "releases"
            with (
                mock.patch.object(installer, "_repository_identity", return_value=("a" * 40, False)),
                mock.patch.object(
                    installer,
                    "_repository_blob",
                    side_effect=lambda root, head, relative_path: self._blob(relative_path),
                ),
            ):
                receipt = installer.install(
                    home=home,
                    release_root=release_root,
                    apply=False,
                    enable=False,
                    start=False,
                    expected_head="a" * 40,
                )
            self.assertFalse(receipt["apply"])
            self.assertEqual(receipt["repository_head"], "a" * 40)
            self.assertFalse(home.exists())
            self.assertEqual(len(receipt["planned"]), 4)

    def test_install_apply_renders_release_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            release_root = base / "releases"

            def fake_run(argv, *, cwd=None):
                if "--property=LoadState" in argv:
                    return mock.Mock(returncode=0, stdout="loaded\n", stderr="")
                if "--property=Result" in argv:
                    return mock.Mock(returncode=0, stdout="success\n", stderr="")
                return mock.Mock(returncode=0, stdout="", stderr="")

            patches = (
                mock.patch.object(installer, "_repository_identity", return_value=("b" * 40, False)),
                mock.patch.object(
                    installer,
                    "_repository_blob",
                    side_effect=lambda root, head, relative_path: self._blob(relative_path),
                ),
                mock.patch.object(installer, "_verify_units", return_value={"status": "verified", "returncode": 0}),
                mock.patch.object(installer, "_run", side_effect=fake_run),
            )
            with patches[0], patches[1], patches[2], patches[3]:
                first = installer.install(
                    home=home,
                    release_root=release_root,
                    apply=True,
                    enable=True,
                    start=True,
                    expected_head="b" * 40,
                )
                second = installer.install(
                    home=home,
                    release_root=release_root,
                    apply=True,
                    enable=False,
                    start=False,
                    expected_head="b" * 40,
                )

            service = home / ".config/systemd/user/heim-pc-maintenance-outcomes.service"
            script = release_root / ("b" * 40) / "scripts/maintenance_outcomes.py"
            policy = release_root / ("b" * 40) / "config/maintenance-producers.v1.json"
            self.assertTrue(service.is_file())
            self.assertTrue(script.is_file())
            self.assertTrue(policy.is_file())
            self.assertNotIn("@RELEASE_ROOT@", service.read_text(encoding="utf-8"))
            self.assertIn(str(release_root / ("b" * 40)), service.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(policy.stat().st_mode), 0o600)
            self.assertTrue(all(item["action"] == "unchanged" for item in second["installed"]))
            self.assertIn("timer-enabled+service-started", first["systemd"])

    def test_dirty_repository_blocks_commit_bound_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(installer, "_repository_identity", return_value=("c" * 40, True)):
                with self.assertRaisesRegex(installer.InstallError, "clean"):
                    installer.install(
                        home=Path(directory) / "home",
                        release_root=Path(directory) / "releases",
                        apply=False,
                        enable=False,
                        start=False,
                    )


if __name__ == "__main__":
    unittest.main()
