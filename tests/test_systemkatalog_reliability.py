from __future__ import annotations

import importlib.util
import json
import stat
import tarfile
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load("systemkatalog_reliability_installer", "scripts/install_systemkatalog_reliability.py")
watchdog = _load("systemkatalog_drift_watch", "scripts/systemkatalog_drift_watch.py")


class SystemkatalogReliabilityTests(unittest.TestCase):
    def test_repositories_root_agent_entry_is_conditional_and_canonical(self) -> None:
        agent_text = (ROOT / "config/agents/repos-root-AGENTS.md").read_text(encoding="utf-8")
        readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("/home/alex/repos/systemkatalog", agent_text)
        self.assertIn("mehrere Repositories oder Systeme", agent_text)
        self.assertIn("nicht pauschal geladen", agent_text)
        self.assertIn("Direkter Systemkatalog-Pointer", readme_text)
        self.assertIn("~/repos/systemkatalog/AGENTS.md", readme_text)

        legacy_name = "Cabi" + "net"
        legacy_path = "~/repos/" + "cabi" + "net"
        for document in (agent_text, readme_text):
            self.assertNotIn(legacy_name, document)
            self.assertNotIn(legacy_path, document)

    def test_installer_plan_has_no_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            receipt = installer.install(home=home, apply=False, enable=False)
            self.assertFalse(receipt["apply"])
            self.assertTrue(all(item["action"] == "install" for item in receipt["files"]))
            self.assertFalse((home / "repos/AGENTS.md").exists())
            self.assertFalse((home / ".local/bin/systemkatalog-drift-watch").exists())

    def test_installer_apply_is_idempotent_and_sets_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            first = installer.install(home=home, apply=True, enable=False)
            second = installer.install(home=home, apply=True, enable=False)
            self.assertTrue(all(item["action"] == "install" for item in first["files"]))
            self.assertTrue(all(item["action"] == "unchanged" for item in second["files"]))
            self.assertEqual((home / "repos/AGENTS.md").read_bytes(), (ROOT / "config/agents/repos-root-AGENTS.md").read_bytes())
            self.assertEqual(stat.S_IMODE((home / "repos/AGENTS.md").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((home / ".local/bin/systemkatalog-drift-watch").stat().st_mode), 0o755)


    def test_candidate_assessment_reads_exact_candidate_identity(self) -> None:
        payload = {
            "result": {
                "candidate_id": watchdog.CANDIDATE_ID,
                "candidate_status": "active",
                "event_id": 572,
            }
        }
        with mock.patch.object(
            watchdog,
            "_run",
            return_value=mock.Mock(returncode=0, stdout=json.dumps(payload), stderr=""),
        ) as run:
            result = watchdog._candidate_assessment(Path("/tmp/bureau"), watchdog.CANDIDATE_ID)

        self.assertEqual(result, (572, "active"))
        argv = run.call_args.args[0]
        self.assertIn("operator-candidate-assess", argv)
        self.assertEqual(argv[-2:], ["--candidate-id", watchdog.CANDIDATE_ID])
        self.assertNotIn("live-list", argv)

    def test_candidate_assessment_treats_exact_unknown_as_absent(self) -> None:
        payload = {
            "result": {
                "kind": "bureau_operator_intake_failure",
                "message": f"candidate {watchdog.CANDIDATE_ID} is unknown",
                "effect_started": False,
            }
        }
        with mock.patch.object(
            watchdog,
            "_run",
            return_value=mock.Mock(returncode=2, stdout=json.dumps(payload), stderr=""),
        ):
            self.assertIsNone(
                watchdog._candidate_assessment(Path("/tmp/bureau"), watchdog.CANDIDATE_ID)
            )

    def test_candidate_assessment_rejects_unbound_identity(self) -> None:
        payload = {
            "result": {
                "candidate_id": "OTHER",
                "candidate_status": "active",
                "event_id": 572,
            }
        }
        with mock.patch.object(
            watchdog,
            "_run",
            return_value=mock.Mock(returncode=0, stdout=json.dumps(payload), stderr=""),
        ):
            with self.assertRaisesRegex(RuntimeError, "not identity-bound"):
                watchdog._candidate_assessment(Path("/tmp/bureau"), watchdog.CANDIDATE_ID)

    def test_github_repository_parser_accepts_supported_remote_forms(self) -> None:
        expected = "heimgewebe/systemkatalog"
        self.assertEqual(
            watchdog._github_repository_from_remote("git@github.com:heimgewebe/systemkatalog.git"),
            expected,
        )
        self.assertEqual(
            watchdog._github_repository_from_remote(
                "org-236528253@github.com:heimgewebe/systemkatalog.git"
            ),
            expected,
        )
        self.assertEqual(
            watchdog._github_repository_from_remote("https://github.com/heimgewebe/systemkatalog.git"),
            expected,
        )
        self.assertEqual(
            watchdog._github_repository_from_remote("ssh://git@github.com/heimgewebe/systemkatalog.git"),
            expected,
        )
        self.assertIsNone(
            watchdog._github_repository_from_remote("https://example.invalid/heimgewebe/systemkatalog.git")
        )

    def test_fetch_remote_main_is_bound_to_verified_origin_and_commit(self) -> None:
        calls: list[list[str]] = []
        commit = "a" * 40
        remote_url = "git@github.com:heimgewebe/systemkatalog.git"

        def fake_run(argv, *, cwd=None):
            calls.append(argv)
            if argv[-3:] == ["remote", "get-url", "origin"]:
                return mock.Mock(returncode=0, stdout=remote_url + "\n", stderr="")
            if "ls-remote" in argv:
                return mock.Mock(
                    returncode=0,
                    stdout=f"{commit}\trefs/heads/main\n",
                    stderr="",
                )
            if "fetch" in argv or "cat-file" in argv:
                return mock.Mock(returncode=0, stdout="", stderr="")
            raise AssertionError(argv)

        with mock.patch.object(watchdog, "_run", side_effect=fake_run):
            resolved = watchdog._fetch_remote_main(
                Path("/tmp/systemkatalog"), watchdog.SYSTEMKATALOG_REPOSITORY
            )

        self.assertEqual(resolved, commit)
        listed = next(argv for argv in calls if "ls-remote" in argv)
        self.assertEqual(listed[-2:], [remote_url, "refs/heads/main"])
        fetch = next(argv for argv in calls if "fetch" in argv)
        self.assertEqual(fetch[-2:], [remote_url, commit])
        verify = next(argv for argv in calls if "cat-file" in argv)
        self.assertEqual(verify[-1], f"{commit}^{{commit}}")

    def test_fetch_remote_main_rejects_wrong_origin_before_fetch(self) -> None:
        calls: list[list[str]] = []

        def fake_run(argv, *, cwd=None):
            calls.append(argv)
            return mock.Mock(
                returncode=0,
                stdout="git@github.com:someone-else/systemkatalog.git\n",
                stderr="",
            )

        with mock.patch.object(watchdog, "_run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "unexpected origin"):
                watchdog._fetch_remote_main(
                    Path("/tmp/systemkatalog"), watchdog.SYSTEMKATALOG_REPOSITORY
                )
        self.assertEqual(len(calls), 1)

    def test_git_archive_extraction_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "unsafe.tar"
            with tarfile.open(archive_path, mode="w") as archive:
                link = tarfile.TarInfo("unsafe-link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/tmp/outside"
                archive.addfile(link)
            with self.assertRaisesRegex(RuntimeError, "unsupported non-regular"):
                watchdog._extract_git_archive(archive_path, root / "output")

    def test_watchdog_deduplicates_material_drift_from_fresh_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            systemkatalog = base / "systemkatalog"
            bureau = base / "bureau"
            fleet = base / "metarepo/fleet/repos.yml"
            state = base / "state"
            (systemkatalog / "scripts").mkdir(parents=True)
            bureau.mkdir()
            fleet.parent.mkdir(parents=True)
            fleet.write_text("repositories: []\n", encoding="utf-8")
            for name in ("read_github_catalog_observations.py", "system_catalog_drift.py"):
                (systemkatalog / "scripts" / name).write_text("# fixture\n", encoding="utf-8")

            @contextmanager
            def fake_sources(**kwargs):
                yield watchdog.SourceSnapshot(
                    systemkatalog_root=systemkatalog,
                    fleet_file=fleet,
                    systemkatalog_commit="a" * 40,
                    metarepo_commit="b" * 40,
                )

            def fake_run(argv, *, cwd=None):
                if "read_github_catalog_observations.py" in " ".join(argv):
                    output = Path(argv[argv.index("--output") + 1])
                    output.write_text(json.dumps({"repositories": [], "observations": []}), encoding="utf-8")
                    return mock.Mock(returncode=0, stdout="", stderr="")
                if "system_catalog_drift.py" in " ".join(argv):
                    report_path = Path(argv[argv.index("--output") + 1])
                    proposal_path = Path(argv[argv.index("--proposal-output") + 1])
                    report = {
                        "materialDrift": True,
                        "changeCount": 1,
                        "changes": [{"kind": "primary_source_changed"}],
                    }
                    report_path.write_text(json.dumps(report), encoding="utf-8")
                    proposal_path.write_text(json.dumps({"proposalOnly": True}), encoding="utf-8")
                    return mock.Mock(returncode=0, stdout="", stderr="")
                if "operator-candidate-assess" in argv:
                    payload = {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "active",
                            "event_id": 9,
                        }
                    }
                    return mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
                raise AssertionError(argv)

            with (
                mock.patch.object(watchdog, "_fresh_source_snapshot", side_effect=fake_sources),
                mock.patch.object(watchdog, "_run", side_effect=fake_run),
            ):
                receipt = watchdog.run_watch(
                    systemkatalog_root=systemkatalog,
                    fleet_file=fleet,
                    bureau_root=bureau,
                    state_root=state,
                )
            self.assertTrue(receipt["materialDrift"])
            self.assertEqual(receipt["bureau"]["action"], "deduplicated")
            self.assertEqual(receipt["sources"]["systemkatalog"]["commit"], "a" * 40)
            self.assertEqual(receipt["sources"]["fleet"]["commit"], "b" * 40)
            self.assertTrue((state / "last-run.json").exists())
            self.assertEqual(stat.S_IMODE((state / "last-run.json").stat().st_mode), 0o600)


    def test_watchdog_reactivates_closed_candidate_with_supersedes_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            calls = []
            assessments = iter(
                [
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "closed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "closed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "active",
                            "event_id": 42,
                        }
                    },
                ]
            )

            def fake_run(argv, *, cwd=None):
                calls.append(argv)
                if "operator-candidate-assess" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps(next(assessments)),
                        stderr="",
                    )
                if "live-register" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps({"result": {"event_id": 42}}),
                        stderr="",
                    )
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                result = watchdog._ensure_bureau_candidate(
                    base,
                    report_path,
                    json.loads(report_path.read_text()),
                )

            self.assertEqual(result["action"], "reactivated")
            self.assertEqual(result["eventId"], 42)
            self.assertEqual(result["supersedesEventId"], 41)
            register = next(argv for argv in calls if "live-register" in argv)
            supersedes_index = register.index("--supersedes-event-id")
            self.assertEqual(register[supersedes_index + 1], "41")
            self.assertEqual(
                len([argv for argv in calls if "operator-candidate-assess" in argv]),
                3,
            )


    def test_watchdog_registers_when_exact_candidate_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 2, "changes": [{"kind": "repository_unclassified"}]}),
                encoding="utf-8",
            )
            calls = []
            unknown = {
                "result": {
                    "kind": "bureau_operator_intake_failure",
                    "message": f"candidate {watchdog.CANDIDATE_ID} is unknown",
                    "effect_started": False,
                }
            }
            active = {
                "result": {
                    "candidate_id": watchdog.CANDIDATE_ID,
                    "candidate_status": "active",
                    "event_id": 42,
                }
            }
            assessments = iter(
                [
                    (2, unknown),
                    (2, unknown),
                    (0, active),
                ]
            )

            def fake_run(argv, *, cwd=None):
                calls.append(argv)
                if "operator-candidate-assess" in argv:
                    returncode, payload = next(assessments)
                    return mock.Mock(
                        returncode=returncode,
                        stdout=json.dumps(payload),
                        stderr="",
                    )
                if "live-register" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps({"result": {"event_id": 42}}),
                        stderr="",
                    )
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                result = watchdog._ensure_bureau_candidate(
                    base,
                    report_path,
                    json.loads(report_path.read_text()),
                )
            self.assertEqual(
                result,
                {
                    "action": "registered",
                    "candidateId": watchdog.CANDIDATE_ID,
                    "eventId": 42,
                    "status": "active",
                },
            )
            register_argv = next(argv for argv in calls if "live-register" in argv)
            self.assertIn("--promotion-required", register_argv)
            self.assertIn("repo.systemkatalog", register_argv)
            self.assertNotIn("--supersedes-event-id", register_argv)

    def test_watchdog_reports_concurrent_active_update_after_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            assessments = iter(
                [
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "closed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "closed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "active",
                            "event_id": 43,
                        }
                    },
                ]
            )

            def fake_run(argv, *, cwd=None):
                if "operator-candidate-assess" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps(next(assessments)),
                        stderr="",
                    )
                if "live-register" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps({"result": {"event_id": 42}}),
                        stderr="",
                    )
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                result = watchdog._ensure_bureau_candidate(
                    base,
                    report_path,
                    json.loads(report_path.read_text()),
                )

            self.assertEqual(result["action"], "deduplicated")
            self.assertEqual(result["eventId"], 43)
            self.assertEqual(result["registeredEventId"], 42)
            self.assertTrue(result["concurrentUpdateAfterRegistration"])

    def test_watchdog_accepts_concurrent_active_registration_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            calls = []
            assessments = iter(
                [
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "closed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "closed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "active",
                            "event_id": 43,
                        }
                    },
                ]
            )

            def fake_run(argv, *, cwd=None):
                calls.append(argv)
                if "operator-candidate-assess" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps(next(assessments)),
                        stderr="",
                    )
                if "live-register" in argv:
                    return mock.Mock(
                        returncode=1,
                        stdout="",
                        stderr="concurrent append",
                    )
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                result = watchdog._ensure_bureau_candidate(
                    base,
                    report_path,
                    json.loads(report_path.read_text()),
                )

            self.assertEqual(result["action"], "deduplicated")
            self.assertEqual(result["eventId"], 43)
            self.assertTrue(result["recoveredFromConcurrentRegistration"])
            self.assertEqual(
                len([argv for argv in calls if "live-register" in argv]),
                1,
            )

    def test_command_error_uses_stdout_when_stderr_is_empty(self) -> None:
        completed = mock.Mock(returncode=1, stdout="structured failure", stderr="")
        self.assertEqual(watchdog._command_error(completed), "structured failure")


if __name__ == "__main__":
    unittest.main()
