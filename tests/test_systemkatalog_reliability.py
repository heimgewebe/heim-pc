from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import io
import zipfile
import tempfile
import unittest
from datetime import datetime, timezone
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
            receipt = installer.install(home=home, apply=False, enable=False, declarative=False)
            self.assertFalse(receipt["apply"])
            self.assertTrue(all(item["action"] == "install" for item in receipt["files"]))
            self.assertFalse((home / "repos/AGENTS.md").exists())
            self.assertFalse((home / ".local/bin/systemkatalog-drift-watch").exists())

    def test_installer_apply_is_idempotent_and_sets_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            first = installer.install(home=home, apply=True, enable=False, declarative=False)
            second = installer.install(home=home, apply=True, enable=False, declarative=False)
            self.assertTrue(all(item["action"] == "install" for item in first["files"]))
            self.assertTrue(all(item["action"] == "unchanged" for item in second["files"]))
            self.assertEqual((home / "repos/AGENTS.md").read_bytes(), (ROOT / "config/agents/repos-root-AGENTS.md").read_bytes())
            self.assertEqual(stat.S_IMODE((home / "repos/AGENTS.md").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((home / ".local/bin/systemkatalog-drift-watch").stat().st_mode), 0o755)


    def test_installer_respects_declarative_timer(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            declared = home / "declared"
            with mock.patch.object(installer, "DECLARED_USER_UNITS", declared), \
                 mock.patch.object(installer, "_systemctl", side_effect=lambda *args: str(declared / args[-1]) if args[0] == "show" else "") as ctl:
                receipt = installer.install(home=home, apply=True, enable=True, declarative=True)
            self.assertIn(mock.call("start", "systemkatalog-drift-watch.timer"), ctl.call_args_list)
            self.assertEqual(receipt["systemd"], "declarative")
            self.assertEqual(len(receipt["files"]), 1)
            self.assertFalse((home / ".config/systemd/user/systemkatalog-drift-watch.timer").exists())

    def test_declarative_installer_migrates_owned_legacy_units(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            installer.install(home=home, apply=True, enable=False, declarative=False)
            units = home / ".config/systemd/user"
            timer = units / "systemkatalog-drift-watch.timer"
            service = units / "systemkatalog-drift-watch.service"
            wants = units / "timers.target.wants"
            wants.mkdir()
            link = wants / timer.name
            link.symlink_to(timer)
            plan = installer.install(home=home, apply=False, enable=False, declarative=True)
            self.assertEqual(plan["legacyUnits"]["status"], "migration_needed")
            self.assertTrue(timer.is_file() and service.is_file() and link.is_symlink())
            result = installer.install(home=home, apply=True, enable=False, declarative=True)
            self.assertEqual(result["legacyUnits"]["status"], "migrated")
            self.assertFalse(timer.exists() or service.exists() or link.is_symlink())
            self.assertTrue((home / ".local/bin/systemkatalog-drift-watch").exists())
            again = installer.install(home=home, apply=True, enable=False, declarative=True)
            self.assertEqual(again["legacyUnits"]["status"], "absent")

    def test_declarative_installer_verifies_and_preserves_native_enable_link(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            units = home / ".config/systemd/user"
            declared = home / "declared"
            declared.mkdir()
            timer = declared / "systemkatalog-drift-watch.timer"
            timer.write_text("[Timer]\\n", encoding="utf-8")
            wants = units / "timers.target.wants"
            wants.mkdir(parents=True)
            link = wants / timer.name
            link.symlink_to(timer)
            with mock.patch.object(installer, "DECLARED_USER_UNITS", declared), \
                 mock.patch.object(installer, "_systemctl", side_effect=lambda *args: str(declared / args[-1]) if args[0] == "show" else ""):
                result = installer.install(home=home, apply=True, enable=True, declarative=True)
            self.assertEqual(result["legacyUnits"]["status"], "absent")
            self.assertTrue(link.is_symlink())

    def test_declarative_installer_preserves_custom_override(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            installer.install(home=home, apply=True, enable=False, declarative=False)
            units = home / ".config/systemd/user"
            service = units / "systemkatalog-drift-watch.service"
            service.write_text("[Service]\nExecStart=/custom\n", encoding="utf-8")
            timer = units / "systemkatalog-drift-watch.timer"
            with self.assertRaisesRegex(RuntimeError, "custom.*override"):
                installer.install(home=home, apply=True, enable=False, declarative=True)
            self.assertIn("/custom", service.read_text(encoding="utf-8"))
            self.assertTrue(timer.is_file())

    def test_candidate_assessment_reads_exact_candidate_identity(self) -> None:
        payload = {
            "result": {
                "candidate_id": watchdog.CANDIDATE_ID,
                "candidate_status": "active",
                "decision": "promote",
                "event_id": 572,
                "missing_fields": [],
                "source_freshness": {"sha256": "a" * 64},
            }
        }
        with mock.patch.object(
            watchdog,
            "_run",
            return_value=mock.Mock(returncode=0, stdout=json.dumps(payload), stderr=""),
        ) as run:
            result = watchdog._candidate_assessment(Path("/tmp/bureau"), watchdog.CANDIDATE_ID)

        self.assertEqual(
            result,
            watchdog.CandidateAssessment(572, "active", "promote", "a" * 64, ()),
        )
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ["bureau", "--json"])
        self.assertIn("operator-candidate-assess", argv)
        self.assertEqual(argv[-2:], ["--candidate-id", watchdog.CANDIDATE_ID])
        self.assertNotIn("--root", argv)
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

    def test_candidate_match_requires_promotable_digest_bound_assessment(self) -> None:
        digest = "a" * 64
        base = watchdog.CandidateAssessment(1, "observed", "promote", digest, ())
        self.assertTrue(watchdog._candidate_matches_report(base, digest))
        self.assertTrue(
            watchdog._candidate_matches_report(
                base._replace(decision="merge"),
                digest,
            )
        )
        for status in ("active", "paused", "promoted"):
            self.assertTrue(
                watchdog._candidate_matches_report(base._replace(status=status), digest)
            )
        for assessment in (
            base._replace(status="closed"),
            base._replace(status="dropped"),
            base._replace(decision="refine"),
            base._replace(decision=None),
            base._replace(source_sha256="b" * 64),
            base._replace(missing_fields=("desired_outcome",)),
        ):
            self.assertFalse(watchdog._candidate_matches_report(assessment, digest))

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

    def _ci_fixture(self, *, material=True, conclusion="success"):
        now = datetime(2026, 11, 24, 17, 31, tzinfo=timezone.utc)
        changes = [{"kind": "primary_source_changed", "observedSha256": "a" * 64,
                    "observedCommit": "b" * 40}] if material else []
        report = {"schemaVersion": 1, "kind": "system_catalog_drift_report",
                  "generatedAt": "2026-11-24T17:30:20Z", "materialDrift": material,
                  "changeCount": len(changes), "changes": changes,
                  "bureauCandidate": {"candidateId": watchdog.CANDIDATE_ID,
                                      "repo": "repo.systemkatalog"} if material else None,
                  "proposal": {"proposalOnly": True, "autoMerge": False,
                               "candidateId": watchdog.CANDIDATE_ID}}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr(watchdog.ARTIFACT + ".json", json.dumps(report))
        raw = buf.getvalue()
        repo = {"id": 1, "full_name": watchdog.SYSTEMKATALOG_REPOSITORY}
        run = {"id": 21, "head_sha": "c" * 40, "head_branch": "main",
               "path": ".github/workflows/ecosystem-map.yml", "repository": repo,
               "head_repository": repo, "event": "schedule", "status": "completed",
               "conclusion": conclusion, "run_started_at": "2026-11-24T17:30:00Z",
               "updated_at": "2026-11-24T17:30:30Z"}
        artifact = {"name": watchdog.ARTIFACT, "id": 42, "expired": False,
                    "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "size_in_bytes": len(raw),
                    "workflow_run": {"id": 21, "head_sha": run["head_sha"],
                                     "head_branch": "main", "repository_id": 1,
                                     "head_repository_id": 1}}
        calls = []
        def api(path):
            calls.append(path)
            if "/workflows/" in path:
                return json.dumps({"workflow_runs": [run]}).encode()
            if "/runs/21/artifacts" in path:
                return json.dumps({"total_count": 1, "artifacts": [artifact]}).encode()
            if path.endswith("/artifacts/42/zip"):
                return raw
            raise AssertionError(path)
        return now, run, artifact, report, api, calls

    def test_ci_artifact_is_exact_and_material_failure_is_diagnostic(self):
        now, run, artifact, report, api, calls = self._ci_fixture(conclusion="failure")
        result, source = watchdog.fetch_ci_report(api, now=now)
        self.assertEqual(result, report)
        self.assertEqual(source["runId"], 21)
        self.assertEqual(source["artifactDigest"], artifact["digest"])
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(path.startswith("repos/heimgewebe/systemkatalog/actions/") for path in calls))

    def test_ci_artifact_rejects_bad_identity_digest_and_failed_clean_report(self):
        now, run, artifact, _, api, _ = self._ci_fixture()
        artifact["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "provider digest"):
            watchdog.fetch_ci_report(api, now=now)
        artifact["workflow_run"]["id"] = 999
        with self.assertRaisesRegex(ValueError, "identity"):
            watchdog.fetch_ci_report(api, now=now)
        now, run, artifact, _, api, _ = self._ci_fixture(material=False, conclusion="failure")
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            watchdog.fetch_ci_report(api, now=now)

    def test_ci_artifact_missing_or_stale_never_means_clean(self):
        now, run, artifact, _, api, _ = self._ci_fixture()
        def missing(path):
            return b'{"total_count":0,"artifacts":[]}' if "/runs/21/artifacts" in path else api(path)
        with self.assertRaisesRegex(ValueError, "unique drift artifact"):
            watchdog.fetch_ci_report(missing, now=now)
        run["updated_at"] = "2026-11-21T17:30:30Z"
        with self.assertRaisesRegex(ValueError, "stale"):
            watchdog.fetch_ci_report(api, now=now)

    def test_semantic_dedupe_and_check_only(self):
        _, _, _, report, _, _ = self._ci_fixture()
        other = json.loads(json.dumps(report))
        other["generatedAt"] = "2026-11-25T17:30:20Z"
        other["changes"][0]["observedCommit"] = "d" * 40
        self.assertEqual(watchdog.material_fingerprint(report), watchdog.material_fingerprint(other))
        other["changes"][0]["observedSha256"] = "e" * 64
        self.assertNotEqual(watchdog.material_fingerprint(report), watchdog.material_fingerprint(other))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "not-created"
            with mock.patch.object(watchdog, "fetch_ci_report", return_value=(report, {"runId":21})), \
                 mock.patch.object(watchdog, "_ensure_bureau_candidate") as candidate:
                receipt = watchdog.run_watch(bureau_root=root, state_root=root, check_only=True)
                self.assertTrue(receipt["materialDrift"])
                self.assertFalse(root.exists())
                candidate.assert_not_called()
                candidate.return_value = {"action":"deduplicated"}
                result = watchdog.run_watch(bureau_root=root, state_root=root)
                self.assertEqual(result["bureau"]["action"], "deduplicated")
                self.assertTrue((root / "last-run.json").is_file())
                self.assertEqual(hashlib.sha256(Path(result["materialReport"]).read_bytes()).hexdigest(),
                                 result["materialSha256"])

    def test_watchdog_reactivates_closed_candidate_with_supersedes_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
            calls = []
            previous_digest = "b" * 64
            assessments = iter(
                [
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "closed",
                            "decision": "drop",
                            "event_id": 41,
                            "missing_fields": [],
                            "source_freshness": {"sha256": previous_digest},
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "closed",
                            "decision": "drop",
                            "event_id": 41,
                            "missing_fields": [],
                            "source_freshness": {"sha256": previous_digest},
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "observed",
                            "decision": "promote",
                            "event_id": 42,
                            "missing_fields": [],
                            "source_freshness": {"sha256": previous_digest},
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "observed",
                            "decision": "promote",
                            "event_id": 43,
                            "missing_fields": [],
                            "source_freshness": {"sha256": digest},
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
                if "operator-candidate-record" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps({"result": {"event_id": 43}}),
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
            self.assertEqual(result["eventId"], 43)
            self.assertEqual(result["status"], "observed")
            self.assertEqual(result["supersedesEventId"], 42)
            reactivation = next(argv for argv in calls if "live-register" in argv)
            self.assertEqual(reactivation[:2], ["bureau", "--json"])
            self.assertEqual(
                reactivation[reactivation.index("--supersedes-event-id") + 1],
                "41",
            )
            self.assertEqual(
                reactivation[reactivation.index("--candidate-id") + 1],
                watchdog.CANDIDATE_ID,
            )
            self.assertEqual(reactivation[reactivation.index("--status") + 1], "observed")
            self.assertNotIn("--repo", reactivation)
            self.assertNotIn("--task-id", reactivation)
            self.assertNotIn("--promotion-required", reactivation)
            register = next(argv for argv in calls if "operator-candidate-record" in argv)
            self.assertLess(calls.index(reactivation), calls.index(register))
            request_path = Path(register[register.index("--request") + 1])
            request = json.loads(request_path.read_text(encoding="utf-8"))
            self.assertEqual(request["supersedes_event_id"], 42)
            self.assertEqual(request["source_sha256"], digest)
            self.assertEqual(request["candidate_id"], watchdog.CANDIDATE_ID)
            self.assertTrue(request["desired_outcome"])
            self.assertEqual(
                len([argv for argv in calls if "operator-candidate-assess" in argv]),
                4,
            )

    def test_watchdog_deduplicates_exact_report_after_reactivation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
            calls = []
            closed = {
                "result": {
                    "candidate_id": watchdog.CANDIDATE_ID,
                    "candidate_status": "closed",
                    "decision": "drop",
                    "event_id": 41,
                }
            }
            exact = {
                "result": {
                    "candidate_id": watchdog.CANDIDATE_ID,
                    "candidate_status": "observed",
                    "decision": "promote",
                    "event_id": 43,
                    "missing_fields": [],
                    "source_freshness": {"sha256": digest},
                }
            }
            assessments = iter([closed, closed, exact])

            def fake_run(argv, *, cwd=None):
                calls.append(argv)
                if "operator-candidate-assess" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps(next(assessments)),
                        stderr="",
                    )
                if "live-register" in argv:
                    return mock.Mock(returncode=1, stdout="", stderr="concurrent append")
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                result = watchdog._ensure_bureau_candidate(
                    base,
                    report_path,
                    json.loads(report_path.read_text()),
                )

            self.assertEqual(result["action"], "deduplicated")
            self.assertEqual(result["eventId"], 43)
            self.assertTrue(result["recoveredFromConcurrentReactivation"])
            self.assertEqual(len([argv for argv in calls if "live-register" in argv]), 1)
            self.assertFalse(any("operator-candidate-record" in argv for argv in calls))

    def test_watchdog_fails_closed_after_inexact_reactivation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            calls = []
            previous_digest = "b" * 64
            closed = {
                "result": {
                    "candidate_id": watchdog.CANDIDATE_ID,
                    "candidate_status": "closed",
                    "decision": "drop",
                    "event_id": 41,
                }
            }
            inexact = {
                "result": {
                    "candidate_id": watchdog.CANDIDATE_ID,
                    "candidate_status": "observed",
                    "decision": "promote",
                    "event_id": 43,
                    "missing_fields": [],
                    "source_freshness": {"sha256": previous_digest},
                }
            }
            assessments = iter([closed, closed, inexact])

            def fake_run(argv, *, cwd=None):
                calls.append(argv)
                if "operator-candidate-assess" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps(next(assessments)),
                        stderr="",
                    )
                if "live-register" in argv:
                    return mock.Mock(returncode=1, stdout="", stderr="concurrent append")
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "live-register reactivation failed"):
                    watchdog._ensure_bureau_candidate(
                        base,
                        report_path,
                        json.loads(report_path.read_text()),
                    )

            self.assertEqual(len([argv for argv in calls if "live-register" in argv]), 1)
            self.assertFalse(any("operator-candidate-record" in argv for argv in calls))


    def test_watchdog_registers_when_exact_candidate_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 2, "changes": [{"kind": "repository_unclassified"}]}),
                encoding="utf-8",
            )
            digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
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
                    "candidate_status": "observed",
                    "decision": "promote",
                    "event_id": 42,
                    "missing_fields": [],
                    "source_freshness": {"sha256": digest},
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
                if "operator-candidate-record" in argv:
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
                    "status": "observed",
                },
            )
            register_argv = next(
                argv for argv in calls if "operator-candidate-record" in argv
            )
            self.assertEqual(register_argv[:2], ["bureau", "--json"])
            request_path = Path(register_argv[register_argv.index("--request") + 1])
            request = json.loads(request_path.read_text(encoding="utf-8"))
            self.assertEqual(request["repo"], "repo.systemkatalog")
            self.assertEqual(request["source_sha256"], digest)
            self.assertEqual(request["candidate_id"], watchdog.CANDIDATE_ID)
            self.assertNotIn("supersedes_event_id", request)
            self.assertEqual(stat.S_IMODE(request_path.stat().st_mode), 0o600)
            self.assertNotIn("--root", register_argv)

    def test_watchdog_reports_concurrent_observed_update_after_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
            assessments = iter(
                [
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "observed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "observed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "observed",
                            "decision": "promote",
                            "event_id": 43,
                            "missing_fields": [],
                            "source_freshness": {"sha256": digest},
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
                if "operator-candidate-record" in argv:
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

    def test_watchdog_accepts_concurrent_observed_registration_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
            calls = []
            assessments = iter(
                [
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "observed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "observed",
                            "event_id": 41,
                        }
                    },
                    {
                        "result": {
                            "candidate_id": watchdog.CANDIDATE_ID,
                            "candidate_status": "observed",
                            "decision": "promote",
                            "event_id": 43,
                            "missing_fields": [],
                            "source_freshness": {"sha256": digest},
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
                if "operator-candidate-record" in argv:
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
                len([argv for argv in calls if "operator-candidate-record" in argv]),
                1,
            )
            self.assertFalse(any("live-register" in argv for argv in calls))

    def test_watchdog_refines_legacy_active_candidate_with_structured_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(
                json.dumps({"changeCount": 1, "changes": [{"kind": "primary_source_changed"}]}),
                encoding="utf-8",
            )
            digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
            calls = []
            legacy = {
                "result": {
                    "candidate_id": watchdog.CANDIDATE_ID,
                    "candidate_status": "active",
                    "decision": "refine",
                    "event_id": 572,
                    "missing_fields": ["desired_outcome", "source.kind"],
                    "source_freshness": {"sha256": None},
                }
            }
            structured = {
                "result": {
                    "candidate_id": watchdog.CANDIDATE_ID,
                    "candidate_status": "active",
                    "decision": "promote",
                    "event_id": 573,
                    "missing_fields": [],
                    "source_freshness": {"sha256": digest},
                }
            }
            assessments = iter([legacy, legacy, structured])

            def fake_run(argv, *, cwd=None):
                calls.append(argv)
                if "operator-candidate-assess" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps(next(assessments)),
                        stderr="",
                    )
                if "operator-candidate-record" in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps({"result": {"event_id": 573}}),
                        stderr="",
                    )
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                result = watchdog._ensure_bureau_candidate(
                    base,
                    report_path,
                    json.loads(report_path.read_text()),
                )

            self.assertEqual(result["action"], "refined")
            self.assertEqual(result["eventId"], 573)
            self.assertEqual(result["supersedesEventId"], 572)
            register = next(argv for argv in calls if "operator-candidate-record" in argv)
            request_path = Path(register[register.index("--request") + 1])
            request = json.loads(request_path.read_text(encoding="utf-8"))
            self.assertEqual(request["supersedes_event_id"], 572)
            self.assertEqual(request["source_sha256"], digest)
            self.assertTrue(request["desired_outcome"])

    def test_command_error_uses_stdout_when_stderr_is_empty(self) -> None:
        completed = mock.Mock(returncode=1, stdout="structured failure", stderr="")
        self.assertEqual(watchdog._command_error(completed), "structured failure")


if __name__ == "__main__":
    unittest.main()
