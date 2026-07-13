from __future__ import annotations

import importlib.util
import json
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

    def test_latest_candidate_status_uses_latest_event(self) -> None:
        payload = {
            "records": [
                {"event_id": 2, "record": {"candidate_id": watchdog.CANDIDATE_ID, "status": "closed"}},
                {"event_id": 7, "record": {"candidate_id": watchdog.CANDIDATE_ID, "status": "active"}},
                {"event_id": 5, "record": {"candidate_id": "OTHER", "status": "active"}},
            ]
        }
        self.assertEqual(watchdog._latest_candidate_status(payload, watchdog.CANDIDATE_ID), "active")

    def test_watchdog_deduplicates_material_drift(self) -> None:
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
                if "live-list" in argv:
                    payload = {"records": [{"event_id": 9, "record": {"candidate_id": watchdog.CANDIDATE_ID, "status": "active"}}]}
                    return mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                receipt = watchdog.run_watch(
                    systemkatalog_root=systemkatalog,
                    fleet_file=fleet,
                    bureau_root=bureau,
                    state_root=state,
                )
            self.assertTrue(receipt["materialDrift"])
            self.assertEqual(receipt["bureau"]["action"], "deduplicated")
            self.assertTrue((state / "last-run.json").exists())
            self.assertEqual(stat.S_IMODE((state / "last-run.json").stat().st_mode), 0o600)

    def test_watchdog_registers_when_no_active_candidate_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            report_path.write_text(json.dumps({"changeCount": 2, "changes": [{"kind": "repository_unclassified"}]}), encoding="utf-8")
            calls = []

            def fake_run(argv, *, cwd=None):
                calls.append(argv)
                if "live-list" in argv:
                    return mock.Mock(returncode=0, stdout=json.dumps({"records": []}), stderr="")
                if "live-register" in argv:
                    return mock.Mock(returncode=0, stdout=json.dumps({"event_id": 42}), stderr="")
                raise AssertionError(argv)

            with mock.patch.object(watchdog, "_run", side_effect=fake_run):
                result = watchdog._ensure_bureau_candidate(base, report_path, json.loads(report_path.read_text()))
            self.assertEqual(result, {"action": "registered", "candidateId": watchdog.CANDIDATE_ID, "eventId": 42})
            register = next(argv for argv in calls if "live-register" in argv)
            self.assertIn("--promotion-required", register)
            self.assertIn("repo.systemkatalog", register)


if __name__ == "__main__":
    unittest.main()
