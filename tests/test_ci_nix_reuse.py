"""Exercise the exact Main reuse selector, not a copy of its logic."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REPO = "heimgewebe/heim-pc"
SHA = "a" * 40
BUILD = "Build deployed live closure and execute both systemd VM proofs"
STEP_NAMES = (
    "Verify source identity",
    "Check canonical lock projection",
    "Evaluate live trust and lifecycle contracts",
    BUILD,
)


def proof():
    run = {
        "id": 123, "run_attempt": 1, "head_sha": SHA,
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        "event": "merge_group", "workflow_id": 351684660,
        "path": ".github/workflows/heim-pc-nix.yml",
        "head_branch": "gh-readonly-queue/main/pr-1-" + "b" * 40,
        "status": "completed", "conclusion": "success",
    }
    jobs = [
        {
            "name": name, "head_sha": SHA, "run_id": 123, "run_attempt": 1,
            "status": "completed",
            "conclusion": "skipped" if name == "nix" else "success",
            "steps": [
                {"name": step, "status": "completed", "conclusion": "success"}
                for step in STEP_NAMES
            ] if name == "live-system" else [],
        }
        for name in ("detect", "live-system", "nix")
    ]
    return {"total_count": 1, "workflow_runs": [run]}, {"total_count": 3, "jobs": jobs}


class ExactMergeGroupReuseTests(unittest.TestCase):
    def select(self, runs, jobs, *, event="push", repo=REPO,
               ref="refs/heads/main", sha=SHA, failed=False):
        workflow = (ROOT / ".github/workflows/heim-pc-nix.yml").read_text()
        selector = workflow.split("- name: Select exact merge-group build reuse\n", 1)[1]
        script = textwrap.dedent(selector.split("\n      - name:", 1)[0].split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            responses = [
                subprocess.CompletedProcess([], 0, r if isinstance(r, str) else json.dumps(r), "")
                for r in (runs, jobs)
            ]
            with patch.dict(os.environ, {
                "EVENT_NAME": event, "REPOSITORY": repo, "REF_NAME": ref,
                "HEAD_SHA": sha, "GITHUB_OUTPUT": str(output),
            }), patch("subprocess.run", side_effect=(
                subprocess.TimeoutExpired("gh", 10) if failed else responses
            )) as api, patch("sys.stdout", new_callable=io.StringIO):
                exec(compile(script, "<workflow reuse selector>", "exec"), {})
            return output.read_text().strip(), [call.args[0] for call in api.call_args_list]

    def test_complete_exact_full_group(self):
        result, calls = self.select(*proof())
        self.assertEqual("reuse=true", result)
        self.assertEqual([
            ["gh", "api", f"repos/{REPO}/actions/runs?head_sha={SHA}&per_page=30"],
            ["gh", "api", f"repos/{REPO}/actions/runs/123/attempts/1/jobs?per_page=100"],
        ], calls)

    def test_never_reuse_other_contexts(self):
        for kwargs in (
            {"event": "pull_request"}, {"event": "merge_group"},
            {"event": "workflow_dispatch"}, {"repo": "other/heim-pc"},
            {"ref": "refs/heads/topic"}, {"sha": "invalid"},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(("reuse=false", []), self.select(*proof(), **kwargs))

    def test_wrong_run_or_incomplete_inventory_falls_back(self):
        mutations = {
            "head_sha": "c" * 40, "repository": {"full_name": "other/repo"},
            "head_repository": {"full_name": "other/repo"}, "event": "push",
            "workflow_id": 1, "path": ".github/workflows/other.yml",
            "head_branch": "gh-readonly-queue/other/pr-1", "status": "in_progress",
            "conclusion": "failure", "id": True, "run_attempt": 0,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                runs, jobs = proof()
                runs["workflow_runs"][0][field] = value
                self.assertEqual("reuse=false", self.select(runs, jobs)[0])
        runs, jobs = proof()
        runs["total_count"] = 2
        self.assertEqual("reuse=false", self.select(runs, jobs)[0])
        runs, jobs = proof()
        runs["workflow_runs"].append(copy.deepcopy(runs["workflow_runs"][0]))
        runs["total_count"] = 2
        self.assertEqual("reuse=false", self.select(runs, jobs)[0])
        self.assertEqual("reuse=false", self.select("invalid JSON", jobs)[0])
        self.assertEqual("reuse=false", self.select(*proof(), failed=True)[0])

    def test_skipped_failed_missing_or_ambiguous_build_is_not_proof(self):
        for field, value in (
            ("head_sha", "c" * 40), ("run_id", 124), ("run_attempt", 2),
            ("status", "in_progress"), ("conclusion", "failure"),
        ):
            with self.subTest(field=field):
                runs, jobs = proof()
                jobs["jobs"][1][field] = value
                self.assertEqual("reuse=false", self.select(runs, jobs)[0])
        for outcome in ("skipped", "failure", "cancelled"):
            with self.subTest(outcome=outcome):
                runs, jobs = proof()
                jobs["jobs"][1]["steps"][-1]["conclusion"] = outcome
                self.assertEqual("reuse=false", self.select(runs, jobs)[0])
        for operation in ("missing", "duplicate", "truncated", "missing-job", "detect-failed"):
            with self.subTest(operation=operation):
                runs, jobs = proof()
                if operation == "missing":
                    jobs["jobs"][1]["steps"].pop()
                elif operation == "duplicate":
                    jobs["jobs"][1]["steps"].append(copy.deepcopy(jobs["jobs"][1]["steps"][-1]))
                elif operation == "truncated":
                    jobs["total_count"] = 4
                elif operation == "missing-job":
                    jobs["jobs"].pop()
                    jobs["total_count"] = 2
                else:
                    jobs["jobs"][0]["conclusion"] = "failure"
                self.assertEqual("reuse=false", self.select(runs, jobs)[0])

    def test_every_job_identity_and_optional_nix_conclusion(self):
        for job_index in (0, 1, 2):
            for field, value in (
                ("head_sha", "c" * 40), ("run_id", 124), ("run_attempt", 2),
                ("status", "in_progress"),
            ):
                with self.subTest(job=job_index, field=field):
                    runs, jobs = proof()
                    jobs["jobs"][job_index][field] = value
                    self.assertEqual("reuse=false", self.select(runs, jobs)[0])
        for conclusion in ("success", "failure", "cancelled"):
            with self.subTest(nix_conclusion=conclusion):
                runs, jobs = proof()
                jobs["jobs"][2]["conclusion"] = conclusion
                self.assertEqual("reuse=false", self.select(runs, jobs)[0])

    def test_fresh_checks_and_conservative_build_condition_remain(self):
        workflow = (ROOT / ".github/workflows/heim-pc-nix.yml").read_text()
        live = workflow.split("  live-system:\n", 1)[1]
        before, build = live.split("- name: " + BUILD, 1)
        for step in STEP_NAMES[:-1]:
            self.assertIn("- name: " + step, before)
        self.assertIn("actions: read", before)
        self.assertIn("steps.reuse.outputs.reuse != 'true' &&", build)
        self.assertIn("needs.detect.result != 'success'", build)
        self.assertIn("needs.detect.outputs.control_changed != 'false'", build)
        self.assertIn("needs.detect.outputs.nix_changed != 'false'", build)
        self.assertIn("systemd-analyze", build)
        self.assertIn("grabowski-headless-systemd-vm-proof", build)
        self.assertIn("nixer-headless-systemd-vm-proof", build)


if __name__ == "__main__":
    unittest.main()
