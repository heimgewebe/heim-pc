from __future__ import annotations

import copy
from contextlib import closing
import hashlib
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.nixos_day1_workload_parity_evidence as binder
from scripts.nixos_day1_workload_parity_evidence import (
    Day1EvidenceError,
    build_current_binding,
    write_evidence,
)


OBS_ID = "a" * 64
START = "2026-10-07T15:00:00Z"
OBSERVED = "2026-10-07T15:00:05Z"
GENERATED = "2026-10-07T15:00:20Z"
DONE = "2026-10-07T15:00:30Z"
RECEIPT_A = "b" * 64
RECEIPT_B = "c" * 64


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def argv_sha(argv: list[str]) -> str:
    return sha(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def execution_receipt(
    task_id: str, argv: list[str], digest: str, *, cwd: Path
) -> dict:
    return {
        "task_id": task_id,
        "attempt": 1,
        "unit": f"grabowski-task-{task_id}-a1.service",
        "host": "heim-pc",
        "state": "completed",
        "cwd": str(cwd),
        "argv": argv,
        "argv_sha256": argv_sha(argv),
        "lifecycle_receipt_sha256": digest,
    }


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


class T(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root = root
        (root / "scripts").mkdir()
        (root / "runtime").mkdir()
        (root / "nixos/production").mkdir(parents=True)

        software_script = b"print('software')\n"
        collector_script = b"print('collect')\n"
        renderer_script = b"""import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--raw-dir", type=Path, required=True)
parser.add_argument("--summary-out", type=Path, required=True)
parser.add_argument("--json-out", type=Path, required=True)
parser.add_argument("--generated-at", required=True)
args = parser.parse_args()
raw = args.raw_dir.resolve()
run = json.loads((raw / "run-result.json").read_text(encoding="utf-8"))
summary = "\\n".join([
    "---",
    'observed_at: "' + run["observed_at"] + '"',
    'observation_id: "' + run["observation_id"] + '"',
    "binding_eligible: true",
    "---",
    "",
]) + "\\n"
payload = {
    "schema": "program-inventory.v1",
    "generated_at": args.generated_at,
    "observation_scope": {
        "observed_at": run["observed_at"],
        "observation_id": run["observation_id"],
        "binding_eligible": run["binding_eligible"],
    },
    "source_inventory_path": str(raw),
    "collection_provenance": {
        "host": run["host"],
        "collector_sha256": run["collector_sha256"],
        "raw_manifest_sha256": run["raw_manifest_sha256"],
        "raw_artifact_count": run["raw_artifact_count"],
    },
}
args.summary_out.write_text(summary, encoding="utf-8")
args.json_out.write_text(
    json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\\n",
    encoding="utf-8",
)
"""
        self.software_script = software_script
        self.collector_script = collector_script
        (root / "scripts/generate_software_inventory.py").write_bytes(software_script)
        (root / "scripts/collect_program_inventory.py").write_bytes(collector_script)
        (root / "scripts/generate_program_inventory.py").write_bytes(renderer_script)

        contract = {
            "admission": {"current_status": "blocked-until-fresh-heim-pc-inventory"},
            "inventory": {
                "authoritative_host": "heim-pc",
                "canonical_outputs": [
                    "runtime/software-inventory.md",
                    "runtime/program-inventory-summary.md",
                    "runtime/program-inventory.v1.json",
                ],
                "current_binding_schema": {
                    "required_output_paths": [
                        "runtime/software-inventory.md",
                        "runtime/program-inventory-summary.md",
                        "runtime/program-inventory.v1.json",
                    ],
                    "observation": {"kind": "bounded-session-v1"},
                    "provenance": {
                        "software": {
                            "collector_path": "scripts/generate_software_inventory.py"
                        },
                        "program": {
                            "collector_path": "scripts/collect_program_inventory.py",
                            "renderer_path": "scripts/generate_program_inventory.py",
                        },
                    },
                },
                "current_binding": None,
            },
        }
        (root / "nixos/production/day1-workload-parity-contract-v1.json").write_text(
            json.dumps(contract), encoding="utf-8"
        )

        (root / "runtime/software-inventory.md").write_text(
            "\n".join(
                [
                    "---",
                    f'observed_at: "{OBSERVED}"',
                    f'observation_id: "{OBS_ID}"',
                    "binding_eligible: true",
                    f'collector_sha256: "{sha(software_script)}"',
                    'observed_host: "heim-pc"',
                    "---",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        self.raw_dir = (root / "raw-program-run").resolve()
        self.raw_dir.mkdir()
        (self.raw_dir / "a.txt").write_bytes(b"alpha")
        raw_digest = sha(b"a.txt\0" + sha(b"alpha").encode() + b"\n")
        self.raw_digest = raw_digest
        run_result = {
            "out": str(self.raw_dir),
            "host": "heim-pc",
            "observed_at": OBSERVED,
            "observation_id": OBS_ID,
            "binding_eligible": True,
            "collector_sha256": sha(collector_script),
            "raw_manifest_sha256": raw_digest,
            "raw_artifact_count": 1,
        }
        (self.raw_dir / "run-result.json").write_text(
            json.dumps(run_result, indent=2) + "\n", encoding="utf-8"
        )
        subprocess.run(
            [
                "/usr/bin/python3",
                "scripts/generate_program_inventory.py",
                "--raw-dir",
                str(self.raw_dir),
                "--summary-out",
                str(root / "runtime/program-inventory-summary.md"),
                "--json-out",
                str(root / "runtime/program-inventory.v1.json"),
                "--generated-at",
                GENERATED,
            ],
            cwd=root,
            check=True,
        )

        git(root, "init", "-q")
        git(root, "config", "user.email", "test@example.invalid")
        git(root, "config", "user.name", "Test")
        git(
            root,
            "add",
            "scripts",
            "nixos/production/day1-workload-parity-contract-v1.json",
        )
        git(root, "commit", "-q", "-m", "source")
        self.revision = git(root, "rev-parse", "HEAD")

        self.task_state_root = root / "grabowski-task-state"
        (self.task_state_root / "tasks.outcomes").mkdir(parents=True)
        (self.task_state_root / "task-output").mkdir()
        self.task_db = self.task_state_root / "tasks.sqlite3"
        with closing(sqlite3.connect(self.task_db)) as db:
            db.execute(
                "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, attempt INTEGER, "
                "unit TEXT, authoritative_unit TEXT, host TEXT, cwd TEXT, "
                "state TEXT, argv_json TEXT, argv_sha256 TEXT, "
                "lifecycle_receipt_sha256 TEXT, created_at_unix INTEGER, "
                "terminalized_at_unix INTEGER, last_observation_json TEXT)"
            )
        self.task_db.chmod(0o600)
        self._task_state_patch = patch.object(
            binder, "TASK_STATE_ROOT", self.task_state_root
        )
        self._task_state_patch.start()

        receipts = self._make_execution_receipts()
        software_stdout = json.dumps(
            {
                "kind": "heim_pc.software_inventory_output",
                "host": "heim-pc",
                "observed_at": OBSERVED,
                "observation_id": OBS_ID,
                "output_sha256": sha(
                    (root / "runtime/software-inventory.md").read_bytes()
                ),
            }, sort_keys=True
        ).encode() + b"\n"
        program_stdout = json.dumps(run_result, indent=2).encode() + b"\n"
        for receipt, stdout in zip(
            receipts, (software_stdout, program_stdout, b""), strict=True
        ):
            self._register_task(receipt, stdout)
        self._receipts = receipts

    def tearDown(self) -> None:
        self._task_state_patch.stop()
        self.tmp.cleanup()

    def _register_task(self, receipt: dict, stdout: bytes) -> None:
        task_id = receipt["task_id"]
        unit = receipt["unit"]
        timing = {
            "1": (1791385201, 1791385208),
            "2": (1791385209, 1791385218),
            "3": (1791385219, 1791385227),
        }
        task_created, task_terminal = timing[task_id[0]]
        outcome = {
            "kind": "grabowski_task_lifecycle_receipt",
            "schema_version": 2,
            "task_id": task_id,
            "attempt": receipt["attempt"],
            "unit": unit,
            "authoritative_unit": unit,
            "argv_sha256": receipt["argv_sha256"],
            "state": "completed",
            "observed_at_unix": task_terminal,
            "observation": {"state": "completed"},
            "captured_stdout_sha256": sha(stdout),
            "captured_stdout_bytes": len(stdout),
        }
        digest = sha(
            json.dumps(outcome, sort_keys=True, separators=(",", ":")).encode()
        )
        outcome["receipt_sha256"] = digest
        receipt["lifecycle_receipt_sha256"] = digest
        outcome_path = self.task_state_root / "tasks.outcomes" / f"{task_id}.json"
        outcome_path.write_text(json.dumps(outcome, sort_keys=True), encoding="utf-8")
        outcome_path.chmod(0o600)
        output_dir = (
            self.task_state_root / "task-output"
            / f".grabowski-task-output-{task_id}-a{receipt['attempt']}"
        )
        output_dir.mkdir(mode=0o700)
        stdout_path = output_dir / "stdout.log"
        stdout_path.write_bytes(stdout)
        stdout_path.chmod(0o600)
        observation = {
            "state": "completed",
            "properties": {"Result": "success", "ExecMainStatus": "0"},
        }
        with closing(sqlite3.connect(self.task_db)) as db:
            db.execute(
                "INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    task_id, receipt["attempt"], unit, unit,
                    receipt["host"], receipt["cwd"], "completed",
                    json.dumps(receipt["argv"]), receipt["argv_sha256"],
                    digest, task_created, task_terminal, json.dumps(observation),
                ),
            )
            db.commit()

    def execution_receipts(self):
        return copy.deepcopy(self._receipts)

    def _make_execution_receipts(self):
        software_argv = [
            "/usr/bin/python3",
            "scripts/generate_software_inventory.py",
            "--observation-id",
            OBS_ID,
            "--observed-at",
            OBSERVED,
        ]
        program_argv = [
            "/usr/bin/python3",
            "scripts/collect_program_inventory.py",
            "--observation-id",
            OBS_ID,
            "--observed-at",
            OBSERVED,
            "--output-dir",
            str(self.raw_dir),
        ]
        renderer_argv = [
            "/usr/bin/python3",
            "scripts/generate_program_inventory.py",
            "--raw-dir",
            str(self.raw_dir),
            "--summary-out",
            str(self.root / "runtime/program-inventory-summary.md"),
            "--json-out",
            str(self.root / "runtime/program-inventory.v1.json"),
            "--generated-at",
            GENERATED,
        ]
        return (
            execution_receipt("1" * 24, software_argv, RECEIPT_A, cwd=self.root),
            execution_receipt("2" * 24, program_argv, RECEIPT_B, cwd=self.root),
            execution_receipt("3" * 24, renderer_argv, "e" * 64, cwd=self.root),
        )

    def binding(self):
        software_receipt, program_receipt, renderer_receipt = self.execution_receipts()
        return build_current_binding(
            root=self.root,
            contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
            source_revision=self.revision,
            observation_id=OBS_ID,
            started_at=START,
            completed_at=DONE,
            software_execution_receipt=software_receipt,
            program_execution_receipt=program_receipt,
            program_renderer_execution_receipt=renderer_receipt,
        )

    def _reissue_renderer_at(self, generated_at: str) -> None:
        # Reissue a coherent test-only lifecycle receipt and ledger entry to
        # exercise timestamps beyond simple forged-argv rejection.
        receipt = self._receipts[2]
        receipt["argv"][-1] = generated_at
        receipt["argv_sha256"] = argv_sha(receipt["argv"])
        subprocess.run(receipt["argv"], cwd=self.root, check=True)
        task_id = receipt["task_id"]
        path = self.task_state_root / "tasks.outcomes" / f"{task_id}.json"
        outcome = json.loads(path.read_text(encoding="utf-8"))
        outcome["argv_sha256"] = receipt["argv_sha256"]
        outcome.pop("receipt_sha256")
        digest = sha(json.dumps(outcome, sort_keys=True, separators=(",", ":")).encode())
        outcome["receipt_sha256"] = digest
        path.write_text(json.dumps(outcome, sort_keys=True), encoding="utf-8")
        receipt["lifecycle_receipt_sha256"] = digest
        with closing(sqlite3.connect(self.task_db)) as db:
            db.execute(
                "UPDATE tasks SET argv_json = ?, argv_sha256 = ?, "
                "lifecycle_receipt_sha256 = ? WHERE task_id = ?",
                (json.dumps(receipt["argv"]), receipt["argv_sha256"], digest, task_id),
            )
            db.commit()

    def _reseal_software_receipt_field(self, field: str, value: str | int) -> None:
        task_id = "1" * 24
        path = self.task_state_root / "tasks.outcomes" / f"{task_id}.json"
        outcome = json.loads(path.read_text(encoding="utf-8"))
        outcome[field] = value
        outcome.pop("receipt_sha256")
        digest = sha(json.dumps(outcome, sort_keys=True, separators=(",", ":")).encode())
        outcome["receipt_sha256"] = digest
        path.write_text(json.dumps(outcome, sort_keys=True), encoding="utf-8")
        self._receipts[0]["lifecycle_receipt_sha256"] = digest
        with closing(sqlite3.connect(self.task_db)) as db:
            db.execute(
                "UPDATE tasks SET lifecycle_receipt_sha256 = ? WHERE task_id = ?",
                (digest, task_id),
            )
            db.commit()

    def test_builds_fail_closed_binding(self):
        result = self.binding()
        self.assertEqual(result["host"], "heim-pc")
        self.assertEqual(result["source_revision"], self.revision)
        self.assertEqual(result["observation"]["id"], OBS_ID)
        self.assertEqual(len(result["outputs"]), 3)
        self.assertEqual(
            result["provenance"]["software"]["execution_receipt_sha256"],
            self._receipts[0]["lifecycle_receipt_sha256"],
        )
        self.assertEqual(
            result["provenance"]["program"]["execution_receipt_sha256"],
            self._receipts[1]["lifecycle_receipt_sha256"],
        )
        self.assertEqual(
            result["provenance"]["program"]["raw_manifest_sha256"], self.raw_digest
        )
        self.assertEqual(
            result["provenance"]["software"]["execution"]["task_id"], "1" * 24
        )
        self.assertEqual(
            result["provenance"]["program"]["execution"]["task_id"], "2" * 24
        )

    def test_rejects_output_outside_session(self):
        path = self.root / "runtime/software-inventory.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                OBSERVED, "2026-10-07T14:59:59Z"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(Day1EvidenceError, "outside observation session"):
            self.binding()

    def test_rejects_wrong_host(self):
        path = self.root / "runtime/program-inventory.v1.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["collection_provenance"]["host"] = "commonserver"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(Day1EvidenceError, "not authoritative"):
            self.binding()

    def test_rejects_modified_collector(self):
        (self.root / "scripts/collect_program_inventory.py").write_text(
            "print('changed')\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(Day1EvidenceError, "does not match reviewed source"):
            self.binding()

    def test_rejects_modified_contract_schema(self):
        path = self.root / "nixos/production/day1-workload-parity-contract-v1.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["inventory"]["authoritative_host"] = "commonserver"
        path.write_text(json.dumps(payload), encoding="utf-8")
        result = self.binding()
        evidence = self.root / "nixos/production/day1-workload-parity-current-evidence-v1.json"
        with self.assertRaisesRegex(Day1EvidenceError, "neither the reviewed preimage"):
            write_evidence(
                root=self.root,
                contract_path=path,
                evidence_path=evidence,
                binding=result,
                update_contract=True,
            )
        self.assertFalse(evidence.exists())

    def test_rejects_unbound_observation_argv(self):
        software_receipt, program_receipt, renderer_receipt = self.execution_receipts()
        software_receipt["argv"][3] = "e" * 64
        software_receipt["argv_sha256"] = argv_sha(software_receipt["argv"])
        with self.assertRaisesRegex(Day1EvidenceError, "does not bind --observation-id"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt=software_receipt,
                program_execution_receipt=program_receipt,
                program_renderer_execution_receipt=renderer_receipt,
            )

    def test_rejects_script_name_only_as_nonexecuted_argument(self):
        software_receipt, program_receipt, renderer_receipt = self.execution_receipts()
        software_receipt["argv"] = [
            "/usr/bin/python3",
            "-c",
            "print('not the collector')",
            "scripts/generate_software_inventory.py",
            "--observation-id",
            OBS_ID,
            "--observed-at",
            OBSERVED,
        ]
        software_receipt["argv_sha256"] = argv_sha(software_receipt["argv"])
        with self.assertRaisesRegex(Day1EvidenceError, "must execute /usr/bin/python3"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt=software_receipt,
                program_execution_receipt=program_receipt,
                program_renderer_execution_receipt=renderer_receipt,
            )

    def test_rejects_execution_receipt_argv_hash_mismatch(self):
        software_receipt, program_receipt, renderer_receipt = self.execution_receipts()
        software_receipt["argv_sha256"] = "f" * 64
        with self.assertRaisesRegex(Day1EvidenceError, "does not authenticate argv"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt=software_receipt,
                program_execution_receipt=program_receipt,
                program_renderer_execution_receipt=renderer_receipt,
            )

    def test_rejects_noncompleted_execution_receipt(self):
        software_receipt, program_receipt, renderer_receipt = self.execution_receipts()
        software_receipt["state"] = "failed"
        with self.assertRaisesRegex(Day1EvidenceError, "not terminal successful"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt=software_receipt,
                program_execution_receipt=program_receipt,
                program_renderer_execution_receipt=renderer_receipt,
            )

    def test_rejects_renderer_bound_to_different_raw_run(self):
        software_receipt, program_receipt, renderer_receipt = self.execution_receipts()
        other = self.root / "other-raw-run"
        other.mkdir()
        raw_index = renderer_receipt["argv"].index("--raw-dir") + 1
        renderer_receipt["argv"][raw_index] = str(other)
        renderer_receipt["argv_sha256"] = argv_sha(renderer_receipt["argv"])
        with self.assertRaisesRegex(Day1EvidenceError, "does not bind --raw-dir"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt=software_receipt,
                program_execution_receipt=program_receipt,
                program_renderer_execution_receipt=renderer_receipt,
            )

    def test_rejects_tampered_raw_run(self):
        (self.raw_dir / "a.txt").write_bytes(b"changed")
        with self.assertRaisesRegex(Day1EvidenceError, "raw manifest"):
            self.binding()

    def test_rejects_manually_modified_rendered_output(self):
        path = self.root / "runtime/program-inventory.v1.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["manual_override"] = True
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(Day1EvidenceError, "deterministic render"):
            self.binding()

    def test_rejects_renderer_generation_before_observation(self):
        self._reissue_renderer_at("2000-01-01T00:00:00Z")
        with self.assertRaisesRegex(Day1EvidenceError, "generated_at falls outside"):
            self.binding()

    def test_rejects_renderer_generation_before_program_collection_finished(self):
        self._reissue_renderer_at("2026-10-07T15:00:10Z")
        with self.assertRaisesRegex(Day1EvidenceError, "predates completed authenticated"):
            self.binding()

    def test_rejects_renderer_generation_before_renderer_task_start(self):
        # The collector has already completed, but Grabowski did not yet
        # create the renderer task. A declared render time is not evidence.
        self._reissue_renderer_at("2026-10-07T15:00:18Z")
        with self.assertRaisesRegex(Day1EvidenceError, "predates authenticated renderer task start"):
            self.binding()

    def test_rejects_fake_observation_window_around_stale_tasks(self):
        receipts = self.execution_receipts()
        # The inventory timestamps still lie inside the *claimed* short
        # session, but the actual collector and renderer completed later.
        with self.assertRaisesRegex(Day1EvidenceError, "outside bounded observation session"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at="2026-10-07T15:00:21Z",
                software_execution_receipt=receipts[0],
                program_execution_receipt=receipts[1],
                program_renderer_execution_receipt=receipts[2],
            )

    def test_rejects_unordered_collector_and_renderer_tasks(self):
        with closing(sqlite3.connect(self.task_db)) as db:
            db.execute(
                "UPDATE tasks SET created_at_unix = ? WHERE task_id = ?",
                (1791385202, "2" * 24),
            )
            db.commit()
        with self.assertRaisesRegex(Day1EvidenceError, "not serially ordered"):
            self.binding()

    def test_rejects_forged_lifecycle_digest(self):
        receipts = self.execution_receipts()
        receipts[0]["lifecycle_receipt_sha256"] = "f" * 64
        with self.assertRaisesRegex(Day1EvidenceError, "authoritative Grabowski ledger"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt=receipts[0],
                program_execution_receipt=receipts[1],
                program_renderer_execution_receipt=receipts[2],
            )

    def test_rejects_missing_authoritative_task(self):
        with closing(sqlite3.connect(self.task_db)) as db:
            db.execute("DELETE FROM tasks WHERE task_id = ?", ("1" * 24,))
            db.commit()
        with self.assertRaisesRegex(Day1EvidenceError, "absent from authoritative"):
            self.binding()

    def test_rejects_tampered_lifecycle_receipt(self):
        outcome_path = (
            self.task_state_root / "tasks.outcomes" / ("1" * 24 + ".json")
        )
        v = json.loads(outcome_path.read_text())
        v["state"] = "failed"
        outcome_path.write_text(json.dumps(v), encoding="utf-8")
        with self.assertRaisesRegex(Day1EvidenceError, "lifecycle receipt mismatch"):
            self.binding()

    def test_rejects_rewritten_same_uid_stdout_capture(self):
        path = self.root / "runtime/software-inventory.md"
        path.write_text(path.read_text() + "fabricated workload\n", encoding="utf-8")
        report = {
            "kind": "heim_pc.software_inventory_output",
            "host": "heim-pc",
            "observed_at": OBSERVED,
            "observation_id": OBS_ID,
            "output_sha256": sha(path.read_bytes()),
        }
        stdout = (
            self.task_state_root / "task-output"
            / f".grabowski-task-output-{'1' * 24}-a1" / "stdout.log"
        )
        stdout.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(Day1EvidenceError, "captured stdout differs"):
            self.binding()

    def test_rejects_legacy_unsealed_lifecycle_receipt(self):
        task_id = "1" * 24
        path = self.task_state_root / "tasks.outcomes" / f"{task_id}.json"
        outcome = json.loads(path.read_text())
        outcome.pop("captured_stdout_sha256")
        outcome.pop("captured_stdout_bytes")
        outcome.pop("receipt_sha256")
        digest = sha(json.dumps(outcome, sort_keys=True, separators=(",", ":")).encode())
        outcome["receipt_sha256"] = digest
        path.write_text(json.dumps(outcome, sort_keys=True), encoding="utf-8")
        with closing(sqlite3.connect(self.task_db)) as db:
            db.execute(
                "UPDATE tasks SET lifecycle_receipt_sha256 = ? WHERE task_id = ?",
                (digest, task_id),
            )
            db.commit()
        self._receipts[0]["lifecycle_receipt_sha256"] = digest
        with self.assertRaisesRegex(Day1EvidenceError, "lacks terminally sealed"):
            self.binding()

    def test_rejects_incorrect_sealed_stdout_digest(self):
        self._reseal_software_receipt_field("captured_stdout_sha256", "f" * 64)
        with self.assertRaisesRegex(Day1EvidenceError, "captured stdout differs"):
            self.binding()

    def test_rejects_incorrect_sealed_stdout_byte_count(self):
        task_id = "1" * 24
        stdout = (
            self.task_state_root / "task-output"
            / f".grabowski-task-output-{task_id}-a1" / "stdout.log"
        )
        self._reseal_software_receipt_field(
            "captured_stdout_bytes", stdout.stat().st_size + 1
        )
        with self.assertRaisesRegex(Day1EvidenceError, "captured stdout differs"):
            self.binding()

    def test_rejects_swapped_software_after_authenticated_snapshot(self):
        software = self.root / "runtime/software-inventory.md"
        read_snapshot = binder._snapshot_output_bytes
        swapped = [False]

        def swap_after_snapshot(path):
            captured = read_snapshot(path)
            if path == software and not swapped[0]:
                swapped[0] = True
                software.write_text(
                    software.read_text(encoding="utf-8") + "fabricated service\\n",
                    encoding="utf-8",
                )
            return captured

        with patch.object(binder, "_snapshot_output_bytes", side_effect=swap_after_snapshot):
            with self.assertRaisesRegex(Day1EvidenceError, "changed after verified snapshot"):
                self.binding()
        self.assertTrue(swapped[0])

    def test_rejects_swapped_program_json_after_snapshot(self):
        program = self.root / "runtime/program-inventory.v1.json"
        read_snapshot = binder._snapshot_output_bytes
        swapped = [False]

        def swap_after_snapshot(path):
            captured = read_snapshot(path)
            if path == program and not swapped[0]:
                swapped[0] = True
                program.write_bytes(captured + b" ")
            return captured

        with patch.object(binder, "_snapshot_output_bytes", side_effect=swap_after_snapshot):
            with self.assertRaisesRegex(Day1EvidenceError, "changed after verified snapshot"):
                self.binding()
        self.assertTrue(swapped[0])

    def test_rejects_modified_software_output_after_collection(self):
        path = self.root / "runtime/software-inventory.md"
        path.write_text(path.read_text() + "fabricated: service\n", encoding="utf-8")
        with self.assertRaisesRegex(Day1EvidenceError, "authenticated collector output"):
            self.binding()

    def test_rejects_modified_run_result_counters(self):
        path = self.raw_dir / "run-result.json"
        run = json.loads(path.read_text())
        run["process_rows"] = 100000
        path.write_text(json.dumps(run), encoding="utf-8")
        with self.assertRaisesRegex(Day1EvidenceError, "authenticated collector output"):
            self.binding()

    def test_rejects_noop_help_software(self):
        receipts = self.execution_receipts()
        receipts[0]["argv"].insert(2, "--help")
        receipts[0]["argv_sha256"] = argv_sha(receipts[0]["argv"])
        with self.assertRaisesRegex(Day1EvidenceError, "complete allowed command shape"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt=receipts[0],
                program_execution_receipt=receipts[1],
                program_renderer_execution_receipt=receipts[2],
            )

    def test_rejects_noop_help_renderer(self):
        receipts = self.execution_receipts()
        receipts[2]["argv"].insert(2, "-h")
        receipts[2]["argv_sha256"] = argv_sha(receipts[2]["argv"])
        with self.assertRaisesRegex(Day1EvidenceError, "complete allowed command shape"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt=receipts[0],
                program_execution_receipt=receipts[1],
                program_renderer_execution_receipt=receipts[2],
            )

    def test_write_evidence_rejects_path_outside_repository(self):
        result = self.binding()
        contract = self.root / "nixos/production/day1-workload-parity-contract-v1.json"
        with tempfile.TemporaryDirectory() as other:
            evidence = Path(other) / "evidence.json"
            with self.assertRaisesRegex(Day1EvidenceError, "inside repository root"):
                write_evidence(
                    root=self.root,
                    contract_path=contract,
                    evidence_path=evidence,
                    binding=result,
                    update_contract=False,
                )
            self.assertFalse(evidence.exists())

    def test_write_evidence_refuses_different_existing_binding(self):
        result = self.binding()
        evidence = (
            self.root
            / "nixos/production/day1-workload-parity-current-evidence-v1.json"
        )
        contract = self.root / "nixos/production/day1-workload-parity-contract-v1.json"
        payload = json.loads(contract.read_text(encoding="utf-8"))
        payload["inventory"]["current_binding"] = {"source_revision": "f" * 40}
        contract.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(Day1EvidenceError, "neither the reviewed preimage"):
            write_evidence(
                root=self.root,
                contract_path=contract,
                evidence_path=evidence,
                binding=result,
                update_contract=True,
            )
        self.assertFalse(evidence.exists())

    def test_write_evidence_rejects_modified_output_after_binding(self):
        result = self.binding()
        software = self.root / "runtime/software-inventory.md"
        software.write_text(
            software.read_text(encoding="utf-8") + "late injection\\n",
            encoding="utf-8",
        )
        evidence = (
            self.root / "nixos/production/day1-workload-parity-current-evidence-v1.json"
        )
        contract = self.root / "nixos/production/day1-workload-parity-contract-v1.json"
        with self.assertRaisesRegex(Day1EvidenceError, "changed before evidence publication"):
            write_evidence(
                root=self.root,
                contract_path=contract,
                evidence_path=evidence,
                binding=result,
                update_contract=True,
            )
        self.assertFalse(evidence.exists())
        self.assertIsNone(json.loads(contract.read_text())["inventory"]["current_binding"])

    def test_write_evidence_keeps_readiness_blocked(self):
        result = self.binding()
        evidence = (
            self.root
            / "nixos/production/day1-workload-parity-current-evidence-v1.json"
        )
        contract = self.root / "nixos/production/day1-workload-parity-contract-v1.json"
        write_evidence(
            root=self.root,
            contract_path=contract,
            evidence_path=evidence,
            binding=result,
            update_contract=True,
        )
        stored = json.loads(evidence.read_text(encoding="utf-8"))
        updated = json.loads(contract.read_text(encoding="utf-8"))
        self.assertIs(stored["readiness_authorized"], False)
        self.assertIs(stored["classification_complete"], False)
        self.assertEqual(updated["inventory"]["current_binding"], result)
        self.assertEqual(
            updated["admission"]["current_status"],
            "blocked-until-day1-classification-and-acceptance",
        )

        write_evidence(
            root=self.root,
            contract_path=contract,
            evidence_path=evidence,
            binding=result,
            update_contract=True,
        )
        self.assertEqual(
            json.loads(contract.read_text(encoding="utf-8")),
            updated,
        )
        self.assertEqual(
            json.loads(evidence.read_text(encoding="utf-8")),
            stored,
        )


if __name__ == "__main__":
    unittest.main()