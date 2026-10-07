from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.nixos_day1_workload_parity_evidence import (
    Day1EvidenceError,
    build_current_binding,
    write_evidence,
)


OBS_ID = "a" * 64
START = "2026-10-07T15:00:00Z"
OBSERVED = "2026-10-07T15:00:05Z"
DONE = "2026-10-07T15:00:30Z"
RECEIPT_A = "b" * 64
RECEIPT_B = "c" * 64


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        renderer_script = b"print('render')\n"
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
        (root / "runtime/program-inventory-summary.md").write_text(
            "\n".join(
                [
                    "---",
                    f'observed_at: "{OBSERVED}"',
                    f'observation_id: "{OBS_ID}"',
                    "binding_eligible: true",
                    "---",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (root / "runtime/program-inventory.v1.json").write_text(
            json.dumps(
                {
                    "observation_scope": {
                        "observed_at": OBSERVED,
                        "observation_id": OBS_ID,
                        "binding_eligible": True,
                    },
                    "collection_provenance": {
                        "host": "heim-pc",
                        "collector_sha256": sha(collector_script),
                        "raw_manifest_sha256": "d" * 64,
                        "raw_artifact_count": 7,
                    },
                }
            ),
            encoding="utf-8",
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

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def binding(self):
        return build_current_binding(
            root=self.root,
            contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
            source_revision=self.revision,
            observation_id=OBS_ID,
            started_at=START,
            completed_at=DONE,
            software_execution_receipt_sha256=RECEIPT_A,
            software_argv=[
                "python3",
                "scripts/generate_software_inventory.py",
                "--observation-id",
                OBS_ID,
                "--observed-at",
                OBSERVED,
            ],
            program_execution_receipt_sha256=RECEIPT_B,
            program_argv=[
                "python3",
                "scripts/collect_program_inventory.py",
                "--observation-id",
                OBS_ID,
                "--observed-at",
                OBSERVED,
            ],
        )

    def test_builds_fail_closed_binding(self):
        result = self.binding()
        self.assertEqual(result["host"], "heim-pc")
        self.assertEqual(result["source_revision"], self.revision)
        self.assertEqual(result["observation"]["id"], OBS_ID)
        self.assertEqual(len(result["outputs"]), 3)
        self.assertEqual(
            result["provenance"]["software"]["execution_receipt_sha256"], RECEIPT_A
        )
        self.assertEqual(
            result["provenance"]["program"]["execution_receipt_sha256"], RECEIPT_B
        )
        self.assertEqual(
            result["provenance"]["program"]["raw_manifest_sha256"], "d" * 64
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
        with self.assertRaisesRegex(Day1EvidenceError, "does not bind observation_id"):
            build_current_binding(
                root=self.root,
                contract_path=self.root / "nixos/production/day1-workload-parity-contract-v1.json",
                source_revision=self.revision,
                observation_id=OBS_ID,
                started_at=START,
                completed_at=DONE,
                software_execution_receipt_sha256=RECEIPT_A,
                software_argv=[
                    "python3",
                    "scripts/generate_software_inventory.py",
                    "--observation-id",
                    "e" * 64,
                    "--observed-at",
                    OBSERVED,
                    OBS_ID,
                ],
                program_execution_receipt_sha256=RECEIPT_B,
                program_argv=[
                    "python3",
                    "scripts/collect_program_inventory.py",
                    "--observation-id",
                    OBS_ID,
                    "--observed-at",
                    OBSERVED,
                ],
            )

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
