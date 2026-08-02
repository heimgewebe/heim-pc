from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "docker_storage_hygiene", ROOT / "scripts" / "docker_storage_hygiene.py"
)
assert SPEC and SPEC.loader
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


class DockerStorageHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = tempfile.TemporaryDirectory(prefix="docker-hygiene-")
        self.base = Path(self.context.name)
        self.policy_path = self.base / "policy.json"
        self.policy = {
            "schema_version": 1,
            "kind": "heim_pc.docker_storage_hygiene_policy",
            "minimum_unused_age_hours": 168,
            "automatic_gc_authorized": True,
            "operations": ["container", "image", "builder", "network"],
            "volume_prune_authorized": False,
            "named_volumes_preserved": True,
            "max_output_bytes_per_command": 32768,
            "command_timeout_seconds": 900,
            "max_receipts": 8,
        }
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")

    def tearDown(self) -> None:
        self.context.cleanup()

    def test_plan_contains_no_volume_command(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        flattened = [token for argv in plan["commands"] for token in argv]
        self.assertNotIn("volume", flattened)
        self.assertEqual(
            [argv[1] for argv in plan["commands"]],
            ["container", "image", "builder", "network"],
        )
        self.assertFalse(plan["volume_prune_authorized"])
        self.assertTrue(plan["named_volumes_preserved"])

    def test_policy_rejects_volume_authority(self) -> None:
        value = dict(self.policy)
        value["volume_prune_authorized"] = True
        self.policy_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(
            hygiene.DockerHygieneError, "volume-preservation contract"
        ):
            hygiene.load_policy(self.policy_path)

    def test_apply_rejects_modified_plan(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        plan["commands"].append(["/usr/bin/docker", "volume", "prune", "-f"])
        with self.assertRaisesRegex(hygiene.DockerHygieneError, "plan hash"):
            hygiene.apply(plan, policy, self.base / "state")

    def test_apply_rejects_rehashed_plan_that_differs_from_policy(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        plan["commands"][0][-1] = "until=1h"
        material = dict(plan)
        material.pop("plan_sha256")
        plan["plan_sha256"] = hygiene.digest(material)
        with self.assertRaisesRegex(hygiene.DockerHygieneError, "current policy"):
            hygiene.apply(plan, policy, self.base / "state")

    def test_apply_rejects_invalid_command_shape(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        plan["commands"] = []
        material = dict(plan)
        material.pop("plan_sha256")
        plan["plan_sha256"] = hygiene.digest(material)
        with self.assertRaisesRegex(hygiene.DockerHygieneError, "command shape"):
            hygiene.apply(plan, policy, self.base / "state")

    def test_state_directory_rejects_symlink(self) -> None:
        target = self.base / "target"
        target.mkdir()
        link = self.base / "state-link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(hygiene.DockerHygieneError, "state directory"):
            hygiene.ensure_state_directory(link)

    def test_receipt_preserves_volume_invariant(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        state = self.base / "state"
        with patch.object(
            hygiene,
            "run_command",
            return_value={"argv": ["docker"], "returncode": 0, "stdout": "", "stderr": ""},
        ):
            receipt = hygiene.apply(plan, policy, state)
        self.assertTrue(receipt["success"])
        self.assertFalse(receipt["volume_prune_executed"])
        self.assertTrue(receipt["named_volumes_preserved"])
        self.assertTrue((state / f"{receipt['completed_at_unix']}.json").is_file())


if __name__ == "__main__":
    unittest.main()
