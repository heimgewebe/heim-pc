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

PROTECTED_REF = (
    "nixos/nix@sha256:"
    "7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c"
)


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
            "protected_image_refs": [PROTECTED_REF],
            "volume_prune_authorized": False,
            "named_volumes_preserved": True,
            "max_output_bytes_per_command": 32768,
            "command_timeout_seconds": 900,
            "max_receipts": 8,
        }
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")

    def tearDown(self) -> None:
        self.context.cleanup()

    @staticmethod
    def command_result(argv: list[str], returncode: int = 0) -> dict[str, object]:
        return {
            "argv": list(argv),
            "returncode": returncode,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    def test_plan_contains_no_volume_command(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        flattened = [token for argv in plan["commands"] for token in argv]
        self.assertNotIn("volume", flattened)
        self.assertEqual(
            [argv[1] for argv in plan["commands"]],
            ["container", "image", "builder", "network"],
        )
        self.assertEqual(plan["protected_image_refs"], [PROTECTED_REF])
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

    def test_policy_rejects_unpinned_protected_image_ref(self) -> None:
        value = dict(self.policy)
        value["protected_image_refs"] = ["nixos/nix:2.35.2"]
        self.policy_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(
            hygiene.DockerHygieneError, "protected-image contract"
        ):
            hygiene.load_policy(self.policy_path)

    def test_policy_rejects_duplicate_protected_image_ref(self) -> None:
        value = dict(self.policy)
        value["protected_image_refs"] = [PROTECTED_REF, PROTECTED_REF]
        self.policy_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(
            hygiene.DockerHygieneError, "protected-image contract"
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

    def test_apply_protects_image_only_while_image_prune_runs(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        state = self.base / "state"
        calls: list[list[str]] = []

        def run(argv: list[str], _policy: dict[str, object]) -> dict[str, object]:
            calls.append(list(argv))
            return self.command_result(argv)

        with patch.object(hygiene, "run_command", side_effect=run):
            receipt = hygiene.apply(plan, policy, state)

        create_index = next(
            index
            for index, argv in enumerate(calls)
            if argv[1:3] == ["container", "create"]
        )
        prune_index = calls.index(plan["commands"][1])
        remove_index = next(
            index
            for index, argv in enumerate(calls)
            if argv[1:3] == ["container", "rm"]
        )
        self.assertLess(create_index, prune_index)
        self.assertLess(prune_index, remove_index)
        self.assertIn("--pull=never", calls[create_index])
        self.assertEqual(receipt["image_protection"][0]["status"], "released")
        self.assertTrue(receipt["protected_images_ready"])
        self.assertTrue(receipt["protected_images_released"])
        self.assertTrue(receipt["success"])

    def test_apply_skips_image_prune_when_protected_image_is_missing(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        state = self.base / "state"
        calls: list[list[str]] = []

        def run(argv: list[str], _policy: dict[str, object]) -> dict[str, object]:
            calls.append(list(argv))
            return self.command_result(
                argv, 1 if argv[1:3] == ["image", "inspect"] else 0
            )

        with patch.object(hygiene, "run_command", side_effect=run):
            receipt = hygiene.apply(plan, policy, state)

        self.assertNotIn(plan["commands"][1], calls)
        self.assertTrue(receipt["commands"][1]["skipped"])
        self.assertEqual(
            receipt["commands"][1]["reason"], "protected_image_unavailable"
        )
        self.assertFalse(receipt["protected_images_ready"])
        self.assertFalse(receipt["success"])

    def test_apply_releases_protection_after_image_prune_failure(self) -> None:
        policy = hygiene.load_policy(self.policy_path)
        plan = hygiene.plan(policy, "/usr/bin/docker")
        state = self.base / "state"
        calls: list[list[str]] = []

        def run(argv: list[str], _policy: dict[str, object]) -> dict[str, object]:
            calls.append(list(argv))
            return self.command_result(argv, 1 if argv == plan["commands"][1] else 0)

        with patch.object(hygiene, "run_command", side_effect=run):
            receipt = hygiene.apply(plan, policy, state)

        self.assertTrue(
            any(argv[1:3] == ["container", "rm"] for argv in calls)
        )
        self.assertEqual(receipt["image_protection"][0]["status"], "released")
        self.assertTrue(receipt["protected_images_released"])
        self.assertFalse(receipt["success"])

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
            side_effect=lambda argv, _policy: self.command_result(argv),
        ):
            receipt = hygiene.apply(plan, policy, state)
        self.assertTrue(receipt["success"])
        self.assertFalse(receipt["volume_prune_executed"])
        self.assertTrue(receipt["named_volumes_preserved"])
        self.assertTrue((state / f"{receipt['completed_at_unix']}.json").is_file())


if __name__ == "__main__":
    unittest.main()
