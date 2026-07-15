from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load("operator_entry_checker", "scripts/check_operator_entry.py")
installer = _load("operator_entry_installer", "scripts/install_operator_entry.py")


class OperatorEntryTests(unittest.TestCase):
    def test_canonical_contract_is_machine_first_static_and_host_template_based(self) -> None:
        contract = json.loads((ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["kind"], "heim_pc_operator_entry")
        self.assertEqual(contract["operatorModel"]["operator"], "chatgpt_via_grabowski")
        self.assertEqual(contract["operatorModel"]["humanRole"], "meaning_approval_abort")
        self.assertTrue(contract["operatorModel"]["machineFirst"])
        self.assertEqual(contract["host"]["role"], "primary_local_operator_host")
        self.assertEqual(contract["host"]["installedEntryFile"], "${HOME}/.config/heimgewebe/operator-entry.v1.json")
        self.assertEqual(contract["host"]["repositoriesAgentPointer"], "${HOME}/repos/AGENTS.md")
        policy = contract["transferPolicy"]
        self.assertEqual(policy["principle"], "role_based_dual_transport")
        self.assertEqual(policy["sharedExchangeTransport"], "icloudSharedExchange")
        self.assertEqual(policy["directDeliveryTransport"], "taildropDirectDelivery")
        self.assertEqual(policy["selectionRules"]["sharedPersistentWorkspace"], "icloudSharedExchange")
        self.assertEqual(policy["selectionRules"]["directOneShotDelivery"], "taildropDirectDelivery")
        self.assertEqual(policy["selectionRules"]["largeOrSensitiveDelivery"], "taildropDirectDelivery")
        self.assertTrue(set(policy["selectionRules"].values()).issubset(contract["transferPaths"]))
        self.assertNotEqual(policy["sharedExchangeTransport"], policy["directDeliveryTransport"])

        shared = contract["transferPaths"]["icloudSharedExchange"]
        self.assertEqual(shared["role"], "shared_exchange")
        self.assertEqual(shared["canonicalDirectory"], "${HOME}/iCloud/Drive/halde")
        self.assertEqual(shared["transport"], "icloud_drive")
        self.assertEqual(shared["direction"], "bidirectional")
        self.assertEqual(shared["endpoints"], ["heim_pc", "ipad"])
        self.assertIn("icloud_sync_completed_on_heim_pc", shared["doesNotEstablish"])
        self.assertIn("icloud_sync_completed_on_ipad", shared["doesNotEstablish"])
        self.assertNotIn("fallbackTransport", shared)

        direct = contract["transferPaths"]["taildropDirectDelivery"]
        self.assertEqual(direct["role"], "direct_delivery")
        self.assertEqual(direct["transport"], "tailscale_taildrop")
        self.assertEqual(direct["direction"], "bidirectional")
        self.assertEqual(direct["endpoints"], ["heim_pc", "ipad"])
        self.assertEqual(direct["heimPcInbox"], "${HOME}/Incoming/Taildrop")
        self.assertEqual(direct["heimPcSendCommand"], "${HOME}/.local/bin/heim-taildrop-send")
        self.assertEqual(direct["ipadTarget"], "ipad-10th-gen-wifi")
        self.assertEqual(direct["fileManagerDiscovery"]["kind"], "gtk_favorite")
        self.assertEqual(direct["fileManagerDiscovery"]["target"], "${HOME}/Incoming/Taildrop")
        self.assertEqual(direct["fileManagerDiscovery"]["management"], "user_managed")
        self.assertNotIn("heimPcAndIPad", contract["transferPaths"])
        self.assertNotIn("heimPcToIPad", contract["transferPaths"])
        managed = contract["managedBuilds"]
        self.assertEqual(managed["policy"], "${HOME}/repos/heim-pc/config/managed-build.v1.json")
        self.assertEqual(
            managed["entryArgv"],
            ["python3", "${HOME}/repos/heim-pc/scripts/managed_build.py"],
        )
        self.assertEqual(managed["automationRule"], "operator_managed_builds_use_entry")
        self.assertEqual(managed["interactiveShellBehavior"], "unchanged")
        self.assertEqual(managed["worktreeWarningBytes"], 2 * 1024**3)
        self.assertEqual(managed["worktreeHardBytes"], 5 * 1024**3)
        self.assertFalse(managed["automaticCleanupAuthorized"])
        self.assertIn(
            "permission_to_delete_worktree_or_cache_payloads",
            managed["doesNotEstablish"],
        )
        entry_ids = {item["id"] for item in contract["entrySequence"]}
        self.assertIn("operator_context", entry_ids)
        self.assertIn("target_specific_live_state", entry_ids)
        self.assertIn("stableEcosystemSemantics", contract["truthSources"])
        self.assertIn("executionRuntimeLeases", contract["truthSources"])
        excluded = {item["path"] for item in contract["sourcePolicy"]["excludedAsCurrentTruth"]}
        self.assertIn("${HOME}/repos/heim-pc/state/index.json", excluded)
        self.assertIn("${HOME}/repos/heim-pc/state/repos.json", excluded)
        self.assertEqual(contract["pathResolution"]["variables"]["HOME"]["source"], "operator_process_home")
        self.assertFalse(contract["pathResolution"]["publicTemplateContainsResolvedHostPath"])
        self.assertNotIn("/home/", json.dumps(contract, ensure_ascii=False))
        self.assertNotIn("runtimeHealth", contract)
        self.assertNotIn("taskPriority", contract)
        self.assertIn(
            "protection_against_adversarial_parent_directory_replacement",
            contract["doesNotEstablish"],
        )

    def test_ai_context_routes_to_operator_entry(self) -> None:
        ai_context = (ROOT / ".ai-context.yml").read_text(encoding="utf-8")
        self.assertIn("role: operator-entry", ai_context)
        self.assertIn("canonical_entry: manifest/operator-entry.v1.json", ai_context)
        self.assertIn("kind: chatgpt_via_grabowski", ai_context)
        self.assertIn("machine_first: true", ai_context)

    def test_checker_accepts_canonical_source_without_installed_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = checker.check(home=Path(directory), require_installed=False)
        self.assertTrue(receipt["valid"], receipt["errors"])
        self.assertFalse(receipt["projection"]["contract"]["exists"])

    def test_checker_rejects_managed_build_cleanup_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            contract["managedBuilds"]["automaticCleanupAuthorized"] = True
            contract_path = tmp_path / "operator-entry.v1.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            policy_path = ROOT / "config/managed-build.v1.json"
            with (
                patch.object(checker, "CONTRACT_PATH", contract_path),
                patch.object(checker, "MANAGED_BUILD_POLICY_PATH", policy_path),
            ):
                receipt = checker.check(home=tmp_path, require_installed=False)
            self.assertFalse(receipt["valid"])
            self.assertIn(
                "managedBuilds.automaticCleanupAuthorized must remain false",
                receipt["errors"],
            )

    def test_installer_plan_has_no_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            receipt = installer.install(home=home, apply=False)
            self.assertEqual(receipt["kind"], "heim_pc_operator_entry_install_plan")
            self.assertFalse(receipt["apply"])
            self.assertTrue(all(item["action"] == "install" for item in receipt["files"]))
            self.assertFalse((home / "AGENTS.md").exists())
            self.assertFalse((home / "repos/AGENTS.md").exists())
            self.assertFalse((home / ".config/heimgewebe/operator-entry.v1.json").exists())

    def test_installer_blocks_unreviewed_replacement_then_backs_up_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            old_readme = b"old home overview\n"
            (home / "README.md").write_bytes(old_readme)

            plan = installer.install(home=home, apply=False)
            self.assertTrue(plan["requiresReplaceExisting"])
            with self.assertRaises(installer.InstallConflict):
                installer.install(home=home, apply=True)

            first = installer.install(home=home, apply=True, replace_existing=True)
            second = installer.install(home=home, apply=True)

            first_readme = next(item for item in first["files"] if item["target"].endswith("/README.md"))
            self.assertEqual(first_readme["action"], "install")
            self.assertTrue(first_readme["requiresReplacement"])
            self.assertIsNotNone(first_readme["backup"])
            backup = Path(first_readme["backup"])
            self.assertEqual(backup.read_bytes(), old_readme)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertTrue(all(item["action"] == "unchanged" for item in second["files"]))
            self.assertEqual((home / "AGENTS.md").read_bytes(), (ROOT / "config/agents/home-AGENTS.md").read_bytes())
            self.assertEqual(
                (home / "repos/AGENTS.md").read_bytes(),
                (ROOT / "config/agents/repos-root-AGENTS.md").read_bytes(),
            )
            self.assertEqual((home / "README.md").read_bytes(), (ROOT / "config/agents/home-README.md").read_bytes())
            self.assertEqual(
                (home / ".config/heimgewebe/operator-entry.v1.json").read_bytes(),
                (ROOT / "manifest/operator-entry.v1.json").read_bytes(),
            )
            self.assertEqual(stat.S_IMODE((home / "AGENTS.md").stat().st_mode), 0o644)
            receipt_path = Path(first["receiptPath"])
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)

    def test_installer_rejects_symlink_projection_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            outside = home / "outside.md"
            outside.write_text("outside\n", encoding="utf-8")
            (home / "AGENTS.md").symlink_to(outside)
            with self.assertRaises(installer.InstallConflict):
                installer.install(home=home, apply=False)

    def test_installer_rejects_symlink_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            state_root = home / ".local/state/heim-pc"
            state_root.mkdir(parents=True)
            outside = home / "outside.lock"
            outside.write_text("outside\n", encoding="utf-8")
            (state_root / "operator-entry-install.lock").symlink_to(outside)
            with self.assertRaises(installer.InstallConflict):
                installer.install(home=home, apply=True)

    def test_checker_rejects_receipt_not_bound_to_current_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            receipt = installer.install(home=home, apply=True)
            receipt_path = Path(receipt["receiptPath"])
            receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt_data["sourceContractSha256"] = "0" * 64
            receipt_path.write_text(json.dumps(receipt_data), encoding="utf-8")

            checked = checker.check(home=home, require_installed=True)
            self.assertFalse(checked["valid"])
            self.assertIn("installed receipt is not bound to the current contract", checked["errors"])

    def test_checker_requires_byte_identical_installed_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            installer.install(home=home, apply=True)
            receipt = checker.check(home=home, require_installed=True)
            self.assertTrue(receipt["valid"], receipt["errors"])

            (home / "repos/AGENTS.md").write_text("drift\n", encoding="utf-8")
            drifted = checker.check(home=home, require_installed=True)
            self.assertFalse(drifted["valid"])
            self.assertIn("installed reposAgentPointer is missing or differs from canonical source", drifted["errors"])


if __name__ == "__main__":
    unittest.main()
