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
        transcription = contract["capabilityLocators"]["audioTranscription"]
        self.assertEqual(transcription["schemaVersion"], 1)
        self.assertEqual(
            set(transcription["intents"]),
            {"audio.transcribe", "speech_to_text", "transcription", "asr"},
        )
        self.assertEqual(transcription["authority"], "heim_pc_asr_open_engine")
        self.assertEqual(transcription["authorityKind"], "capability_locator_only")
        self.assertEqual(transcription["repository"], "${HOME}/repos/heim-pc")
        self.assertEqual(
            transcription["architecture"],
            "${HOME}/repos/heim-pc/architecture/asr-engine.md",
        )
        self.assertEqual(
            transcription["policy"],
            "${HOME}/repos/heim-pc/manifest/asr-engine-policy.v1.json",
        )
        self.assertEqual(
            transcription["entryArgvPrefix"],
            ["python3", "${HOME}/repos/heim-pc/scripts/asr_engine.py"],
        )
        self.assertEqual(transcription["defaultOperation"], "transcribe")
        self.assertEqual(transcription["policyResolution"], "read_at_execution_time")
        self.assertFalse(transcription["consumerEnginePinningAllowed"])
        self.assertFalse(transcription["cloudOrMeteredUseAuthorizedByLocator"])
        self.assertNotIn("faster-whisper", json.dumps(transcription, ensure_ascii=False))
        self.assertNotIn("qwen", json.dumps(transcription, ensure_ascii=False).lower())
        self.assertNotIn("parakeet", json.dumps(transcription, ensure_ascii=False).lower())
        policy = contract["transferPolicy"]
        self.assertEqual(policy["principle"], "role_based_dual_transport")
        self.assertEqual(policy["scope"], "heim_pc_mobile_devices")
        self.assertEqual(
            policy["mobileTargetsManifest"],
            "${HOME}/repos/heim-pc/manifest/mobile-transfer-targets.v1.json",
        )
        self.assertTrue(policy["targetAvailabilityRequiresFreshRead"])
        self.assertEqual(policy["sharedExchangeTransport"], "googleDriveSharedExchange")
        self.assertEqual(policy["directDeliveryTransport"], "taildropDirectDelivery")
        self.assertEqual(policy["selectionRules"]["sharedPersistentWorkspace"], "googleDriveSharedExchange")
        self.assertEqual(policy["selectionRules"]["directOneShotDelivery"], "taildropDirectDelivery")
        self.assertEqual(policy["selectionRules"]["largeOrSensitiveDelivery"], "taildropDirectDelivery")
        self.assertTrue(set(policy["selectionRules"].values()).issubset(contract["transferPaths"]))
        self.assertNotEqual(policy["sharedExchangeTransport"], policy["directDeliveryTransport"])

        shared = contract["transferPaths"]["googleDriveSharedExchange"]
        self.assertEqual(shared["role"], "shared_exchange")
        self.assertEqual(shared["canonicalDirectory"], "${HOME}/GDrive")
        self.assertEqual(shared["remote"], "gdrive:")
        self.assertEqual(shared["mountService"], "google-drive-rclone.service")
        self.assertEqual(shared["requiredRcloneScope"], "drive")
        self.assertEqual(shared["transport"], "google_drive")
        self.assertEqual(shared["direction"], "bidirectional")
        self.assertEqual(shared["endpoints"], ["heim_pc", "mobile_devices"])
        self.assertIn("google_drive_visibility_on_mobile_now", shared["doesNotEstablish"])
        self.assertIn("mobile_google_drive_client_available_now", shared["doesNotEstablish"])
        self.assertNotIn("fallbackTransport", shared)
        self.assertNotIn("icloudSharedExchange", contract["transferPaths"])

        direct = contract["transferPaths"]["taildropDirectDelivery"]
        self.assertEqual(direct["role"], "direct_delivery")
        self.assertEqual(direct["transport"], "tailscale_taildrop")
        self.assertEqual(direct["direction"], "bidirectional")
        self.assertEqual(direct["endpoints"], ["heim_pc", "mobile_devices"])
        self.assertEqual(direct["heimPcInbox"], "${HOME}/Incoming/Taildrop")
        self.assertEqual(direct["heimPcSendCommand"], "${HOME}/.local/bin/heim-taildrop-send")
        target_resolution = policy["directDeliveryTargetResolution"]
        self.assertEqual(
            target_resolution["manifest"],
            "${HOME}/repos/heim-pc/manifest/mobile-transfer-targets.v1.json",
        )
        self.assertEqual(target_resolution["route"], "directOneShotDelivery")
        self.assertEqual(
            target_resolution["liveTargetsArgv"],
            ["tailscale", "file", "cp", "--targets"],
        )
        self.assertNotIn("ipadTarget", direct)

        mobile_targets = json.loads(
            (ROOT / "manifest/mobile-transfer-targets.v1.json").read_text(encoding="utf-8")
        )
        targets = {item["id"]: item for item in mobile_targets["targets"]}
        self.assertEqual(targets["ipad"]["taildropTarget"], "ipad-10th-gen-wifi")
        self.assertEqual(targets["a54"]["taildropTarget"], "a54-von-alexander")
        route = mobile_targets["routing"][target_resolution["route"]]
        self.assertEqual(route["eligibleTargets"], ["ipad", "a54"])
        self.assertEqual(route["remoteFallbackOrder"], ["ipad", "a54"])
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
        self.assertEqual(
            managed["installedEntryArgv"],
            [
                "python3",
                "${HOME}/.local/lib/heim-pc/managed-build/scripts/managed_build.py",
            ],
        )
        self.assertEqual(
            managed["installedPolicy"],
            "${HOME}/.local/lib/heim-pc/managed-build/config/managed-build.v1.json",
        )
        self.assertEqual(
            managed["environmentResolver"]["entryArgv"],
            [
                "python3",
                "${HOME}/.local/lib/heim-pc/managed-build/scripts/managed_build.py",
                "resolve-environment",
            ],
        )
        self.assertEqual(
            managed["environmentResolver"]["identityAuthority"],
            "same_managed_build_identity_algorithm",
        )
        self.assertEqual(
            managed["environmentResolver"]["prepareArgv"],
            [
                "python3",
                "${HOME}/.local/lib/heim-pc/managed-build/scripts/managed_build.py",
                "prepare-environment",
            ],
        )
        self.assertEqual(managed["automationRule"], "operator_managed_builds_use_entry")
        self.assertEqual(managed["interactiveShellBehavior"], "unchanged")
        self.assertEqual(managed["worktreeWarningBytes"], 2 * 1024**3)
        self.assertEqual(managed["worktreeHardBytes"], 5 * 1024**3)
        self.assertFalse(managed["automaticCleanupAuthorized"])
        cost = contract["costPolicy"]
        self.assertEqual(cost["objective"], "zero_incremental_cost")
        self.assertEqual(cost["defaultBudgetUsd"], 0)
        self.assertTrue(cost["requireHardBudget"])
        self.assertTrue(cost["billingStateMustBeVerifiedBeforeInference"])
        self.assertEqual(cost["unknownBillingState"], "block")
        self.assertFalse(cost["priorBudgetAuthorizationsCarryForward"])
        self.assertTrue(cost["humanAuthorizationRequiredForAnyNonzeroIncrementalCost"])
        self.assertIn("pay_as_you_go", cost["forbidden"])
        self.assertIn("metered_api_key_usage", cost["forbidden"])
        self.assertIn(
            "permission_to_delete_worktree_or_cache_payloads",
            managed["doesNotEstablish"],
        )
        entry_ids = {item["id"] for item in contract["entrySequence"]}
        self.assertIn("operator_context", entry_ids)
        self.assertIn("capability_resolution", entry_ids)
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

    def test_checker_rejects_transcription_locator_engine_pinning_or_cloud_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            locator = contract["capabilityLocators"]["audioTranscription"]
            locator["consumerEnginePinningAllowed"] = True
            locator["cloudOrMeteredUseAuthorizedByLocator"] = True
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
                "capabilityLocators.audioTranscription.consumerEnginePinningAllowed must remain false",
                receipt["errors"],
            )
            self.assertIn(
                "capabilityLocators.audioTranscription.cloudOrMeteredUseAuthorizedByLocator must remain false",
                receipt["errors"],
            )

    def test_checker_rejects_nonzero_or_soft_cost_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            contract["costPolicy"]["defaultBudgetUsd"] = 1
            contract["costPolicy"]["requireHardBudget"] = False
            contract["costPolicy"]["unknownBillingState"] = "allow"
            contract["costPolicy"]["priorBudgetAuthorizationsCarryForward"] = True
            contract_path = tmp_path / "operator-entry.v1.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            policy_path = ROOT / "config/managed-build.v1.json"
            with (
                patch.object(checker, "CONTRACT_PATH", contract_path),
                patch.object(checker, "MANAGED_BUILD_POLICY_PATH", policy_path),
            ):
                receipt = checker.check(home=tmp_path, require_installed=False)
            self.assertFalse(receipt["valid"])
            self.assertIn("costPolicy.defaultBudgetUsd must be the integer 0", receipt["errors"])
            self.assertIn("costPolicy.requireHardBudget must be true", receipt["errors"])
            self.assertIn("costPolicy.unknownBillingState must be block", receipt["errors"])
            self.assertIn(
                "costPolicy.priorBudgetAuthorizationsCarryForward must be false",
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
            self.assertFalse(
                (home / ".local/lib/heim-pc/managed-build/scripts/managed_build.py").exists()
            )

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
            installed_root = home / ".local/lib/heim-pc/managed-build"
            self.assertEqual(
                (installed_root / "scripts/managed_build.py").read_bytes(),
                (ROOT / "scripts/managed_build.py").read_bytes(),
            )
            self.assertEqual(
                (installed_root / "scripts/storage_inventory.py").read_bytes(),
                (ROOT / "scripts/storage_inventory.py").read_bytes(),
            )
            self.assertEqual(
                (installed_root / "config/managed-build.v1.json").read_bytes(),
                (ROOT / "config/managed-build.v1.json").read_bytes(),
            )
            self.assertEqual(
                stat.S_IMODE((installed_root / "scripts/managed_build.py").stat().st_mode),
                0o755,
            )
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
