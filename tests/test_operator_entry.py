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
        self.assertEqual(transcription["authority"], "heimgewebe_asr_open_engine")
        self.assertEqual(transcription["authorityKind"], "capability_locator_only")
        self.assertEqual(transcription["repository"], "${HOME}/repos/asr")
        self.assertEqual(
            transcription["architecture"],
            "${HOME}/repos/asr/architecture/asr-engine.md",
        )
        self.assertEqual(
            transcription["policy"],
            "${HOME}/repos/asr/manifest/asr-engine-policy.v1.json",
        )
        self.assertEqual(
            transcription["contract"],
            "${HOME}/repos/asr/manifest/asr-transcript-contract.v1.json",
        )
        self.assertEqual(
            transcription["runbook"],
            "${HOME}/repos/asr/runbooks/asr-local-transcription.md",
        )
        reuse_policy = transcription["reusePolicy"]
        self.assertTrue(reuse_policy["resolveBeforeSetup"])
        self.assertTrue(reuse_policy["readinessBeforeSetup"])
        self.assertTrue(reuse_policy["setupOnlyWhenReadinessReportsMissing"])
        self.assertEqual(
            reuse_policy["sharedRuntimeCacheRoot"],
            "${HOME}/.local/cache/heimgewebe/asr",
        )
        self.assertEqual(
            reuse_policy["sharedRuntimeStateRoot"],
            "${HOME}/.local/state/heimgewebe/asr",
        )
        self.assertFalse(reuse_policy["perRequestVirtualenvAllowed"])
        self.assertFalse(reuse_policy["perRequestModelCacheAllowed"])
        self.assertFalse(reuse_policy["perRequestPackageInstallAllowed"])
        self.assertEqual(
            transcription["entryArgvPrefix"],
            ["python3", "${HOME}/repos/asr/scripts/asr_engine.py"],
        )
        self.assertEqual(
            transcription["compatibilityEntryArgvPrefix"],
            ["python3", "${HOME}/repos/heim-pc/scripts/asr_engine.py"],
        )
        self.assertEqual(transcription["defaultOperation"], "transcribe")
        self.assertEqual(transcription["policyResolution"], "read_at_execution_time")
        self.assertFalse(transcription["consumerEnginePinningAllowed"])
        self.assertFalse(transcription["cloudOrMeteredUseAuthorizedByLocator"])
        self.assertNotIn("faster-whisper", json.dumps(transcription, ensure_ascii=False))
        self.assertNotIn("qwen", json.dumps(transcription, ensure_ascii=False).lower())
        self.assertNotIn("parakeet", json.dumps(transcription, ensure_ascii=False).lower())
        self.assertEqual(transcription["entryKind"], "argv")
        self.assertEqual(transcription["readinessOperation"], "doctor")
        document_text = contract["capabilityLocators"]["documentTextExtraction"]
        self.assertEqual(document_text["schemaVersion"], 1)
        self.assertEqual(
            set(document_text["intents"]),
            {"document.text_extract", "document.ocr", "pdf.text_extract", "image.ocr", "ocr"},
        )
        self.assertEqual(document_text["authority"], "heim_pc_document_text_engine")
        self.assertEqual(document_text["authorityKind"], "capability_locator_only")
        self.assertEqual(document_text["entryKind"], "argv")
        self.assertEqual(
            document_text["entryArgvPrefix"],
            ["python3", "${HOME}/repos/heim-pc/scripts/document_text_engine.py"],
        )
        self.assertEqual(document_text["defaultOperation"], "extract")
        self.assertEqual(document_text["readinessOperation"], "doctor")
        self.assertEqual(document_text["policyResolution"], "read_at_execution_time")
        self.assertFalse(document_text["cloudOrMeteredUseAuthorizedByLocator"])
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
        entry_ids = [item["id"] for item in contract["entrySequence"]]
        self.assertIn("operator_context", entry_ids)
        discovery_order = [
            "scope_classification",
            "native_capability_discovery",
            "capability_resolution",
            "specialized_route_resolution",
            "source_resolution",
            "target_specific_live_state",
        ]
        discovery_start = entry_ids.index("scope_classification")
        self.assertEqual(
            entry_ids[discovery_start : discovery_start + len(discovery_order)],
            discovery_order,
        )
        entry_by_id = {item["id"]: item for item in contract["entrySequence"]}
        self.assertEqual(
            entry_by_id["native_capability_discovery"]["operation"],
            "prefer_existing_typed_surface",
        )
        self.assertEqual(
            entry_by_id["capability_resolution"]["statusPolicy"],
            {
                "resolved": "select_host_authority",
                "not_found": "continue_to_declared_specialized_routes",
                "blocked": "stop_without_fallback",
            },
        )
        self.assertEqual(
            entry_by_id["specialized_route_resolution"]["precondition"],
            "host_capability_status_not_found",
        )
        self.assertEqual(
            entry_by_id["target_specific_live_state"]["readinessPolicy"],
            {
                "notReadyIsNotNotFound": True,
                "notReadyAction": "recover_selected_authority",
                "parallelReplacementAllowed": False,
            },
        )
        self.assertIn("stableEcosystemSemantics", contract["truthSources"])
        self.assertIn("executionRuntimeLeases", contract["truthSources"])
        repository_context = contract["truthSources"]["repositoryContext"]
        self.assertEqual(repository_context["repository"], "${HOME}/repos/repoground")
        self.assertEqual(repository_context["publicName"], "RepoGround")
        self.assertEqual(
            repository_context["preferredReads"],
            [
                "repoground_freshness_check",
                "repoground_context_pack",
                "repoground_query",
                "repoground_range_get",
            ],
        )
        serialized_repository_context = json.dumps(repository_context, ensure_ascii=False).lower()
        self.assertNotIn("lenskit", serialized_repository_context)
        self.assertNotIn("repobrief", serialized_repository_context)
        self.assertTrue(
            all(not item.startswith("rlens_") for item in repository_context["preferredReads"])
        )
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

    def test_checker_rejects_transcription_reuse_policy_that_allows_per_request_setup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            locator = contract["capabilityLocators"]["audioTranscription"]
            locator["runbook"] = "${HOME}/repos/heim-pc/runbooks/other.md"
            locator["readinessOperation"] = "setup"
            locator["reusePolicy"]["sharedRuntimeCacheRoot"] = "${HOME}/.cache/per-request-asr"
            locator["reusePolicy"]["readinessBeforeSetup"] = False
            locator["reusePolicy"]["setupOnlyWhenReadinessReportsMissing"] = False
            locator["reusePolicy"]["perRequestVirtualenvAllowed"] = True
            locator["reusePolicy"]["perRequestModelCacheAllowed"] = True
            locator["reusePolicy"]["perRequestPackageInstallAllowed"] = True
            contract_path = tmp_path / "operator-entry.v1.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            with patch.object(checker, "CONTRACT_PATH", contract_path):
                receipt = checker.check(home=tmp_path, require_installed=False)
            self.assertFalse(receipt["valid"])
            self.assertIn(
                "capabilityLocators.audioTranscription.runbook must point to the generic ASR authority",
                receipt["errors"],
            )
            self.assertIn(
                "capabilityLocators.audioTranscription.readinessOperation must be doctor",
                receipt["errors"],
            )
            self.assertIn(
                "capabilityLocators.audioTranscription.reusePolicy.sharedRuntimeCacheRoot must name the generic ASR runtime root",
                receipt["errors"],
            )
            self.assertIn(
                "capabilityLocators.audioTranscription.reusePolicy.readinessBeforeSetup must be true",
                receipt["errors"],
            )
            self.assertIn(
                "capabilityLocators.audioTranscription.reusePolicy.setupOnlyWhenReadinessReportsMissing must be true",
                receipt["errors"],
            )
            for flag in (
                "perRequestVirtualenvAllowed",
                "perRequestModelCacheAllowed",
                "perRequestPackageInstallAllowed",
            ):
                self.assertIn(
                    f"capabilityLocators.audioTranscription.reusePolicy.{flag} must remain false",
                    receipt["errors"],
                )

    def test_checker_rejects_discovery_fallback_on_blocked_host_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            entry_by_id = {item["id"]: item for item in contract["entrySequence"]}
            entry_by_id["capability_resolution"]["statusPolicy"]["blocked"] = (
                "continue_to_declared_specialized_routes"
            )
            entry_by_id["specialized_route_resolution"]["precondition"] = (
                "host_capability_status_unresolved"
            )
            contract_path = tmp_path / "operator-entry.v1.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            with patch.object(checker, "CONTRACT_PATH", contract_path):
                receipt = checker.check(home=tmp_path, require_installed=False)
            self.assertFalse(receipt["valid"])
            self.assertIn(
                "capability_resolution.statusPolicy must allow fallback only on explicit not_found",
                receipt["errors"],
            )
            self.assertIn(
                "specialized_route_resolution.precondition must require host capability not_found",
                receipt["errors"],
            )

    def test_checker_rejects_interposed_discovery_step(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            entry_sequence = contract["entrySequence"]
            native_index = next(
                index
                for index, item in enumerate(entry_sequence)
                if item["id"] == "native_capability_discovery"
            )
            entry_sequence.insert(
                native_index + 1,
                {
                    "id": "setup_per_request",
                    "surface": "agent",
                    "operation": "build_replacement_infrastructure",
                },
            )
            contract_path = tmp_path / "operator-entry.v1.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            with patch.object(checker, "CONTRACT_PATH", contract_path):
                receipt = checker.check(home=tmp_path, require_installed=False)
            self.assertFalse(receipt["valid"])
            self.assertIn(
                "entrySequence discovery steps must preserve reuse-before-build order",
                receipt["errors"],
            )

    def test_checker_rejects_readiness_policy_that_allows_parallel_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            entry_by_id = {item["id"]: item for item in contract["entrySequence"]}
            entry_by_id["target_specific_live_state"]["readinessPolicy"][
                "parallelReplacementAllowed"
            ] = True
            contract_path = tmp_path / "operator-entry.v1.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            with patch.object(checker, "CONTRACT_PATH", contract_path):
                receipt = checker.check(home=tmp_path, require_installed=False)
            self.assertFalse(receipt["valid"])
            self.assertIn(
                "target_specific_live_state.readinessPolicy must preserve canonical not-ready semantics",
                receipt["errors"],
            )

    def test_reuse_before_build_guidance_matches_entry_sequence(self) -> None:
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        runbook = (ROOT / "runbooks/asr-local-transcription.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        home_entry = (ROOT / "runtime/home-entry.md").read_text(encoding="utf-8")

        agent_rule = next(
            line
            for line in agents.splitlines()
            if line.startswith("* **Reuse-before-build / Capability-first:**")
        )
        self.assertEqual(
            agent_rule,
            "* **Reuse-before-build / Capability-first:** "
            "Zuerst eine bereits veröffentlichte native typed Grabowski-Oberfläche "
            "verwenden, wenn sie den Auftrag erfüllt. Nur wenn keine solche native "
            "Oberfläche passt und der Intent host-local ist, den installierten "
            "Capability-Locator auflösen; ein `blocked` stoppt statt auf einen "
            "Ersatzpfad auszuweichen. Erst bei explizitem `not_found` dürfen bereits "
            "deklarierte Spezialrouten folgen. Für Audio-Transkription ist der "
            "host-local Grabowski-Leseweg danach "
            "`grabowski_host_capability_resolve(intent=\"audio.transcribe\")`. "
            "Keine eigene Runtime, virtuelle Umgebung oder Modellcache aufbauen, "
            "solange eine kanonische Authority oder deklarierte Route existiert.",
        )

        heading = "## 1. Native Oberfläche vor Host-Locator prüfen"
        section = runbook.split(heading, 1)[1].split("\n## ", 1)[0].strip()
        expected_opening = (
            "Vor dem host-local Schritt zuerst eine bereits veröffentlichte native "
            "typed Grabowski-Oberfläche verwenden, wenn sie den Auftrag erfüllt. "
            "Nur wenn keine solche Oberfläche passt, den installierten Maschinenvertrag "
            "über die host-local Capability-Auflösung lesen. Ein `blocked` ist kein "
            "Miss und darf nicht durch einen Ersatzpfad umgangen werden. Nur ein "
            "explizites `not_found` darf zu einer bereits deklarierten Spezialroute "
            "weiterführen."
        )
        self.assertTrue(section.startswith(expected_opening), section)
        precondition = (
            "Host-Cutover-Schritte 1–3 erfolgreich abgeschlossen sind: "
            "Installationsplan prüfen → `--apply --replace-existing` ausführen → "
            "`check_operator_entry.py --require-installed` erfolgreich prüfen"
        )
        self.assertIn(precondition, section)
        self.assertLess(
            section.index(precondition),
            section.index('`grabowski_host_capability_resolve(intent="audio.transcribe")`'),
        )

        cutover = runbook.split("## Host-Cutover", 1)[1].split("\n## ", 1)[0]
        plan_index = cutover.index("Installationsplan")
        apply_index = cutover.index("--apply --replace-existing")
        verify_index = cutover.index("--require-installed")
        resolve_index = cutover.index("grabowski_host_capability_resolve")
        self.assertLess(plan_index, apply_index)
        self.assertLess(apply_index, verify_index)
        self.assertLess(verify_index, resolve_index)
        for non_claim in ("mutation_permission", "retry_permission", "task_completion"):
            self.assertIn(non_claim, runbook)
        self.assertIn(
            "Do not delete or replace the shared ASR cache as an automatic recovery action.",
            runbook,
        )

        readme_route = readme.split(
            "Für ChatGPT über Grabowski beginnt jede neue Operatorroute mit:", 1
        )[1].split("\n## ", 1)[0]
        readme_steps = [
            line.strip() for line in readme_route.splitlines() if line.strip()[:1].isdigit()
        ]
        self.assertEqual(
            readme_steps[6:10],
            [
                "7. zuerst eine bereits veröffentlichte native typed Grabowski-Oberfläche verwenden, wenn sie den Auftrag erfüllt;",
                "8. nur bei einem host-local Intent ohne passende native Oberfläche `grabowski_host_capability_resolve` verwenden; `blocked` stoppt, nur explizites `not_found` darf zu einer bereits deklarierten Spezialroute weiterführen, und non-host Intents hängen nicht vom Host-Vertrag ab;",
                "9. gezielt die im Vertrag referenzierten Primärquellen der ausgewählten Route lesen;",
                "10. danach die gewählte Authority sowie ihre Live-Policy, Readiness und den zielbezogenen Livezustand unmittelbar vor Ausführung erneut lesen; not-ready ist nicht not-found und rechtfertigt keinen parallelen Ersatz.",
            ],
        )

        home_route = home_entry.split("## Betriebslogik", 1)[1]
        home_steps = [
            line.strip() for line in home_route.splitlines() if line.strip()[:1].isdigit()
        ]
        self.assertEqual(
            home_steps[3:7],
            [
                "4. zuerst eine passende bereits veröffentlichte native typed Grabowski-Oberfläche verwenden,",
                "5. nur bei einem host-local Intent ohne passende native Oberfläche `grabowski_host_capability_resolve` verwenden; `blocked` stoppt, nur explizites `not_found` erlaubt die bereits deklarierte Spezialroute, während non-host Intents nicht vom Host-Vertrag abhängen,",
                "6. nur die im Vertrag referenzierten Primärquellen der ausgewählten Route lesen,",
                "7. danach die ausgewählte Authority samt Live-Policy und Readiness unmittelbar vor Ausführung erneut lesen; not-ready ist nicht not-found und erlaubt keinen parallelen Ersatz,",
            ],
        )

    def test_checker_accepts_additional_generic_locator_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            contract["capabilityLocators"]["exampleReadOnly"] = {
                "schemaVersion": 1,
                "purpose": "Test the generic locator validator without a named capability special case",
                "intents": ["example.read_only"],
                "authority": "heim_pc_example_read_only",
                "authorityKind": "capability_locator_only",
                "repository": "${HOME}/repos/heim-pc",
                "entryKind": "argv",
                "entryArgvPrefix": ["python3", "${HOME}/repos/heim-pc/scripts/check_operator_entry.py"],
                "defaultOperation": "check",
                "readinessOperation": "check",
                "policyResolution": "read_at_execution_time",
                "doesNotEstablish": ["current_runtime_readiness"],
            }
            contract_path = tmp_path / "operator-entry.v1.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            with patch.object(checker, "CONTRACT_PATH", contract_path):
                receipt = checker.check(home=tmp_path, require_installed=False)
            self.assertTrue(receipt["valid"], receipt["errors"])

    def test_checker_rejects_casefold_ambiguous_capability_intent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            contract = json.loads(
                (ROOT / "manifest/operator-entry.v1.json").read_text(encoding="utf-8")
            )
            contract["capabilityLocators"]["documentTextExtraction"]["intents"].append("ASR")
            contract_path = tmp_path / "operator-entry.v1.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            with patch.object(checker, "CONTRACT_PATH", contract_path):
                receipt = checker.check(home=tmp_path, require_installed=False)
            self.assertFalse(receipt["valid"])
            self.assertTrue(
                any("capability intent 'ASR' is ambiguous" in error for error in receipt["errors"]),
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
