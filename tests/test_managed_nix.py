from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

import scripts.managed_nix as managed_nix
from scripts.managed_nix import (
    ACTIVATION_AUTHORITY_KIND,
    ACTIVATION_PLAN_KIND,
    BOOT_CRITICAL_EFFECTS,
    BUILD_REQUEST_KIND,
    BUILD_SOURCE_CONTEXT_KIND,
    CANONICAL_BUILD_ENTRYPOINT,
    DESTRUCTIVE_EFFECTS,
    MANAGED_DEPLOYMENT_CONTRACT,
    MAX_AUTHORITY_LIFETIME_SECONDS,
    NORMAL_EFFECTS,
    ManagedNixError,
    canonical_build_request_payload,
    classify_effect,
    make_activation_receipt,
    make_build_receipt,
    rollback_plan,
    sha256_json,
    validate_activation_authority,
    validate_activation_plan,
    validate_build_receipt,
    validate_build_request,
    validate_build_source_context,
)

REVISION = "a" * 40
CONTROL_DIGEST = "b" * 64
LOCK_DIGEST = "c" * 64
CLOSURE = "/nix/store/00000000000000000000000000000000-nixos-system-heim-pc-26.05"
PRIOR = "/nix/store/11111111111111111111111111111111-nixos-system-heim-pc-25.11"


def request(**updates):
    value = {
        "schema_version": 1,
        "kind": BUILD_REQUEST_KIND,
        "effect_class": "build",
        "repository": "heimgewebe/heim-pc",
        "source_revision": REVISION,
        "control_release_set": {"id": "control-2026-09", "digest": CONTROL_DIGEST},
        "nix_inputs": {"flake.lock": LOCK_DIGEST},
        "budgets": {
            "store_bytes": {"warning": 10_000, "hard": 20_000},
            "cache_bytes": {"warning": 1_000, "hard": 2_000},
            "runtime_seconds": {"warning": 300, "hard": 900},
        },
        "leases": ["nix-store:heim-pc", "repo:heim-pc@" + REVISION],
        "possible_effects": ["kernel", "initrd"],
        "entrypoint": list(CANONICAL_BUILD_ENTRYPOINT),
    }
    value.update(updates)
    return value


def receipt():
    return make_build_receipt(
        request(),
        system_closure=CLOSURE,
        declared_capabilities={"boot": {"uefi": True}, "gpu": {"nvidia": True}},
    )


def authority(build_receipt=None, **updates):
    build_receipt = build_receipt or receipt()
    value = {
        "schema_version": 1,
        "kind": ACTIVATION_AUTHORITY_KIND,
        "effect_class": "activation",
        "mode": "next-boot",
        "source_revision": REVISION,
        "system_closure": CLOSURE,
        "target": "sandbox:nixos-activation-1",
        "build_receipt_sha256": sha256_json(build_receipt),
        "prior_closure": PRIOR,
        "recovery_path": "known-generation-and-rescue-medium",
        "issued_at": "2026-09-04T07:30:00Z",
        "expires_at": "2026-09-04T09:00:00Z",
    }
    value.update(updates)
    return value


def validate_authority(
    build_receipt,
    candidate,
    *,
    expected_target="sandbox:nixos-activation-1",
    now="2026-09-04T08:00:00Z",
    authority_sha256=None,
):
    return validate_activation_authority(
        build_receipt,
        candidate,
        expected_authority_sha256=authority_sha256 or sha256_json(candidate),
        expected_target=expected_target,
        now=now,
    )


def test_effect_classifier_uses_possible_effect_not_filename_or_intent() -> None:
    assert classify_effect(["package-set", "audio-userspace"]) == "normal"
    assert classify_effect(["kernel", "package-set"]) == "boot-critical"
    assert classify_effect(["luks-keyslot-mutation"]) == "destructive"
    assert classify_effect(["sounds-harmless-but-is-unknown"]) == "destructive"
    assert classify_effect(("package-set",)) == "normal"


def test_effect_classifier_contract_sets_are_disjoint() -> None:
    assert not (DESTRUCTIVE_EFFECTS & BOOT_CRITICAL_EFFECTS)
    assert not (DESTRUCTIVE_EFFECTS & NORMAL_EFFECTS)
    assert not (BOOT_CRITICAL_EFFECTS & NORMAL_EFFECTS)
    classifier = MANAGED_DEPLOYMENT_CONTRACT["effect_classifier"]
    assert set(classifier["destructive_effects"]) == DESTRUCTIVE_EFFECTS
    assert set(classifier["boot_critical_effects"]) == BOOT_CRITICAL_EFFECTS
    assert set(classifier["normal_effects"]) == NORMAL_EFFECTS
    assert classifier["unknown_effect"] == "destructive"


def test_build_request_binds_revision_release_inputs_budgets_leases_and_exact_adapter() -> None:
    normalized = validate_build_request(request())
    assert normalized["repository"] == "heimgewebe/heim-pc"
    assert normalized["source_revision"] == REVISION
    assert normalized["control_release_set"]["digest"] == CONTROL_DIGEST
    assert normalized["nix_inputs"] == {"flake.lock": LOCK_DIGEST}
    assert normalized["effect_scope"] == "boot-critical"
    assert normalized["leases"] == sorted(normalized["leases"])
    assert normalized["entrypoint"] == list(CANONICAL_BUILD_ENTRYPOINT)


def test_build_request_hashes_only_canonical_contract_input_not_derived_scope() -> None:
    raw = request(possible_effects=["KERNEL", "INITRD"])
    normalized = validate_build_request(raw)
    payload = canonical_build_request_payload(raw)
    built = make_build_receipt(
        raw,
        system_closure=CLOSURE,
        declared_capabilities={"boot": {"uefi": True}},
    )
    assert set(payload) == set(MANAGED_DEPLOYMENT_CONTRACT["build"]["request_fields"])
    assert "effect_scope" not in payload
    assert payload["possible_effects"] == ["initrd", "kernel"]
    assert built["build_request_sha256"] == sha256_json(payload)
    assert built["build_request_sha256"] != sha256_json(normalized)


def test_build_request_digest_is_semantic_canonical_json_not_raw_file_bytes() -> None:
    first = request(
        possible_effects=["KERNEL", "INITRD"],
        leases=["repo:heim-pc@" + REVISION, "nix-store:heim-pc"],
    )
    second = request(
        possible_effects=["initrd", "kernel"],
        leases=["nix-store:heim-pc", "repo:heim-pc@" + REVISION],
    )
    assert sha256_json(canonical_build_request_payload(first)) == sha256_json(
        canonical_build_request_payload(second)
    )


def test_build_source_context_requires_observed_exact_repository_and_revision() -> None:
    context = validate_build_source_context(
        request(),
        observed_repository="heimgewebe/heim-pc",
        observed_source_revision=REVISION,
    )
    assert context["kind"] == BUILD_SOURCE_CONTEXT_KIND
    assert context["source_revision"] == REVISION
    assert context["build_request_sha256"] == sha256_json(
        canonical_build_request_payload(request())
    )
    with pytest.raises(ManagedNixError, match="observed repository"):
        validate_build_source_context(
            request(),
            observed_repository="heimgewebe/other",
            observed_source_revision=REVISION,
        )
    with pytest.raises(ManagedNixError, match="observed source revision"):
        validate_build_source_context(
            request(),
            observed_repository="heimgewebe/heim-pc",
            observed_source_revision="d" * 40,
        )


def test_build_request_rejects_mutable_or_noncanonical_identity_and_adapter() -> None:
    with pytest.raises(ManagedNixError, match="immutable"):
        validate_build_request(request(source_revision="main"))
    with pytest.raises(ManagedNixError, match="canonical owner/repository"):
        validate_build_request(request(repository="../heim-pc"))
    with pytest.raises(ManagedNixError, match="canonical owner/repository"):
        validate_build_request(request(repository="heimgewebe/heim-pc.git"))
    with pytest.raises(ManagedNixError, match="leases"):
        validate_build_request(request(leases=[]))
    for entrypoint in (
        ["nixos-rebuild", "switch"],
        [
            "nix",
            "build",
            ".#nixosConfigurations.heim-pc.config.system.build.toplevel",
            "--impure",
        ],
        ["nix", "build", ".#other"],
    ):
        with pytest.raises(ManagedNixError, match="canonical pure NixOS"):
            validate_build_request(request(entrypoint=entrypoint))


def test_build_request_rejects_noncanonical_repository_identity() -> None:
    for repository in (
        "../repo",
        "./repo",
        "owner/..",
        "owner/.",
        "/tmp/repo",
        "owner/repo.git",
    ):
        with pytest.raises(ManagedNixError, match="canonical owner/repository"):
            validate_build_request(request(repository=repository))


def test_build_request_canonicalizes_effects_without_alias_collisions() -> None:
    normalized = validate_build_request(
        request(possible_effects=["PACKAGE-SET", "audio-userspace"])
    )
    assert normalized["possible_effects"] == ["audio-userspace", "package-set"]
    with pytest.raises(ManagedNixError, match="unique after canonicalization"):
        validate_build_request(request(possible_effects=["kernel", "KERNEL"]))


def test_build_request_rejects_casefold_lease_aliases() -> None:
    with pytest.raises(ManagedNixError, match="case-folding"):
        validate_build_request(request(leases=["LEASE:X", "lease:x"]))


def test_build_request_rejects_non_strict_budget_thresholds_and_bool_integers() -> None:
    budgets = request()["budgets"]
    budgets["cache_bytes"] = {"warning": 2_000, "hard": 2_000}
    with pytest.raises(ManagedNixError, match="strictly below"):
        validate_build_request(request(budgets=budgets))

    budgets = request()["budgets"]
    budgets["runtime_seconds"] = {"warning": True, "hard": 900}
    with pytest.raises(ManagedNixError, match="strictly below"):
        validate_build_request(request(budgets=budgets))


def test_schema_version_is_strict_integer_across_request_receipt_authority_and_plan() -> None:
    for bad in (True, 1.0):
        with pytest.raises(ManagedNixError, match="must be integer 1"):
            validate_build_request(request(schema_version=bad))

        built = receipt()
        built["schema_version"] = bad
        with pytest.raises(ManagedNixError, match="must be integer 1"):
            validate_build_receipt(built)

        built = receipt()
        candidate = authority(built, schema_version=bad)
        with pytest.raises(ManagedNixError, match="must be integer 1"):
            validate_authority(built, candidate)

        built = receipt()
        plan = validate_authority(built, authority(built))
        plan["schema_version"] = bad
        with pytest.raises(ManagedNixError, match="must be integer 1"):
            validate_activation_plan(plan)


def test_destructive_or_ambiguous_effect_never_uses_managed_build_lane() -> None:
    with pytest.raises(ManagedNixError, match="separate destructive plan"):
        validate_build_request(request(possible_effects=["filesystem-create-destroy"]))
    with pytest.raises(ManagedNixError, match="separate destructive plan"):
        validate_build_request(request(possible_effects=["mystery-side-effect"]))


def test_closure_binding_rejects_traversal_short_non_nix_illegal_or_wrong_host_names() -> None:
    for bad in (
        "/nix/store/../../etc/x-nixos-system-y",
        "/nix/store/abc-nixos-system-heim-pc",
        "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-nixos-system-heim-pc-26.05",
        "/nix/store/00000000000000000000000000000000-not-a-system",
        "/nix/store/00000000000000000000000000000000-nixos-system-heim-pc-foo bar",
        "/nix/store/00000000000000000000000000000000-nixos-system-heim-pc-foo*bar",
        "/nix/store/00000000000000000000000000000000-nixos-system-heim-pc-ümlaut",
        "/nix/store/00000000000000000000000000000000-nixos-system-other-26.05",
        "/nix/store/00000000000000000000000000000000-nixos-system-heim-pc-",
    ):
        with pytest.raises(ManagedNixError, match="canonical immutable"):
            make_build_receipt(
                request(),
                system_closure=bad,
                declared_capabilities={"boot": {"uefi": True}},
            )


def test_successful_build_receipt_binds_exact_closure_and_does_not_authorize_activation() -> None:
    built = receipt()
    assert built["kind"] == "heim_pc.nixos_build_receipt"
    assert built["system_closure"] == CLOSURE
    assert built["source_revision"] == REVISION
    assert built["control_release_set"]["digest"] == CONTROL_DIGEST
    assert built["possible_effects"] == ["initrd", "kernel"]
    assert built["activation_authorized"] is False
    assert len(built["build_request_sha256"]) == 64
    assert validate_build_receipt(built) == built


def test_build_receipt_revalidates_budgets_exact_shape_and_effect_scope() -> None:
    built = receipt()
    built["budgets"] = {"store_bytes": {"warning": 1, "hard": 2}}
    with pytest.raises(ManagedNixError, match="must define"):
        validate_build_receipt(built)

    built = receipt()
    built["surprise"] = True
    with pytest.raises(ManagedNixError, match="fields mismatch"):
        validate_build_receipt(built)

    built = receipt()
    built["possible_effects"] = ["package-set"]
    with pytest.raises(ManagedNixError, match="effect_scope"):
        validate_build_receipt(built)

    built = receipt()
    built["possible_effects"] = ["mystery-side-effect"]
    with pytest.raises(ManagedNixError, match="destructive or ambiguous"):
        validate_build_receipt(built)


def test_activation_accepts_only_externally_bound_receipt_authority() -> None:
    built = receipt()
    candidate = authority(built)
    plan = validate_authority(built, candidate)
    assert plan["system_closure"] == CLOSURE
    assert plan["source_revision"] == REVISION
    assert plan["source_reevaluation_allowed"] is False
    assert plan["broad_root_shell_allowed"] is False
    assert plan["authority_sha256"] == sha256_json(candidate)
    assert plan["executor_authority"] == "successor-task-typed-activation-only"
    assert validate_activation_plan(plan) == plan


def test_self_asserted_review_flag_is_not_an_authority_surface() -> None:
    built = receipt()
    candidate = authority(built, reviewed=True)
    with pytest.raises(ManagedNixError, match="fields mismatch"):
        validate_activation_authority(
            built,
            candidate,
            expected_authority_sha256=sha256_json(candidate),
            expected_target="sandbox:nixos-activation-1",
            now="2026-09-04T08:00:00Z",
        )


def test_activation_authority_rejects_noncanonical_strings_before_digest_use() -> None:
    built = receipt()
    candidate = authority(built, target=" sandbox:nixos-activation-1 ")
    with pytest.raises(ManagedNixError, match="must already be canonical"):
        validate_authority(built, candidate)

    candidate = authority(built, recovery_path=" rescue ")
    with pytest.raises(ManagedNixError, match="must already be canonical"):
        validate_authority(built, candidate)


def test_activation_requires_external_digest_binding_and_fresh_bounded_authority() -> None:
    built = receipt()
    candidate = authority(built)
    with pytest.raises(ManagedNixError, match="externally bound review authority"):
        validate_authority(built, candidate, authority_sha256="f" * 64)

    expired = authority(built, expires_at="2026-09-04T07:00:00Z")
    with pytest.raises(ManagedNixError, match="expires_at must be after issued_at"):
        validate_authority(built, expired)

    expired = authority(built, expires_at="2026-09-04T08:00:00Z")
    with pytest.raises(ManagedNixError, match="expired"):
        validate_authority(built, expired)

    future = authority(
        built,
        issued_at="2026-09-04T08:30:00Z",
        expires_at="2026-09-04T09:00:00Z",
    )
    with pytest.raises(ManagedNixError, match="not yet valid"):
        validate_authority(built, future)

    too_long = authority(
        built,
        issued_at="2026-09-04T06:00:00Z",
        expires_at="2026-09-04T09:00:01Z",
    )
    assert MAX_AUTHORITY_LIFETIME_SECONDS == 7200
    with pytest.raises(ManagedNixError, match="lifetime exceeds"):
        validate_authority(built, too_long)


def test_boot_critical_build_cannot_skip_directly_to_persistent_activation() -> None:
    built = receipt()
    candidate = authority(built, mode="persistent")
    with pytest.raises(ManagedNixError, match="test/next-boot"):
        validate_authority(built, candidate)


def test_activation_fails_before_effect_on_closure_source_target_or_receipt_mismatch() -> None:
    built = receipt()
    cases = [
        (
            authority(
                built,
                system_closure=(
                    "/nix/store/22222222222222222222222222222222-"
                    "nixos-system-heim-pc-other"
                ),
            ),
            "closure",
        ),
        (authority(built, source_revision="d" * 40), "source revision"),
        (authority(built, target="production:heim-pc"), "target"),
        (authority(built, build_receipt_sha256="e" * 64), "build receipt"),
    ]
    for candidate, message in cases:
        with pytest.raises(ManagedNixError, match=message):
            validate_authority(built, candidate)


def test_activation_helpers_reject_partial_forged_or_drifted_plans() -> None:
    partial = {"kind": ACTIVATION_PLAN_KIND}
    with pytest.raises(ManagedNixError, match="fields mismatch"):
        make_activation_receipt(
            partial,
            live_closure=CLOSURE,
            readback_evidence_sha256="f" * 64,
        )
    with pytest.raises(ManagedNixError, match="fields mismatch"):
        rollback_plan(partial)

    built = receipt()
    plan = validate_authority(built, authority(built))
    plan["source_reevaluation_allowed"] = True
    with pytest.raises(ManagedNixError, match="forbid source reevaluation"):
        rollback_plan(plan)

    plan = validate_authority(built, authority(built))
    plan["executor_authority"] = "caller"
    with pytest.raises(ManagedNixError, match="executor authority"):
        make_activation_receipt(
            plan,
            live_closure=CLOSURE,
            readback_evidence_sha256="f" * 64,
        )


def test_activation_receipt_requires_independent_live_closure_readback() -> None:
    built = receipt()
    candidate = authority(built)
    plan = validate_authority(built, candidate)
    result = make_activation_receipt(
        plan,
        live_closure=CLOSURE,
        readback_evidence_sha256="f" * 64,
    )
    assert result["kind"] == "heim_pc.nixos_activation_receipt"
    assert result["live_closure"] == result["system_closure"] == CLOSURE
    assert result["source_reevaluation_used"] is False

    with pytest.raises(ManagedNixError, match="live closure"):
        make_activation_receipt(
            plan,
            live_closure=(
                "/nix/store/22222222222222222222222222222222-"
                "nixos-system-heim-pc-other"
            ),
            readback_evidence_sha256="f" * 64,
        )


def test_rollback_is_bound_to_prior_closure_without_source_reevaluation() -> None:
    built = receipt()
    candidate = authority(built)
    plan = validate_authority(built, candidate)
    rollback = rollback_plan(plan)
    assert rollback["system_closure"] == PRIOR
    assert rollback["source_reevaluation_allowed"] is False


def test_cli_semantic_validation_error_is_compact_without_argparse_usage(
    tmp_path: Path,
) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request(source_revision="main")), encoding="utf-8")
    script = Path(__file__).parents[1] / "scripts" / "managed_nix.py"
    completed = subprocess.run(
        [sys.executable, str(script), "validate-build-request", str(request_path)],
        cwd=Path(__file__).parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "managed-nix validation error:" in completed.stderr
    assert "usage:" not in completed.stderr.lower()
    assert completed.stdout == ""


def test_cli_can_emit_canonical_json_for_hash_sensitive_automation(tmp_path: Path) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request()), encoding="utf-8")
    script = Path(__file__).parents[1] / "scripts" / "managed_nix.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--canonical-json",
            "validate-build-request",
            str(request_path),
        ],
        cwd=Path(__file__).parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout == json.dumps(
        validate_build_request(request()),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ) + "\n"


def test_contract_loader_rejects_v1_semantic_policy_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path = tmp_path / "contract-v1.json"
    monkeypatch.setattr(managed_nix, "_CONTRACT_PATH", contract_path)

    cases = [
        (("closure", "nix_base32_alphabet"), "0123456789abcdfghijklmnpqrsvwxye", "nix_base32_alphabet"),
        (("build", "canonical_entrypoint"), ["nixos-rebuild", "switch"], "canonical_entrypoint"),
        (("build", "effect_class"), "activation", "build.effect_class"),
        (("activation", "allowed_modes"), ["test", "next-boot", "persistent", "direct-switch"], "allowed_modes"),
        (("activation", "executor_authority"), "caller", "executor_authority"),
        (("activation", "max_authority_lifetime_seconds"), 86_400, "max_authority_lifetime_seconds"),
        (("activation", "runtime_proof_task"), "HEIM-PC-NIXOS-MIGRATION-V1-T999", "runtime_proof_task"),
        (("execution_context", "build_context_kind"), "caller_context", "build_context_kind"),
    ]
    for path, replacement, error_fragment in cases:
        candidate = copy.deepcopy(MANAGED_DEPLOYMENT_CONTRACT)
        target = candidate
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        contract_path.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(RuntimeError, match=error_fragment):
            managed_nix._load_managed_contract()


def test_contract_file_is_runtime_source_and_keeps_t012_implementation_only() -> None:
    contract_path = Path(__file__).parents[1] / "nixos" / "deployment" / "contract-v1.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    assert contract == MANAGED_DEPLOYMENT_CONTRACT
    assert contract["build"]["canonical_entrypoint"] == list(CANONICAL_BUILD_ENTRYPOINT)
    assert set(contract["build"]["receipt_fields"]) == set(
        contract["build"]["receipt_requires"]
    )
    assert contract["build"]["request_digest_semantics"] == "canonical-validated-input-v1"
    assert contract["build"]["request_digest_excludes_derived_fields"] == ["effect_scope"]
    assert contract["activation"]["requires_external_authority_sha256"] is True
    assert contract["activation"]["self_asserted_review_flag_allowed"] is False
    assert contract["activation"]["runtime_executor_implemented_here"] is False
    assert contract["activation"]["runtime_proof_task"] == "HEIM-PC-NIXOS-MIGRATION-V1-T004"
    assert contract["activation"]["requires_independent_live_closure_readback"] is True
    assert contract["execution_context"] == {
        "build_context_kind": "heim_pc.nixos_build_source_context",
        "build_context_fields": [
            "schema_version",
            "kind",
            "repository",
            "source_revision",
            "build_request_sha256",
        ],
        "build_repository_must_match_observed_repository": True,
        "build_source_revision_must_match_observed_checkout": True,
        "activation_target_must_come_from_reserved_runtime_target": True,
        "current_time_must_come_from_trusted_runtime_clock": True,
        "caller_supplied_values_are_authority": False,
    }
    assert contract["implementation_boundary"] == {
        "live_activation": False,
        "service_restart": False,
        "runtime_rollback": False,
        "production_storage_mutation": False,
        "efi_mutation": False,
        "secure_boot_mutation": False,
        "firmware_mutation": False,
        "reboot": False,
    }
