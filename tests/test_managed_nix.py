from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.managed_nix import (
    ACTIVATION_AUTHORITY_KIND,
    BUILD_REQUEST_KIND,
    CANONICAL_BUILD_ENTRYPOINT,
    ManagedNixError,
    classify_effect,
    make_activation_receipt,
    make_build_receipt,
    rollback_plan,
    sha256_json,
    validate_activation_authority,
    validate_build_receipt,
    validate_build_request,
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


def test_build_request_binds_revision_release_inputs_budgets_leases_and_exact_adapter() -> None:
    normalized = validate_build_request(request())
    assert normalized["repository"] == "heimgewebe/heim-pc"
    assert normalized["source_revision"] == REVISION
    assert normalized["control_release_set"]["digest"] == CONTROL_DIGEST
    assert normalized["nix_inputs"] == {"flake.lock": LOCK_DIGEST}
    assert normalized["effect_scope"] == "boot-critical"
    assert normalized["leases"] == sorted(normalized["leases"])
    assert normalized["entrypoint"] == list(CANONICAL_BUILD_ENTRYPOINT)


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


def test_build_request_canonicalizes_effects_without_alias_collisions() -> None:
    normalized = validate_build_request(
        request(possible_effects=["PACKAGE-SET", "audio-userspace"])
    )
    assert normalized["possible_effects"] == ["audio-userspace", "package-set"]
    with pytest.raises(ManagedNixError, match="unique after canonicalization"):
        validate_build_request(request(possible_effects=["kernel", "KERNEL"]))


def test_build_request_rejects_noncanonical_repository_identity() -> None:
    for repository in ("../repo", "./repo", "owner/..", "owner/.", "/tmp/repo", "owner/repo.git"):
        with pytest.raises(ManagedNixError, match="canonical owner/repository"):
            validate_build_request(request(repository=repository))


def test_destructive_or_ambiguous_effect_never_uses_managed_build_lane() -> None:
    with pytest.raises(ManagedNixError, match="separate destructive plan"):
        validate_build_request(request(possible_effects=["filesystem-create-destroy"]))
    with pytest.raises(ManagedNixError, match="separate destructive plan"):
        validate_build_request(request(possible_effects=["mystery-side-effect"]))


def test_closure_binding_rejects_traversal_short_or_non_nix_hashes() -> None:
    for bad in (
        "/nix/store/../../etc/x-nixos-system-y",
        "/nix/store/abc-nixos-system-heim-pc",
        "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-nixos-system-heim-pc",
        "/nix/store/00000000000000000000000000000000-not-a-system",
    ):
        with pytest.raises(ManagedNixError, match="canonical immutable NixOS"):
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
    assert built["activation_authorized"] is False
    assert len(built["build_request_sha256"]) == 64
    validate_build_receipt(built)


def test_build_receipt_revalidates_budgets_and_exact_shape() -> None:
    built = receipt()
    built["budgets"] = {"store_bytes": {"warning": 1, "hard": 2}}
    with pytest.raises(ManagedNixError, match="must define"):
        validate_build_receipt(built)

    built = receipt()
    built["surprise"] = True
    with pytest.raises(ManagedNixError, match="fields mismatch"):
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


def test_activation_requires_external_digest_binding_and_fresh_authority() -> None:
    built = receipt()
    candidate = authority(built)
    with pytest.raises(ManagedNixError, match="externally bound review authority"):
        validate_authority(built, candidate, authority_sha256="f" * 64)

    expired = authority(built, expires_at="2026-09-04T07:00:00Z")
    with pytest.raises(ManagedNixError, match="expired"):
        validate_authority(built, expired)


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


def test_contract_file_explicitly_keeps_t002_implementation_only() -> None:
    contract_path = Path(__file__).parents[1] / "nixos" / "deployment" / "contract-v1.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    assert contract["build"]["canonical_entrypoint"] == list(CANONICAL_BUILD_ENTRYPOINT)
    assert contract["activation"]["requires_external_authority_sha256"] is True
    assert contract["activation"]["self_asserted_review_flag_allowed"] is False
    assert contract["activation"]["runtime_executor_implemented_here"] is False
    assert contract["activation"]["runtime_proof_task"] == "HEIM-PC-NIXOS-MIGRATION-V1-T004"
    assert contract["activation"]["requires_independent_live_closure_readback"] is True
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
