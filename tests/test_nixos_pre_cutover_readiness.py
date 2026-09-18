import hashlib
import importlib.util
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "nixos_pre_cutover_readiness.py"
spec = importlib.util.spec_from_file_location("nixos_pre_cutover_readiness", MODULE)
ready = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ready)

REVISION = "a" * 40
NOW = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)

TEST_ATTESTATION_POLICY = {
    "status": "provisioned",
    "trust_model": "github-artifact-attestation",
    "repository": "heimgewebe/recovery-evidence-authority",
    "signer_workflow": (
        "heimgewebe/recovery-evidence-authority/.github/workflows/recovery-evidence.yml"
    ),
    "signer_digest": "1" * 40,
    "source_digest": "2" * 40,
    "source_ref": "refs/heads/main",
    "predicate_type": "https://heimgewebe.local/attestations/nixos-recovery-evidence/v1",
    "deny_self_hosted_runners": True,
    "attestation_predicate_source_revision_bound": True,
    "producer_receipt_digest_bound": True,
    "provisioning_authority": "later-cutover-process",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _sha_json(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _synthetic_attestation_verifier(argv: list[str]) -> subprocess.CompletedProcess:
    assert argv[:3] == [ready.GH_BIN, "attestation", "verify"]
    subject_path = Path(argv[3])
    bundle_path = Path(argv[argv.index("--bundle") + 1])
    assert bundle_path.is_file()
    subject = json.loads(subject_path.read_text(encoding="utf-8"))
    evidence = subject["evidence"]
    predicate = {
        "schema_version": 1,
        "kind": ready.RECOVERY_ATTESTATION_KIND,
        "provenance_kind": subject["kind"],
        "provenance_sha256": hashlib.sha256(subject_path.read_bytes()).hexdigest(),
        "producer": subject["producer"],
        "evidence_id": subject["evidence_id"],
        "evidence_scope": subject["evidence_scope"],
        "evidence_schema": subject["evidence_schema"],
        "evidence_sha256": _sha_json(evidence),
        "producer_receipt_sha256": evidence["producer_receipt_sha256"],
        "source_revision": subject["source_revision"],
        "recovery_contract_sha256": subject["recovery_contract_sha256"],
        "observed_at": subject["observed_at"],
        "production_effects_authorized": False,
    }
    stdout = json.dumps([
        {"verificationResult": {"statement": {"predicate": predicate}}}
    ]).encode("utf-8")
    return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")


def _contracts(tmp_path: Path, *, provisioned: bool = True) -> tuple[Path, Path]:
    recovery = json.loads((ROOT / "nixos" / "production" / "recovery-contract-v1.json").read_text())
    lifecycle = json.loads((ROOT / "nixos" / "production" / "nix-lifecycle-contract-v1.json").read_text())
    if provisioned:
        recovery["evidence_attestation"] = dict(TEST_ATTESTATION_POLICY)
    recovery_path = tmp_path / "recovery-contract.json"
    lifecycle_path = tmp_path / "lifecycle-contract.json"
    recovery_path.write_text(json.dumps(recovery, sort_keys=True) + "\n", encoding="utf-8")
    lifecycle_path.write_text(json.dumps(lifecycle, sort_keys=True) + "\n", encoding="utf-8")
    recovery_path.chmod(0o644)
    lifecycle_path.chmod(0o644)
    return recovery_path, lifecycle_path


def _provenance(
    *,
    requirement: dict,
    kind: str,
    schema: str,
    recovery_sha256: str,
    observed_at: str,
    receipt_digit: str,
) -> dict:
    return {
        "schema_version": 1,
        "kind": kind,
        "evidence_id": requirement["id"],
        "evidence_scope": requirement["scope"],
        "source_revision": REVISION,
        "recovery_contract_sha256": recovery_sha256,
        "status": "passed",
        "observed_at": observed_at,
        "producer": requirement["producer"],
        "evidence_schema": schema,
        "evidence": {
            "schema_version": 1,
            "kind": schema,
            "result": "passed",
            "producer_receipt_sha256": receipt_digit * 64,
        },
        "production_effects_authorized": False,
    }


def _fixture(tmp_path: Path, *, provisioned: bool = True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    recovery_path, lifecycle_path = _contracts(tmp_path, provisioned=provisioned)
    recovery = json.loads(recovery_path.read_text())
    recovery_sha = _sha(recovery_path)
    receipts = []
    receipt_paths = {}
    for index, requirement in enumerate(recovery["required_evidence"]):
        evidence_id = requirement["id"]
        path = tmp_path / f"receipt-{index}.json"

        evidence_provenance_path = tmp_path / f"evidence-provenance-{index}.json"
        _write_private(
            evidence_provenance_path,
            _provenance(
                requirement=requirement,
                kind=ready.RECOVERY_EVIDENCE_PROVENANCE_KIND,
                schema=requirement["evidence_schema"],
                recovery_sha256=recovery_sha,
                observed_at="2026-09-18T09:50:00Z",
                receipt_digit="a",
            ),
        )
        evidence_attestation_path = tmp_path / f"evidence-attestation-{index}.json"
        _write_private(evidence_attestation_path, {"synthetic_sigstore_bundle": evidence_id})

        if requirement["requires_restore_test"]:
            restore_provenance_path = tmp_path / f"restore-provenance-{index}.json"
            _write_private(
                restore_provenance_path,
                _provenance(
                    requirement=requirement,
                    kind=ready.RECOVERY_RESTORE_TEST_PROVENANCE_KIND,
                    schema=requirement["restore_test_schema"],
                    recovery_sha256=recovery_sha,
                    observed_at="2026-09-18T09:45:00Z",
                    receipt_digit="b",
                ),
            )
            restore_attestation_path = tmp_path / f"restore-attestation-{index}.json"
            _write_private(
                restore_attestation_path,
                {"synthetic_sigstore_bundle": evidence_id + "-restore"},
            )
            restore_test = {
                "status": "passed",
                "observed_at": "2026-09-18T09:45:00Z",
                "evidence_provenance_path": str(restore_provenance_path),
                "evidence_provenance_sha256": _sha(restore_provenance_path),
                "evidence_attestation_path": str(restore_attestation_path),
                "evidence_attestation_sha256": _sha(restore_attestation_path),
            }
        else:
            restore_test = {"status": "not-required"}

        value = {
            "schema_version": 1,
            "kind": ready.RECOVERY_RECEIPT_KIND,
            "evidence_id": evidence_id,
            "evidence_scope": requirement["scope"],
            "requires_restore_test": requirement["requires_restore_test"],
            "evidence_provenance_path": str(evidence_provenance_path),
            "evidence_provenance_sha256": _sha(evidence_provenance_path),
            "evidence_attestation_path": str(evidence_attestation_path),
            "evidence_attestation_sha256": _sha(evidence_attestation_path),
            "restore_test": restore_test,
            "status": "passed",
            "source_revision": REVISION,
            "recovery_contract_sha256": recovery_sha,
            "observed_at": "2026-09-18T09:50:00Z",
            "production_effects_authorized": False,
        }
        _write_private(path, value)
        receipt_paths[evidence_id] = path
        receipts.append({"evidence_id": evidence_id, "path": str(path), "sha256": _sha(path)})

    bundle_path = tmp_path / "readiness.json"
    bundle = {
        "schema_version": 1,
        "kind": ready.READINESS_KIND,
        "source_revision": REVISION,
        "recovery_contract_sha256": recovery_sha,
        "nix_lifecycle_contract_sha256": _sha(lifecycle_path),
        "recovery_evidence_receipts": receipts,
        "observed_at": "2026-09-18T09:55:00Z",
        "freshness_seconds": recovery["evidence_freshness"]["maximum_age_seconds"],
        "production_effects_authorized": False,
    }
    _write_private(bundle_path, bundle)
    return bundle_path, recovery_path, lifecycle_path, receipt_paths


def _validate(fx, *, verifier=_synthetic_attestation_verifier):
    bundle, recovery, lifecycle, _receipts = fx
    return ready.validate_readiness(
        bundle,
        source_revision=REVISION,
        recovery_contract_path=recovery,
        lifecycle_contract_path=lifecycle,
        now=NOW,
        attestation_verifier=verifier,
    )


def test_unprovisioned_external_trust_root_blocks_readiness(tmp_path):
    fx = _fixture(tmp_path, provisioned=False)
    with pytest.raises(
        ready.ReadinessError,
        match="attestation trust root is not provisioned",
    ):
        _validate(fx)


@pytest.mark.parametrize(
    "repository",
    ["heimgewebe/heim-pc", "HEIMGEWEBE/HEIM-PC"],
)
def test_same_repository_attestation_is_not_independent(tmp_path, repository):
    fx = _fixture(tmp_path)
    recovery = json.loads(fx[1].read_text())
    policy = dict(recovery["evidence_attestation"])
    policy["repository"] = repository
    policy["signer_workflow"] = (
        repository + "/.github/workflows/nixos-recovery-evidence-attest.yml"
    )
    recovery["evidence_attestation"] = policy
    fx[1].write_text(json.dumps(recovery, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(
        ready.ReadinessError,
        match="not an independent exact producer",
    ):
        _validate(fx)


def test_non_string_recovery_evidence_id_is_rejected_cleanly():
    recovery = json.loads(
        (ROOT / "nixos" / "production" / "recovery-contract-v1.json").read_text()
    )
    recovery["required_evidence"][0]["id"] = 7
    with pytest.raises(
        ready.ReadinessError,
        match="evidence requirement is invalid",
    ):
        ready._recovery_policy(recovery)


def test_valid_private_readiness_bundle_binds_all_receipts(tmp_path):
    fx = _fixture(tmp_path)
    result = _validate(fx)
    recovery = json.loads(fx[1].read_text())
    assert [item["evidence_id"] for item in result["receipts"]] == [
        item["id"] for item in recovery["required_evidence"]
    ]
    assert result["production_effects_authorized"] is False
    requirements = {
        item["id"]: item for item in recovery["required_evidence"]
    }
    assert all(
        item["evidence_scope"] == requirements[item["evidence_id"]]["scope"]
        for item in result["evidence_summary"]
    )
    assert all(
        item["restore_test_status"]
        == ("passed" if item["restore_test_required"] else "not-required")
        for item in result["evidence_summary"]
    )


def _rewrite_receipt_and_rebind(fx, evidence_id, transform):
    path = fx[3][evidence_id]
    receipt = json.loads(path.read_text())
    transform(receipt)
    _write_private(path, receipt)
    bundle = json.loads(fx[0].read_text())
    for binding in bundle["recovery_evidence_receipts"]:
        if binding["evidence_id"] == evidence_id:
            binding["sha256"] = _sha(path)
    _write_private(fx[0], bundle)


def test_readiness_bundle_wrong_mode_is_rejected(tmp_path):
    fx = _fixture(tmp_path)
    fx[0].chmod(0o640)
    with pytest.raises(ready.ReadinessError, match="mode"):
        _validate(fx)


def test_readiness_source_revision_is_exact(tmp_path):
    fx = _fixture(tmp_path)
    bundle = json.loads(fx[0].read_text())
    bundle["source_revision"] = "b" * 40
    _write_private(fx[0], bundle)
    with pytest.raises(ready.ReadinessError, match="source revision"):
        _validate(fx)


@pytest.mark.parametrize("which", ["recovery", "lifecycle"])
def test_contract_digest_mismatch_is_rejected(tmp_path, which):
    fx = _fixture(tmp_path)
    bundle = json.loads(fx[0].read_text())
    key = "recovery_contract_sha256" if which == "recovery" else "nix_lifecycle_contract_sha256"
    bundle[key] = "0" * 64
    _write_private(fx[0], bundle)
    with pytest.raises(ready.ReadinessError, match="contract digest"):
        _validate(fx)


def test_missing_receipt_is_rejected(tmp_path):
    fx = _fixture(tmp_path)
    bundle = json.loads(fx[0].read_text())
    bundle["recovery_evidence_receipts"].pop()
    _write_private(fx[0], bundle)
    with pytest.raises(ready.ReadinessError, match="evidence set mismatch"):
        _validate(fx)


def test_foreign_receipt_is_rejected(tmp_path):
    fx = _fixture(tmp_path)
    bundle = json.loads(fx[0].read_text())
    foreign_path = tmp_path / "foreign.json"
    _write_private(foreign_path, {"foreign": True})
    bundle["recovery_evidence_receipts"].append({
        "evidence_id": "foreign",
        "path": str(foreign_path),
        "sha256": _sha(foreign_path),
    })
    _write_private(fx[0], bundle)
    with pytest.raises(ready.ReadinessError, match="evidence set mismatch"):
        _validate(fx)


def test_bound_receipt_file_must_exist(tmp_path):
    fx = _fixture(tmp_path)
    next(iter(fx[3].values())).unlink()
    with pytest.raises(ready.ReadinessError, match="cannot be opened safely"):
        _validate(fx)

def test_duplicate_evidence_id_is_rejected(tmp_path):
    fx = _fixture(tmp_path)
    bundle = json.loads(fx[0].read_text())
    bundle["recovery_evidence_receipts"].append(dict(bundle["recovery_evidence_receipts"][0]))
    _write_private(fx[0], bundle)
    with pytest.raises(ready.ReadinessError, match="duplicate evidence id"):
        _validate(fx)


def test_receipt_status_must_pass(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, path = next(iter(fx[3].items()))
    receipt = json.loads(path.read_text())
    receipt["status"] = "failed"
    _write_private(path, receipt)
    bundle = json.loads(fx[0].read_text())
    for binding in bundle["recovery_evidence_receipts"]:
        if binding["evidence_id"] == evidence_id:
            binding["sha256"] = _sha(path)
    _write_private(fx[0], bundle)
    with pytest.raises(ready.ReadinessError, match="did not pass"):
        _validate(fx)


def test_receipt_scope_must_match_contract(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id = next(iter(fx[3]))
    _rewrite_receipt_and_rebind(
        fx, evidence_id, lambda receipt: receipt.__setitem__("evidence_scope", "foreign-scope")
    )
    with pytest.raises(ready.ReadinessError, match="evidence scope mismatch"):
        _validate(fx)


def test_receipt_restore_requirement_must_match_contract(tmp_path):
    fx = _fixture(tmp_path)
    recovery = json.loads(fx[1].read_text())
    evidence_id = next(item["id"] for item in recovery["required_evidence"] if item["requires_restore_test"])
    _rewrite_receipt_and_rebind(
        fx, evidence_id, lambda receipt: receipt.__setitem__("requires_restore_test", False)
    )
    with pytest.raises(ready.ReadinessError, match="restore-test requirement mismatch"):
        _validate(fx)


def test_required_restore_test_must_be_present_and_pass(tmp_path):
    fx = _fixture(tmp_path)
    recovery = json.loads(fx[1].read_text())
    evidence_id = next(item["id"] for item in recovery["required_evidence"] if item["requires_restore_test"])
    _rewrite_receipt_and_rebind(
        fx, evidence_id, lambda receipt: receipt.__setitem__("restore_test", {"status": "not-required"})
    )
    with pytest.raises(ready.ReadinessError, match="required restore test"):
        _validate(fx)

    fx = _fixture(tmp_path / "failed")
    recovery = json.loads(fx[1].read_text())
    evidence_id = next(item["id"] for item in recovery["required_evidence"] if item["requires_restore_test"])
    def fail_restore(receipt):
        receipt["restore_test"]["status"] = "failed"
    _rewrite_receipt_and_rebind(fx, evidence_id, fail_restore)
    with pytest.raises(ready.ReadinessError, match="restore test did not pass"):
        _validate(fx)


def test_required_restore_test_provenance_and_freshness_are_bound(tmp_path):
    fx = _fixture(tmp_path)
    recovery = json.loads(fx[1].read_text())
    evidence_id = next(item["id"] for item in recovery["required_evidence"] if item["requires_restore_test"])

    def bad_digest(receipt):
        receipt["restore_test"]["evidence_provenance_sha256"] = "not-a-digest"
    _rewrite_receipt_and_rebind(fx, evidence_id, bad_digest)
    with pytest.raises(ready.ReadinessError, match="restore-test provenance digest"):
        _validate(fx)

    fx = _fixture(tmp_path / "stale")
    recovery = json.loads(fx[1].read_text())
    evidence_id = next(item["id"] for item in recovery["required_evidence"] if item["requires_restore_test"])
    def stale_restore(receipt):
        receipt["restore_test"]["observed_at"] = "2020-01-01T00:00:00Z"
    _rewrite_receipt_and_rebind(fx, evidence_id, stale_restore)
    with pytest.raises(ready.ReadinessError, match="stale"):
        _validate(fx)


def test_non_restore_evidence_must_mark_restore_test_not_required(tmp_path):
    fx = _fixture(tmp_path)
    recovery = json.loads(fx[1].read_text())
    evidence_id = next(item["id"] for item in recovery["required_evidence"] if not item["requires_restore_test"])
    def invent_restore(receipt):
        receipt["restore_test"] = {
            "status": "passed",
            "observed_at": "2026-09-18T09:45:00Z",
            "evidence_provenance_sha256": "1" * 64,
        }
    _rewrite_receipt_and_rebind(fx, evidence_id, invent_restore)
    with pytest.raises(ready.ReadinessError, match="exactly not-required"):
        _validate(fx)


def test_receipt_evidence_provenance_digest_is_required(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id = next(iter(fx[3]))
    _rewrite_receipt_and_rebind(
        fx, evidence_id, lambda receipt: receipt.__setitem__("evidence_provenance_sha256", "bad")
    )
    with pytest.raises(ready.ReadinessError, match="evidence provenance digest"):
        _validate(fx)



def test_receipt_evidence_provenance_object_is_required_and_digest_bound(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, receipt_path = next(iter(fx[3].items()))
    receipt = json.loads(receipt_path.read_text())
    provenance_path = Path(receipt["evidence_provenance_path"])
    _write_private(provenance_path, {"tampered": True})
    with pytest.raises(ready.ReadinessError, match="evidence provenance digest mismatch"):
        _validate(fx)

    fx = _fixture(tmp_path / "missing")
    evidence_id = next(iter(fx[3]))
    _rewrite_receipt_and_rebind(
        fx,
        evidence_id,
        lambda receipt: receipt.__setitem__(
            "evidence_provenance_path", str((tmp_path / "missing-object.json").absolute())
        ),
    )
    with pytest.raises(ready.ReadinessError, match="cannot be opened safely"):
        _validate(fx)


@pytest.mark.parametrize("missing_field", ["producer", "evidence"])
def test_provenance_object_requires_substantive_evidence_payload(tmp_path, missing_field):
    fx = _fixture(tmp_path)
    evidence_id, receipt_path = next(iter(fx[3].items()))
    receipt = json.loads(receipt_path.read_text())
    provenance_path = Path(receipt["evidence_provenance_path"])
    provenance = json.loads(provenance_path.read_text())
    provenance[missing_field] = "" if missing_field == "producer" else {}
    _write_private(provenance_path, provenance)

    def rebind(receipt_value):
        receipt_value["evidence_provenance_sha256"] = _sha(provenance_path)

    _rewrite_receipt_and_rebind(fx, evidence_id, rebind)
    expected = "producer mismatch" if missing_field == "producer" else "producer-schema bound"
    with pytest.raises(ready.ReadinessError, match=expected):
        _validate(fx)


def test_required_restore_test_provenance_object_is_digest_bound(tmp_path):
    fx = _fixture(tmp_path)
    recovery = json.loads(fx[1].read_text())
    evidence_id = next(
        item["id"] for item in recovery["required_evidence"] if item["requires_restore_test"]
    )
    receipt = json.loads(fx[3][evidence_id].read_text())
    provenance_path = Path(receipt["restore_test"]["evidence_provenance_path"])
    _write_private(provenance_path, {"tampered": True})
    with pytest.raises(ready.ReadinessError, match="restore-test provenance digest mismatch"):
        _validate(fx)


def test_same_bytes_provenance_replacement_is_plan_drift(tmp_path):
    fx = _fixture(tmp_path)
    snapshot = _validate(fx)
    receipt = json.loads(next(iter(fx[3].values())).read_text())
    provenance_path = Path(receipt["evidence_provenance_path"])
    payload = provenance_path.read_bytes()
    replacement = tmp_path / "replacement-provenance.json"
    replacement.write_bytes(payload)
    replacement.chmod(0o600)
    replacement.replace(provenance_path)
    with pytest.raises(ready.ReadinessError, match="drifted after plan compilation"):
        ready.revalidate_readiness(
            snapshot,
            source_revision=REVISION,
            recovery_contract_path=fx[1],
            lifecycle_contract_path=fx[2],
            now=NOW,
            attestation_verifier=_synthetic_attestation_verifier,
        )

def test_provenance_object_semantics_are_verified_after_digest_rebind(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, receipt_path = next(iter(fx[3].items()))
    receipt = json.loads(receipt_path.read_text())
    provenance_path = Path(receipt["evidence_provenance_path"])
    provenance = json.loads(provenance_path.read_text())
    provenance["evidence_id"] = "foreign-evidence"
    _write_private(provenance_path, provenance)

    def rebind(receipt_value):
        receipt_value["evidence_provenance_sha256"] = _sha(provenance_path)

    _rewrite_receipt_and_rebind(fx, evidence_id, rebind)
    with pytest.raises(ready.ReadinessError, match="evidence id mismatch"):
        _validate(fx)


def test_provenance_object_recovery_contract_digest_is_bound(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, receipt_path = next(iter(fx[3].items()))
    receipt = json.loads(receipt_path.read_text())
    provenance_path = Path(receipt["evidence_provenance_path"])
    provenance = json.loads(provenance_path.read_text())
    provenance["recovery_contract_sha256"] = "0" * 64
    _write_private(provenance_path, provenance)

    def rebind(receipt_value):
        receipt_value["evidence_provenance_sha256"] = _sha(provenance_path)

    _rewrite_receipt_and_rebind(fx, evidence_id, rebind)
    with pytest.raises(ready.ReadinessError, match="recovery contract digest mismatch"):
        _validate(fx)


def test_provenance_path_cannot_reuse_receipt_path(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, receipt_path = next(iter(fx[3].items()))

    def point_at_receipt(receipt_value):
        receipt_value["evidence_provenance_path"] = str(receipt_path)
        receipt_value["evidence_provenance_sha256"] = _sha(receipt_path)

    _rewrite_receipt_and_rebind(fx, evidence_id, point_at_receipt)
    with pytest.raises(ready.ReadinessError):
        _validate(fx)


def test_recovery_provenance_requires_external_attestation_binding(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id = next(iter(fx[3]))

    def remove_attestation(receipt):
        receipt.pop("evidence_attestation_path")
        receipt.pop("evidence_attestation_sha256")

    _rewrite_receipt_and_rebind(fx, evidence_id, remove_attestation)
    with pytest.raises(ready.ReadinessError, match="evidence attestation path"):
        _validate(fx)


def test_attestation_bundle_digest_is_bound(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, receipt_path = next(iter(fx[3].items()))
    receipt = json.loads(receipt_path.read_text())
    attestation_path = Path(receipt["evidence_attestation_path"])
    _write_private(attestation_path, {"tampered": True})
    with pytest.raises(ready.ReadinessError, match="evidence attestation digest mismatch"):
        _validate(fx)


def test_attestation_predicate_must_bind_reviewed_producer_and_schema(tmp_path):
    fx = _fixture(tmp_path)

    def bad_verifier(argv):
        result = _synthetic_attestation_verifier(argv)
        payload = json.loads(result.stdout.decode("utf-8"))
        payload[0]["verificationResult"]["statement"]["predicate"]["producer"] = "forged-producer"
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps(payload).encode("utf-8"),
            stderr=b"",
        )

    with pytest.raises(ready.ReadinessError, match="predicate does not bind"):
        _validate(fx, verifier=bad_verifier)


def test_attestation_verifier_argv_pins_external_trust_boundary(tmp_path):
    fx = _fixture(tmp_path)
    calls = []

    def recording_verifier(argv):
        calls.append(list(argv))
        return _synthetic_attestation_verifier(argv)

    _validate(fx, verifier=recording_verifier)
    assert calls
    for argv in calls:
        assert argv[:3] == [ready.GH_BIN, "attestation", "verify"]
        assert argv[argv.index("--repo") + 1] == TEST_ATTESTATION_POLICY["repository"]
        assert (
            argv[argv.index("--signer-workflow") + 1]
            == TEST_ATTESTATION_POLICY["signer_workflow"]
        )
        assert (
            argv[argv.index("--signer-digest") + 1]
            == TEST_ATTESTATION_POLICY["signer_digest"]
        )
        assert (
            argv[argv.index("--source-digest") + 1]
            == TEST_ATTESTATION_POLICY["source_digest"]
        )
        assert argv[argv.index("--source-ref") + 1] == TEST_ATTESTATION_POLICY["source_ref"]
        assert (
            argv[argv.index("--predicate-type") + 1]
            == "https://heimgewebe.local/attestations/nixos-recovery-evidence/v1"
        )
        assert "--deny-self-hosted-runners" in argv

def test_same_bytes_attestation_replacement_is_plan_drift(tmp_path):
    fx = _fixture(tmp_path)
    snapshot = _validate(fx)
    receipt = json.loads(next(iter(fx[3].values())).read_text())
    attestation_path = Path(receipt["evidence_attestation_path"])
    payload = attestation_path.read_bytes()
    replacement = tmp_path / "replacement-attestation.json"
    replacement.write_bytes(payload)
    replacement.chmod(0o600)
    replacement.replace(attestation_path)
    with pytest.raises(ready.ReadinessError, match="drifted after plan compilation"):
        ready.revalidate_readiness(
            snapshot,
            source_revision=REVISION,
            recovery_contract_path=fx[1],
            lifecycle_contract_path=fx[2],
            now=NOW,
            attestation_verifier=_synthetic_attestation_verifier,
        )


def test_attestation_path_cannot_reuse_provenance_path(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, receipt_path = next(iter(fx[3].items()))
    receipt = json.loads(receipt_path.read_text())
    provenance_path = Path(receipt["evidence_provenance_path"])

    def reuse_provenance(receipt_value):
        receipt_value["evidence_attestation_path"] = str(provenance_path)
        receipt_value["evidence_attestation_sha256"] = _sha(provenance_path)

    _rewrite_receipt_and_rebind(fx, evidence_id, reuse_provenance)
    with pytest.raises(ready.ReadinessError, match="reuses a bound evidence path"):
        _validate(fx)


def test_receipt_digest_mismatch_is_rejected(tmp_path):
    fx = _fixture(tmp_path)
    _write_private(next(iter(fx[3].values())), {"tampered": True})
    with pytest.raises(ready.ReadinessError, match="digest mismatch"):
        _validate(fx)


def test_receipt_wrong_recovery_digest_is_rejected(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, path = next(iter(fx[3].items()))
    receipt = json.loads(path.read_text())
    receipt["recovery_contract_sha256"] = "0" * 64
    _write_private(path, receipt)
    bundle = json.loads(fx[0].read_text())
    for binding in bundle["recovery_evidence_receipts"]:
        if binding["evidence_id"] == evidence_id:
            binding["sha256"] = _sha(path)
    _write_private(fx[0], bundle)
    with pytest.raises(ready.ReadinessError, match="recovery contract digest mismatch"):
        _validate(fx)


def test_receipt_stale_or_future_is_rejected(tmp_path):
    fx = _fixture(tmp_path)
    evidence_id, path = next(iter(fx[3].items()))
    receipt = json.loads(path.read_text())
    receipt["observed_at"] = "2020-01-01T00:00:00Z"
    _write_private(path, receipt)
    bundle = json.loads(fx[0].read_text())
    for binding in bundle["recovery_evidence_receipts"]:
        if binding["evidence_id"] == evidence_id:
            binding["sha256"] = _sha(path)
    _write_private(fx[0], bundle)
    with pytest.raises(ready.ReadinessError, match="stale"):
        _validate(fx)


def test_symlink_private_file_is_rejected(tmp_path):
    fx = _fixture(tmp_path)
    link = tmp_path / "readiness-link.json"
    link.symlink_to(fx[0])
    with pytest.raises(ready.ReadinessError, match="symlink|traverse"):
        ready.validate_readiness(
            link,
            source_revision=REVISION,
            recovery_contract_path=fx[1],
            lifecycle_contract_path=fx[2],
            now=NOW,
            attestation_verifier=_synthetic_attestation_verifier,
        )


def test_symlink_parent_component_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    fx = _fixture(real)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(ready.ReadinessError, match="symlink|traverse"):
        ready.validate_readiness(
            linked / fx[0].name,
            source_revision=REVISION,
            recovery_contract_path=fx[1],
            lifecycle_contract_path=fx[2],
            now=NOW,
            attestation_verifier=_synthetic_attestation_verifier,
        )


def test_same_bytes_file_replacement_is_still_plan_drift(tmp_path):
    fx = _fixture(tmp_path)
    snapshot = _validate(fx)
    payload = fx[0].read_bytes()
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(payload)
    replacement.chmod(0o600)
    replacement.replace(fx[0])
    with pytest.raises(ready.ReadinessError, match="drifted after plan compilation"):
        ready.revalidate_readiness(
            snapshot,
            source_revision=REVISION,
            recovery_contract_path=fx[1],
            lifecycle_contract_path=fx[2],
            now=NOW,
            attestation_verifier=_synthetic_attestation_verifier,
        )


@pytest.mark.parametrize("target", ["bundle", "receipt", "recovery-contract", "lifecycle-contract"])
def test_revalidation_detects_any_plan_time_drift(tmp_path, target):
    fx = _fixture(tmp_path)
    snapshot = _validate(fx)
    if target == "bundle":
        value = json.loads(fx[0].read_text())
        value["observed_at"] = "2026-09-18T09:54:59Z"
        _write_private(fx[0], value)
    elif target == "receipt":
        path = next(iter(fx[3].values()))
        value = json.loads(path.read_text())
        value["note"] = "changed after plan"
        _write_private(path, value)
    elif target == "recovery-contract":
        value = json.loads(fx[1].read_text())
        value["status"] = "changed"
        fx[1].write_text(json.dumps(value, sort_keys=True) + "\n")
    else:
        value = json.loads(fx[2].read_text())
        value["automatic_gc"] = True
        fx[2].write_text(json.dumps(value, sort_keys=True) + "\n")
    with pytest.raises(ready.ReadinessError):
        ready.revalidate_readiness(
            snapshot,
            source_revision=REVISION,
            recovery_contract_path=fx[1],
            lifecycle_contract_path=fx[2],
            now=NOW,
            attestation_verifier=_synthetic_attestation_verifier,
        )
