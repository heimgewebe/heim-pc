import hashlib
import importlib.util
import json
import os
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


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _contracts(tmp_path: Path) -> tuple[Path, Path]:
    recovery = json.loads((ROOT / "nixos" / "production" / "recovery-contract-v1.json").read_text())
    lifecycle = json.loads((ROOT / "nixos" / "production" / "nix-lifecycle-contract-v1.json").read_text())
    recovery_path = tmp_path / "recovery-contract.json"
    lifecycle_path = tmp_path / "lifecycle-contract.json"
    recovery_path.write_text(json.dumps(recovery, sort_keys=True) + "\n", encoding="utf-8")
    lifecycle_path.write_text(json.dumps(lifecycle, sort_keys=True) + "\n", encoding="utf-8")
    recovery_path.chmod(0o644)
    lifecycle_path.chmod(0o644)
    return recovery_path, lifecycle_path


def _fixture(tmp_path: Path):
    recovery_path, lifecycle_path = _contracts(tmp_path)
    recovery = json.loads(recovery_path.read_text())
    ids = [item["id"] for item in recovery["required_evidence"]]
    receipts = []
    receipt_paths = {}
    for index, evidence_id in enumerate(ids):
        path = tmp_path / f"receipt-{index}.json"
        value = {
            "schema_version": 1,
            "kind": ready.RECOVERY_RECEIPT_KIND,
            "evidence_id": evidence_id,
            "status": "passed",
            "source_revision": REVISION,
            "recovery_contract_sha256": _sha(recovery_path),
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
        "recovery_contract_sha256": _sha(recovery_path),
        "nix_lifecycle_contract_sha256": _sha(lifecycle_path),
        "recovery_evidence_receipts": receipts,
        "observed_at": "2026-09-18T09:55:00Z",
        "freshness_seconds": recovery["evidence_freshness"]["maximum_age_seconds"],
        "production_effects_authorized": False,
    }
    _write_private(bundle_path, bundle)
    return bundle_path, recovery_path, lifecycle_path, receipt_paths


def _validate(fx):
    bundle, recovery, lifecycle, _receipts = fx
    return ready.validate_readiness(
        bundle,
        source_revision=REVISION,
        recovery_contract_path=recovery,
        lifecycle_contract_path=lifecycle,
        now=NOW,
    )


def test_valid_private_readiness_bundle_binds_all_receipts(tmp_path):
    fx = _fixture(tmp_path)
    result = _validate(fx)
    recovery = json.loads(fx[1].read_text())
    assert [item["evidence_id"] for item in result["receipts"]] == [
        item["id"] for item in recovery["required_evidence"]
    ]
    assert result["production_effects_authorized"] is False


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
        )
