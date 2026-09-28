from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "nixos_critical_data_inventory.py"
ROOT_INVENTORY = ROOT / "scripts" / "nixos_critical_user_data_inventory.py"
spec = importlib.util.spec_from_file_location("nixos_critical_data_inventory", MODULE)
aggregate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(aggregate)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_contracts(tmp_path: Path) -> Path:
    home = {
        "schema_version": 1,
        "kind": aggregate.SCOPE_KIND,
        "scope": "critical-user-data-home",
        "scope_semantics": "whole-home-by-default",
        "root": "/home/alex",
        "logical_root": "/home/alex",
    }
    docker = {
        "schema_version": 1,
        "kind": aggregate.SCOPE_KIND,
        "scope": "critical-user-data-docker-volumes",
        "scope_semantics": "whole-root-by-default",
        "root": "/var/lib/docker/volumes",
        "logical_root": "/var/lib/docker/volumes",
    }
    home_path = tmp_path / "critical-user-home-data-contract-v1.json"
    docker_path = tmp_path / "critical-docker-volume-data-contract-v1.json"
    home_path.write_text(json.dumps(home, sort_keys=True) + "\n", encoding="utf-8")
    docker_path.write_text(json.dumps(docker, sort_keys=True) + "\n", encoding="utf-8")
    scope = {
        "schema_version": 1,
        "kind": aggregate.SCOPE_KIND,
        "scope": "critical-user-data",
        "scope_semantics": "explicit-root-set-default-include",
        "members": [
            {
                "id": "home",
                "contract_file": home_path.name,
                "contract_sha256": _sha(home_path),
                "destination": {
                    "nixos_storage_domain": "@home",
                    "logical_path": "/home/alex",
                },
                "restore_mode": "active-user-data",
            },
            {
                "id": "docker-volumes",
                "contract_file": docker_path.name,
                "contract_sha256": _sha(docker_path),
                "destination": {
                    "nixos_storage_domain": "@data",
                    "logical_path": "/var/lib/heim-pc-data/legacy-docker-volumes",
                },
                "restore_mode": "staged-archive-not-active-docker-store",
            },
        ],
        "inventory_implementation": {
            "algorithm": aggregate.AGGREGATE_ALGORITHM,
            "root_inventory_script": "scripts/nixos_critical_user_data_inventory.py",
            "root_inventory_script_sha256": _sha(ROOT_INVENTORY),
            "aggregate_inventory_script": "scripts/nixos_critical_data_inventory.py",
            "aggregate_inventory_script_sha256": _sha(MODULE),
            "member_contract_digest_bound": True,
            "source_and_restored_aggregate_inventory_sha256_must_match": True,
        },
    }
    scope_path = tmp_path / "critical-user-data-contract-v1.json"
    scope_path.write_text(json.dumps(scope, sort_keys=True) + "\n", encoding="utf-8")
    return scope_path


def _fake_root_inventory():
    class InventoryError(ValueError):
        pass

    def collect_inventory(path, *, classification_only=False, max_exclusion_samples=0):
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        scope = value["scope"]
        is_home = scope == "critical-user-data-home"
        return {
            "scope": scope,
            "authoritative_inventory": not classification_only,
            "inventory_sha256": None if classification_only else (("a" if is_home else "b") * 64),
            "record_count": 3 if is_home else 5,
            "regular_file_bytes": 11 if is_home else 17,
            "exclusion_boundary_count": 2 if is_home else 0,
        }

    return SimpleNamespace(InventoryError=InventoryError, collect_inventory=collect_inventory)


def test_aggregate_inventory_binds_both_member_digests(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    quiesced = {"count": 0}
    monkeypatch.setattr(
        aggregate,
        "_docker_quiesced",
        lambda: quiesced.__setitem__("count", quiesced["count"] + 1),
    )

    result = aggregate.collect_inventory(contract)

    expected = hashlib.sha256()
    scope = json.loads(contract.read_text(encoding="utf-8"))
    for member, digest in zip(
        sorted(scope["members"], key=lambda item: item["id"]),
        ["b" * 64, "a" * 64],
    ):
        expected.update(
            aggregate._canonical_line(
                {
                    "id": member["id"],
                    "contract_sha256": member["contract_sha256"],
                    "inventory_sha256": digest,
                }
            )
        )

    assert result["authoritative_inventory"] is True
    assert result["inventory_sha256"] == expected.hexdigest()
    assert result["member_count"] == 2
    assert result["record_count"] == 8
    assert result["regular_file_bytes"] == 28
    assert quiesced["count"] == 1


def test_classification_does_not_claim_authoritative_digest_or_require_quiesce(
    monkeypatch, tmp_path
):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    monkeypatch.setattr(
        aggregate,
        "_docker_quiesced",
        lambda: (_ for _ in ()).throw(AssertionError("classification must not require outage")),
    )

    result = aggregate.collect_inventory(contract, classification_only=True)

    assert result["authoritative_inventory"] is False
    assert result["inventory_sha256"] is None
    assert all(member["inventory_sha256"] is None for member in result["members"])


def test_aggregate_rejects_member_contract_drift(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    docker = tmp_path / "critical-docker-volume-data-contract-v1.json"
    docker.write_text(docker.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(aggregate.AggregateInventoryError, match="digest mismatch"):
        aggregate.collect_inventory(contract, classification_only=True)


def test_authoritative_inventory_fails_if_docker_is_not_quiesced(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)

    def blocked():
        raise aggregate.AggregateInventoryError("containers running")

    monkeypatch.setattr(aggregate, "_docker_quiesced", blocked)
    with pytest.raises(aggregate.AggregateInventoryError, match="containers running"):
        aggregate.collect_inventory(contract)
