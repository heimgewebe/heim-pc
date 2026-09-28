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
        "scope_semantics": "explicit-path-set",
        "root": "/home/alex",
        "logical_root": "/home/alex",
    }
    home_path = tmp_path / "critical-user-home-data-contract-v1.json"
    home_path.write_text(json.dumps(home, sort_keys=True) + "\n", encoding="utf-8")
    scope = {
        "schema_version": 1,
        "kind": aggregate.SCOPE_KIND,
        "scope": "critical-user-data",
        "scope_semantics": "explicit-positive-selection",
        "members": [
            {
                "id": "home",
                "contract_file": home_path.name,
                "contract_sha256": _sha(home_path),
                "destination": {
                    "nixos_storage_domain": "@home",
                    "logical_path": "/home/alex",
                },
                "restore_mode": "explicit-path-restore-with-authority-reconciliation",
            }
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
        assert value["scope"] == "critical-user-data-home"
        return {
            "scope": value["scope"],
            "authoritative_inventory": not classification_only,
            "inventory_sha256": None if classification_only else ("a" * 64),
            "record_count": 3,
            "regular_file_bytes": 11,
            "exclusion_boundary_count": 0,
        }

    return SimpleNamespace(InventoryError=InventoryError, collect_inventory=collect_inventory)


def test_aggregate_inventory_binds_explicit_member_digest(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)

    result = aggregate.collect_inventory(contract)

    scope = json.loads(contract.read_text(encoding="utf-8"))
    member = scope["members"][0]
    expected = hashlib.sha256()
    expected.update(
        aggregate._canonical_line(
            {
                "id": "home",
                "contract_sha256": member["contract_sha256"],
                "inventory_sha256": "a" * 64,
            }
        )
    )
    assert result["authoritative_inventory"] is True
    assert result["inventory_sha256"] == expected.hexdigest()
    assert result["scope_semantics"] == "explicit-positive-selection"
    assert result["member_count"] == 1
    assert result["record_count"] == 3
    assert result["regular_file_bytes"] == 11


def test_classification_does_not_claim_authoritative_digest_or_require_docker(
    monkeypatch, tmp_path
):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    monkeypatch.setattr(
        aggregate,
        "_docker_quiesced",
        lambda: (_ for _ in ()).throw(AssertionError("Docker is outside canonical scope")),
    )

    result = aggregate.collect_inventory(contract, classification_only=True)

    assert result["authoritative_inventory"] is False
    assert result["inventory_sha256"] is None
    assert result["members"] == [
        {
            "id": "home",
            "scope": "critical-user-data-home",
            "contract_sha256": json.loads(contract.read_text())["members"][0][
                "contract_sha256"
            ],
            "inventory_sha256": None,
            "record_count": 3,
            "regular_file_bytes": 11,
            "exclusion_boundary_count": 0,
        }
    ]


def test_aggregate_rejects_member_contract_drift(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    home = tmp_path / "critical-user-home-data-contract-v1.json"
    home.write_text(home.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(aggregate.AggregateInventoryError, match="digest mismatch"):
        aggregate.collect_inventory(contract, classification_only=True)


def test_aggregate_rejects_old_default_include_semantics(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    value = json.loads(contract.read_text())
    value["scope_semantics"] = "explicit-root-set-default-include"
    contract.write_text(json.dumps(value) + "\n")
    with pytest.raises(aggregate.AggregateInventoryError, match="identity"):
        aggregate.collect_inventory(contract, classification_only=True)


def test_aggregate_rejects_docker_member(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    value = json.loads(contract.read_text())
    value["members"].append(
        {
            "id": "docker-volumes",
            "contract_file": "critical-docker-volume-data-contract-v1.json",
            "contract_sha256": "b" * 64,
            "destination": {"nixos_storage_domain": "@data", "logical_path": "/legacy"},
            "restore_mode": "staged",
        }
    )
    contract.write_text(json.dumps(value) + "\n")
    with pytest.raises(aggregate.AggregateInventoryError, match="member set"):
        aggregate.collect_inventory(contract, classification_only=True)
