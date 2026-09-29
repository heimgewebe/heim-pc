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

COLD_ROOT = "/var/lib/heim-pc-data/import/legacy-2026"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _home_contract() -> dict:
    return {
        "schema_version": 1,
        "kind": aggregate.SCOPE_KIND,
        "scope": "critical-user-data-home",
        "scope_semantics": "explicit-path-set",
        "root": "/home/alex",
        "logical_root": "/home/alex",
        "includes": [
            {
                "path": "/home/alex/collections/bibliothek",
                "class": "legacy-library-preservation",
                "rationale": "test library",
                "capture": "tree",
                "restore_mode": "cold-preservation-tree",
            },
            {
                "path": "/home/alex/repos/schotter",
                "class": "local-only-repository",
                "rationale": "test repo",
                "capture": "tree",
                "restore_mode": "cold-preservation-git-capsule",
            },
            {
                "path": "/home/alex/repos/fotoatelier",
                "class": "local-only-repository",
                "rationale": "test repo with worktree overlay",
                "capture": "tree",
                "restore_mode": "cold-preservation-git-capsule",
            },
        ],
        "materialization_policy": {
            "schema_version": 1,
            "kind": "heim_pc.critical_user_data_materialization_policy",
            "source_scope_and_nixos_target_layout_are_separate": True,
            "source_equivalent_disposable_restore_required": True,
            "cold_import_root": COLD_ROOT,
            "first_productive_boot_requires_cold_import_completion": False,
            "roles": {
                "bootstrap-direct": {
                    "classes": ["credentials-and-identity"],
                    "nixos_storage_domain": "@home",
                    "target_mapping": "same-absolute-path",
                    "source_path_is_live_target_path": True,
                    "activation": "direct-after-verified-restore",
                },
                "authority-reconcile": {
                    "classes": [
                        "grabowski-authority-state",
                        "grabowski-audit-chain",
                        "grabowski-durable-outbox",
                        "bureau-authority-state",
                        "chronik-history-state",
                        "observer-findings",
                    ],
                    "nixos_storage_domain": "@data",
                    "staging_root": COLD_ROOT + "/authority",
                    "target_mapping": "source-path-relative-to-/home/alex",
                    "source_path_is_live_target_path": False,
                    "activation": "service-specific-restore-reconcile-only",
                    "direct_activation_forbidden": True,
                },
                "cold-preservation": {
                    "classes": [
                        "legacy-library-preservation",
                        "local-only-repository",
                    ],
                    "nixos_storage_domain": "@data",
                    "staging_root": COLD_ROOT,
                    "source_path_is_live_target_path": False,
                    "activation": "future-explicit-import-only",
                    "required_before_first_productive_boot": False,
                },
            },
            "cold_entries": [
                {
                    "source_path": "/home/alex/collections/bibliothek",
                    "capsule_kind": "tree-snapshot",
                    "target_path": COLD_ROOT + "/bibliothek",
                    "manifest_path": COLD_ROOT + "/bibliothek.manifest.json",
                    "old_source_path_becomes_active_path": False,
                    "future_importer_required": True,
                },
                {
                    "source_path": "/home/alex/repos/schotter",
                    "capsule_kind": "git-bundle-plus-working-tree-overlay",
                    "bundle_path": COLD_ROOT + "/repos/schotter.gitbundle",
                    "working_tree_overlay_path": COLD_ROOT + "/repos/schotter-working-tree.tar.zst",
                    "manifest_path": COLD_ROOT + "/repos/schotter.manifest.json",
                    "bundle_mode": "--all",
                    "working_tree_overlay_policy": "required-iff-tracked-dirty-or-untracked",
                    "active_checkout_created_automatically": False,
                },
                {
                    "source_path": "/home/alex/repos/fotoatelier",
                    "capsule_kind": "git-bundle-plus-working-tree-overlay",
                    "bundle_path": COLD_ROOT + "/repos/fotoatelier.gitbundle",
                    "working_tree_overlay_path": COLD_ROOT + "/repos/fotoatelier-working-tree.tar.zst",
                    "manifest_path": COLD_ROOT + "/repos/fotoatelier.manifest.json",
                    "bundle_mode": "--all",
                    "working_tree_overlay_policy": "required-iff-tracked-dirty-or-untracked",
                    "active_checkout_created_automatically": False,
                },
            ],
            "capsule_manifest_requirements": {
                "sha256_bound": True,
                "source_path_bound": True,
                "source_inventory_sha256_bound": True,
                "git_ref_tips_bound_for_git_capsules": True,
                "git_head_bound_for_git_capsules": True,
                "working_tree_status_bound_for_git_capsules": True,
            },
        },
    }


def _write_contracts(tmp_path: Path) -> Path:
    home = _home_contract()
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
                    "nixos_storage_domain": "per-entry-policy",
                    "logical_path": "materialization-policy",
                },
                "restore_mode": "source-scope-with-role-specific-materialization",
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
            "contract_sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
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


def test_classification_does_not_claim_authoritative_digest(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)

    result = aggregate.collect_inventory(contract, classification_only=True)

    assert result["authoritative_inventory"] is False
    assert result["inventory_sha256"] is None
    assert result["members"] == [
        {
            "id": "home",
            "scope": "critical-user-data-home",
            "contract_sha256": json.loads(contract.read_text())["members"][0]["contract_sha256"],
            "inventory_sha256": None,
            "record_count": 3,
            "regular_file_bytes": 11,
            "exclusion_boundary_count": 0,
        }
    ]


def test_aggregate_rejects_member_result_contract_digest_drift(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)

    class InventoryError(ValueError):
        pass

    def collect_inventory(path, *, classification_only=False, max_exclusion_samples=0):
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return {
            "scope": value["scope"],
            "contract_sha256": "b" * 64,
            "authoritative_inventory": not classification_only,
            "inventory_sha256": None if classification_only else ("a" * 64),
            "record_count": 3,
            "regular_file_bytes": 11,
            "exclusion_boundary_count": 0,
        }

    monkeypatch.setattr(
        aggregate,
        "_load_root_inventory_module",
        lambda: SimpleNamespace(
            InventoryError=InventoryError,
            collect_inventory=collect_inventory,
        ),
    )

    with pytest.raises(
        aggregate.AggregateInventoryError,
        match="member inventory contract digest mismatch",
    ):
        aggregate.collect_inventory(contract, classification_only=True)


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


def test_aggregate_rejects_materialization_back_to_legacy_library_path(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    scope = json.loads(contract.read_text())
    home_path = tmp_path / scope["members"][0]["contract_file"]
    home = json.loads(home_path.read_text())
    library = next(
        item
        for item in home["materialization_policy"]["cold_entries"]
        if item["source_path"] == "/home/alex/collections/bibliothek"
    )
    library["target_path"] = "/home/alex/collections/bibliothek"
    home_path.write_text(json.dumps(home, sort_keys=True) + "\n")
    scope["members"][0]["contract_sha256"] = _sha(home_path)
    contract.write_text(json.dumps(scope, sort_keys=True) + "\n")
    with pytest.raises(aggregate.AggregateInventoryError, match="library preservation policy"):
        aggregate.collect_inventory(contract, classification_only=True)


def test_aggregate_rejects_weakened_capsule_manifest_binding(monkeypatch, tmp_path):
    contract = _write_contracts(tmp_path)
    monkeypatch.setattr(aggregate, "_load_root_inventory_module", _fake_root_inventory)
    scope = json.loads(contract.read_text())
    home_path = tmp_path / scope["members"][0]["contract_file"]
    home = json.loads(home_path.read_text())
    home["materialization_policy"]["capsule_manifest_requirements"] = {
        "sha256_bound": False,
        "source_path_bound": True,
        "source_inventory_sha256_bound": True,
        "git_ref_tips_bound_for_git_capsules": True,
        "git_head_bound_for_git_capsules": True,
        "working_tree_status_bound_for_git_capsules": True,
    }
    home_path.write_text(json.dumps(home, sort_keys=True) + "\n")
    scope["members"][0]["contract_sha256"] = _sha(home_path)
    contract.write_text(json.dumps(scope, sort_keys=True) + "\n")
    with pytest.raises(aggregate.AggregateInventoryError, match="manifest requirements"):
        aggregate.collect_inventory(contract, classification_only=True)