from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.storage_inventory import (
    PolicyError,
    collect,
    load_policy,
    publish_snapshot,
    scan_path,
)


def make_policy(path: Path, producer_path: Path, *, warning: int = 10, hard: int = 20) -> Path:
    policy = {
        "schema_version": 1,
        "kind": "heim_pc.storage_lifecycle_policy",
        "policy_id": "test",
        "classes": {
            "temporary_workspace": {"automatic_cleanup": False},
            "regenerable_cache": {"automatic_cleanup": False},
        },
        "filesystem_thresholds_percent": {"notice": 60, "warning": 75, "critical": 85},
        "global_temporary_budget_bytes": {"warning": 1000, "hard": 2000},
        "snapshot_retention": {"max_count": 2},
        "producers": [{
            "id": "fixture",
            "class": "temporary_workspace",
            "owner": "test-owner",
            "paths": [str(producer_path)],
            "budget_bytes": {"warning": warning, "hard": hard},
            "cleanup_strategy": "none",
        }],
        "safety": {
            "cross_filesystems": False,
            "does_not_establish": ["permission_to_delete"],
        },
    }
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_scan_does_not_follow_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "large").write_bytes(b"x" * (1024 * 1024))
    root = tmp_path / "root"
    root.mkdir()
    (root / "small").write_bytes(b"x" * 5)
    (root / "link").symlink_to(outside, target_is_directory=True)

    result = scan_path(root)

    assert result.file_count == 2
    assert result.size_bytes < 100_000


def test_scan_counts_hard_linked_storage_only_once(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    original = root / "original"
    original.write_bytes(b"x" * 4096)
    before = scan_path(root)
    (root / "second").hardlink_to(original)

    after = scan_path(root)

    assert after.file_count == 2
    assert after.size_bytes == before.size_bytes


def test_sparse_file_reports_allocated_and_apparent_sizes_separately(tmp_path: Path) -> None:
    sparse = tmp_path / "sparse"
    with sparse.open("wb") as handle:
        handle.seek((16 * 1024 * 1024) - 1)
        handle.write(b"x")

    result = scan_path(sparse)

    assert result.apparent_size_bytes == 16 * 1024 * 1024
    assert result.size_bytes <= result.apparent_size_bytes


def test_collect_reports_hard_limit_without_cleanup_authority(tmp_path: Path) -> None:
    producer = tmp_path / "producer"
    producer.mkdir()
    (producer / "payload").write_bytes(b"x" * 64)
    policy_path = make_policy(tmp_path / "policy.json", producer, warning=1, hard=2)

    payload = collect(load_policy(policy_path), home=tmp_path, filesystem_root=tmp_path)

    record = payload["producers"][0]
    assert record["status"] == "hard_limit"
    assert record["automatic_cleanup_authorized"] is False
    assert payload["does_not_establish"] == ["permission_to_delete"]


def test_missing_path_is_explicitly_degraded(tmp_path: Path) -> None:
    policy_path = make_policy(tmp_path / "policy.json", tmp_path / "missing")

    payload = collect(load_policy(policy_path), home=tmp_path, filesystem_root=tmp_path)

    assert payload["producers"][0]["status"] == "missing"
    assert payload["summary"]["degraded_count"] == 1


def test_snapshot_retention_is_bounded_and_latest_is_written(tmp_path: Path) -> None:
    state = tmp_path / "state"
    for index in range(3):
        payload = {"kind": "heim_pc.storage_inventory", "policy_id": "test", "generated_at": f"2026-07-14T00:00:0{index}Z", "value": index}
        publish_snapshot(state, payload, max_count=2)

    snapshots = sorted(state.glob("storage-*.json"))
    latest = json.loads((state / "latest.json").read_text())

    assert len(snapshots) == 2
    assert latest["value"] == 2


def test_snapshot_retention_preserves_foreign_matching_files(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    foreign = state / "storage-foreign.json"
    foreign.write_text("{}")
    for index in range(2):
        publish_snapshot(
            state,
            {
                "kind": "heim_pc.storage_inventory",
                "policy_id": "test",
                "generated_at": f"2026-07-14T00:01:0{index}Z",
            },
            max_count=1,
        )

    assert foreign.exists()
    assert len([path for path in state.glob("storage-*.json") if path != foreign]) == 1


def test_snapshot_state_directory_must_not_be_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "state"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="real directory"):
        publish_snapshot(
            link,
            {
                "kind": "heim_pc.storage_inventory",
                "policy_id": "test",
                "generated_at": "2026-07-14T00:02:00Z",
            },
            max_count=1,
        )


def test_collect_reports_large_unowned_candidates_without_cleanup_authority(tmp_path: Path) -> None:
    discovery_root = tmp_path / "repos"
    discovery_root.mkdir()
    known = discovery_root / ".known-worktrees"
    known.mkdir()
    (known / "payload").write_bytes(b"k" * 4096)
    unknown = discovery_root / ".unknown-worktrees"
    unknown.mkdir()
    (unknown / "payload").write_bytes(b"u" * 4096)
    policy_path = make_policy(tmp_path / "policy.json", known)
    data = json.loads(policy_path.read_text())
    data["unowned_discovery"] = {
        "minimum_bytes": 1,
        "roots": [{
            "path": str(discovery_root),
            "max_depth": 1,
            "name_globs": [".*-worktrees"],
        }],
    }
    policy_path.write_text(json.dumps(data))

    payload = collect(load_policy(policy_path), home=tmp_path, filesystem_root=tmp_path)

    assert [item["path"] for item in payload["unowned_candidates"]] == [str(unknown)]
    assert payload["unowned_candidates"][0]["automatic_cleanup_authorized"] is False
    assert payload["summary"]["unowned_candidate_count"] == 1


def test_policy_rejects_duplicate_producer_ids(tmp_path: Path) -> None:
    producer = tmp_path / "producer"
    policy_path = make_policy(tmp_path / "policy.json", producer)
    data = json.loads(policy_path.read_text())
    data["producers"].append(dict(data["producers"][0]))
    policy_path.write_text(json.dumps(data))

    with pytest.raises(PolicyError, match="unique"):
        load_policy(policy_path)
