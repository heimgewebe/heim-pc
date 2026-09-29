from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import socket
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "nixos_critical_user_data_inventory.py"
spec = importlib.util.spec_from_file_location(
    "nixos_critical_user_data_inventory", MODULE
)
inventory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(inventory)



REAL_VERIFY_AUTHORITATIVE_SOURCE_STABILITY = (
    inventory._verify_authoritative_source_stability
)


@pytest.fixture(autouse=True)
def _bypass_authoritative_source_stability_for_low_level_unit_tests():
    original = inventory._verify_authoritative_source_stability
    original_verified_execution = inventory._VERIFIED_EXECUTION
    inventory._verify_authoritative_source_stability = lambda _policy: None
    inventory._VERIFIED_EXECUTION = True
    try:
        yield
    finally:
        inventory._verify_authoritative_source_stability = original
        inventory._VERIFIED_EXECUTION = original_verified_execution


def _contract(path: Path, home: Path) -> Path:
    value = {
        "schema_version": 1,
        "kind": inventory.CONTRACT_KIND,
        "scope": "critical-user-data",
        "scope_semantics": "whole-home-by-default",
        "root": str(home),
        "logical_root": str(home),
        "inventory": {
            "schema": inventory.INVENTORY_KIND,
            "algorithm": inventory.ALGORITHM,
            "same_filesystem_only": True,
            "follow_symlinks": False,
            "regular_file_content_sha256": True,
            "directory_mode_bound": True,
            "regular_file_mode_bound": True,
            "uid_gid_bound": True,
            "explicit_ancestor_metadata_bound": True,
            "xattrs_sha256_bound": True,
            "symlink_target_bound": True,
            "special_files": "excluded-runtime-only",
            "unreadable_included_path": "fail",
            "changed_during_hash": "fail",
            "authoritative_source_stability": inventory.SOURCE_STABILITY_MODE,
        },
        "exclusions": {
            "top_level_prefixes": [
                {
                    "prefix": ".grabowski-task-output-",
                    "class": "transient-agent-output",
                    "rationale": "test transient",
                }
            ],
            "roots": [
                {
                    "path": str(home / ".cache"),
                    "class": "cache",
                    "rationale": "test cache",
                }
            ],
            "file_name_prefixes_under": [],
            "file_name_prefix_suffixes_under": [],
            "directory_names_under": [
                {
                    "root": str(home / "repos"),
                    "names": ["node_modules", "target"],
                    "class": "repository-generated-state",
                    "rationale": "test generated",
                }
            ],
        },
        "required_classes": ["user-data-under-home"],
        "off_host_restore": {
            "backup_must_be_complete_for_scope": True,
            "target_must_be_independent": True,
            "disposable_restore_target_required": True,
            "network_required_for_restore": False,
            "source_and_restored_inventory_sha256_must_match": True,
        },
        "does_not_establish": ["successful restore"],
    }
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    home.mkdir()
    (home / "docs").mkdir()
    (home / "docs" / "a.txt").write_text("alpha\n", encoding="utf-8")
    (home / "docs" / "b.txt").write_text("beta\n", encoding="utf-8")
    (home / "link").symlink_to("docs/a.txt")
    (home / ".cache").mkdir()
    (home / ".cache" / "ignored").write_text("cache-a", encoding="utf-8")
    transient = home / ".grabowski-task-output-abc"
    transient.mkdir()
    (transient / "ignored").write_text("task-a", encoding="utf-8")
    generated = home / "repos" / "demo" / "node_modules"
    generated.mkdir(parents=True)
    (generated / "ignored").write_text("dep-a", encoding="utf-8")
    contract = _contract(tmp_path / "contract.json", home)
    return contract, home


def test_inventory_is_deterministic_and_exclusions_do_not_change_digest(tmp_path):
    contract, home = _fixture(tmp_path)
    first = inventory.collect_inventory(contract)
    second = inventory.collect_inventory(contract)
    assert first == second
    assert first["authoritative_inventory"] is True
    assert first["inventory_sha256"]
    assert first["critical_scope_sha256"] == first["contract_sha256"]
    assert first["exclusion_boundary_count"] == 3
    assert first["exclusion_class_counts"] == {
        "cache": 1,
        "repository-generated-state": 1,
        "transient-agent-output": 1,
    }

    (home / ".cache" / "ignored").write_text("cache-b", encoding="utf-8")
    (home / "repos" / "demo" / "node_modules" / "ignored").write_text(
        "dep-b", encoding="utf-8"
    )
    after_excluded_change = inventory.collect_inventory(contract)
    assert after_excluded_change["inventory_sha256"] == first["inventory_sha256"]
    assert (
        after_excluded_change["exclusion_boundary_sha256"]
        == first["exclusion_boundary_sha256"]
    )


def test_inventory_binds_content_mode_and_symlink_target(tmp_path):
    contract, home = _fixture(tmp_path)
    baseline = inventory.collect_inventory(contract)["inventory_sha256"]

    file_path = home / "docs" / "a.txt"
    file_path.write_text("changed\n", encoding="utf-8")
    content_changed = inventory.collect_inventory(contract)["inventory_sha256"]
    assert content_changed != baseline

    file_path.write_text("alpha\n", encoding="utf-8")
    original_mode = file_path.stat().st_mode & 0o777
    file_path.chmod(original_mode ^ 0o100)
    mode_changed = inventory.collect_inventory(contract)["inventory_sha256"]
    assert mode_changed != baseline

    file_path.chmod(original_mode)
    link = home / "link"
    link.unlink()
    link.symlink_to("docs/b.txt")
    target_changed = inventory.collect_inventory(contract)["inventory_sha256"]
    assert target_changed != baseline


def test_classification_only_never_hashes_or_opens_regular_file_contents(tmp_path, monkeypatch):
    contract, home = _fixture(tmp_path)
    (home / "docs" / "protected.sqlite3").write_bytes(b"not-a-real-db")

    def forbidden_hash(_fd):
        raise AssertionError("classification-only must not hash file content")

    real_open = inventory.os.open

    def guarded_open(path, flags, *args, **kwargs):
        if path in {"a.txt", "protected.sqlite3"} and kwargs.get("dir_fd") is not None:
            raise AssertionError("classification-only must not open regular files")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(inventory, "_hash_fd", forbidden_hash)
    monkeypatch.setattr(inventory.os, "open", guarded_open)
    result = inventory.collect_inventory(contract, classification_only=True)
    assert result["kind"] == inventory.OBSERVATION_KIND
    assert result["authoritative_inventory"] is False
    assert result["inventory_sha256"] is None
    assert result["record_count"] > 0


def test_file_name_prefix_exclusion_is_narrow_and_attribute_bound(tmp_path):
    contract, home = _fixture(tmp_path)
    grok = home / ".grok"
    grok.mkdir()
    sentinel = grok / "sandbox-blocked.123"
    sentinel.write_bytes(b"")
    sentinel.chmod(0)
    auth = grok / "auth.json"
    auth.write_text("credential-state-a\n", encoding="utf-8")
    readable_same_prefix = grok / "sandbox-blocked.user-data"
    readable_same_prefix.write_text("must-stay-in-scope-a\n", encoding="utf-8")
    outside = home / "sandbox-blocked.456"
    outside.write_text("outside-a\n", encoding="utf-8")
    named_directory = grok / "sandbox-blocked.directory"
    named_directory.mkdir()
    nested = named_directory / "kept.txt"
    nested.write_text("nested-a\n", encoding="utf-8")

    value = json.loads(contract.read_text(encoding="utf-8"))
    value["exclusions"]["file_name_prefixes_under"] = [
        {
            "root": str(grok),
            "prefixes": ["sandbox-blocked."],
            "required_size_bytes": 0,
            "required_mode": 0,
            "class": "transient-runtime-state",
            "rationale": "test zero-byte mode-000 sentinel",
        }
    ]
    contract.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    baseline = inventory.collect_inventory(contract)
    assert baseline["exclusion_class_counts"]["transient-runtime-state"] == 1
    digest = baseline["inventory_sha256"]

    auth.write_text("credential-state-b\n", encoding="utf-8")
    assert inventory.collect_inventory(contract)["inventory_sha256"] != digest
    auth.write_text("credential-state-a\n", encoding="utf-8")

    readable_same_prefix.write_text("must-stay-in-scope-b\n", encoding="utf-8")
    assert inventory.collect_inventory(contract)["inventory_sha256"] != digest
    readable_same_prefix.write_text("must-stay-in-scope-a\n", encoding="utf-8")

    outside.write_text("outside-b\n", encoding="utf-8")
    assert inventory.collect_inventory(contract)["inventory_sha256"] != digest
    outside.write_text("outside-a\n", encoding="utf-8")

    nested.write_text("nested-b\n", encoding="utf-8")
    assert inventory.collect_inventory(contract)["inventory_sha256"] != digest


def test_file_name_prefix_exclusion_rejects_root_outside_scope(tmp_path):
    contract, home = _fixture(tmp_path)
    value = json.loads(contract.read_text(encoding="utf-8"))
    value["exclusions"]["file_name_prefixes_under"] = [
        {
            "root": str(tmp_path / "outside"),
            "prefixes": ["sandbox-blocked."],
            "required_size_bytes": 0,
            "required_mode": 0,
            "class": "transient-runtime-state",
            "rationale": "invalid test",
        }
    ]
    contract.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(inventory.InventoryError, match="strictly beneath"):
        inventory.collect_inventory(contract)


def test_file_name_prefix_suffix_exclusion_keeps_sqlite_db_and_wal_critical(
    tmp_path, monkeypatch
):
    contract, home = _fixture(tmp_path)
    state = home / ".local" / "state" / "grabowski"
    state.mkdir(parents=True)
    database = state / "resources.sqlite3"
    wal = state / "resources.sqlite3-wal"
    shm = state / "resources.sqlite3-shm"
    unrelated = state / "notes-shm"
    database.write_text("database-a\n", encoding="utf-8")
    wal.write_text("wal-a\n", encoding="utf-8")
    shm.write_bytes(b"transient-shm-a")
    unrelated.write_text("unrelated-a\n", encoding="utf-8")

    value = json.loads(contract.read_text(encoding="utf-8"))
    value["exclusions"]["file_name_prefix_suffixes_under"] = [
        {
            "root": str(state),
            "prefixes": ["resources.sqlite3"],
            "suffixes": ["-shm"],
            "class": "transient-sqlite-wal-index",
            "rationale": "test transient SQLite wal-index",
        }
    ]
    contract.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    baseline = inventory.collect_inventory(contract)
    assert baseline["exclusion_class_counts"]["transient-sqlite-wal-index"] == 1
    digest = baseline["inventory_sha256"]

    shm.write_bytes(b"transient-shm-b")
    assert inventory.collect_inventory(contract)["inventory_sha256"] == digest

    database.write_text("database-b\n", encoding="utf-8")
    assert inventory.collect_inventory(contract)["inventory_sha256"] != digest
    database.write_text("database-a\n", encoding="utf-8")

    wal.write_text("wal-b\n", encoding="utf-8")
    assert inventory.collect_inventory(contract)["inventory_sha256"] != digest
    wal.write_text("wal-a\n", encoding="utf-8")

    unrelated.write_text("unrelated-b\n", encoding="utf-8")
    assert inventory.collect_inventory(contract)["inventory_sha256"] != digest
    unrelated.write_text("unrelated-a\n", encoding="utf-8")

    real_stat = inventory.os.stat

    def vanished_shm(path, *args, **kwargs):
        if path == "resources.sqlite3-shm" and kwargs.get("dir_fd") is not None:
            raise FileNotFoundError(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(inventory.os, "stat", vanished_shm)
    vanished = inventory.collect_inventory(contract, classification_only=True)
    assert vanished["exclusion_class_counts"]["transient-sqlite-wal-index"] == 1


def test_sqlite_wal_family_retries_transient_companion_disappearance(
    tmp_path, monkeypatch
):
    contract, home = _fixture(tmp_path)
    state = home / ".local" / "state" / "grabowski"
    state.mkdir(parents=True)
    database = state / "live.sqlite3"

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE payload(value TEXT NOT NULL)")
        connection.execute("INSERT INTO payload VALUES ('alpha')")
        connection.commit()

        value = json.loads(contract.read_text(encoding="utf-8"))
        value["exclusions"]["file_name_prefix_suffixes_under"] = [
            {
                "root": str(state),
                "prefixes": ["live.sqlite3"],
                "suffixes": ["-shm"],
                "class": "transient-sqlite-wal-index",
                "rationale": "test transient SQLite wal-index",
            }
        ]
        contract.write_text(
            json.dumps(value, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        baseline = inventory.collect_inventory(contract)
        baseline_digest = baseline["inventory_sha256"]

        connection.execute("INSERT INTO payload VALUES ('beta')")
        connection.commit()
        changed = inventory.collect_inventory(contract)
        assert changed["inventory_sha256"] != baseline_digest

        real_open = inventory.os.open
        wal_open_attempts = {"count": 0}

        def transient_wal_open(path, flags, *args, **kwargs):
            if (
                path == "live.sqlite3-wal"
                and kwargs.get("dir_fd") is not None
                and wal_open_attempts["count"] == 0
            ):
                wal_open_attempts["count"] += 1
                raise FileNotFoundError(path)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(inventory.os, "open", transient_wal_open)
        retried = inventory.collect_inventory(contract)
        assert retried["authoritative_inventory"] is True
        assert wal_open_attempts["count"] == 1
    finally:
        connection.close()


def test_sqlite_wal_created_after_listing_is_still_captured_in_order(
    tmp_path, monkeypatch
):
    contract, home = _fixture(tmp_path)
    state = home / ".local" / "state" / "grabowski"
    state.mkdir(parents=True)
    database = state / "live.sqlite3"

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE payload(value TEXT NOT NULL)")
        connection.execute("INSERT INTO payload VALUES ('alpha')")
        connection.commit()

        value = json.loads(contract.read_text(encoding="utf-8"))
        value["exclusions"]["file_name_prefix_suffixes_under"] = [
            {
                "root": str(state),
                "prefixes": ["live.sqlite3"],
                "suffixes": ["-shm"],
                "class": "transient-sqlite-wal-index",
                "rationale": "test transient SQLite wal-index",
            }
        ]
        contract.write_text(
            json.dumps(value, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        baseline = inventory.collect_inventory(contract)

        real_scandir = inventory.os.scandir
        hidden = {"done": False}

        class FilteredScandir:
            def __init__(self, entries):
                self._entries = iter(entries)

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def __iter__(self):
                return self

            def __next__(self):
                return next(self._entries)

        def hide_wal_from_initial_listing(fd):
            iterator = real_scandir(fd)
            try:
                entries = list(iterator)
            finally:
                iterator.close()
            entry_names = {entry.name for entry in entries}
            if not hidden["done"] and "live.sqlite3" in entry_names:
                hidden["done"] = True
                entries = [
                    entry for entry in entries if entry.name != "live.sqlite3-wal"
                ]
            return FilteredScandir(entries)

        monkeypatch.setattr(inventory.os, "scandir", hide_wal_from_initial_listing)
        with pytest.raises(inventory.InventoryError, match="membership changed"):
            inventory.collect_inventory(contract)
        assert hidden["done"] is True
        assert baseline["authoritative_inventory"] is True
    finally:
        connection.close()


def test_explicit_sqlite_family_fails_closed_when_read_guard_unavailable(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    home.mkdir()
    database = home / "state.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE payload(value TEXT NOT NULL)")
        connection.execute("INSERT INTO payload VALUES ('alpha')")
        connection.commit()
    finally:
        connection.close()

    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(database),
            "class": "authority",
            "rationale": "consistent SQLite snapshot required",
            "capture": "sqlite-family",
            "restore_mode": "authority-reconcile",
        }],
    )

    attempts = {"count": 0}

    def unavailable_guard(*_args, **_kwargs):
        attempts["count"] += 1
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(inventory.sqlite3, "connect", unavailable_guard)
    monkeypatch.setattr(inventory.time, "sleep", lambda _seconds: None)

    with pytest.raises(inventory.InventoryError, match="SQLite family did not stabilize"):
        inventory.collect_inventory(contract)
    assert attempts["count"] == inventory.SQLITE_FAMILY_MAX_ATTEMPTS


def test_sqlite_wal_family_fails_closed_when_companion_never_stabilizes(
    tmp_path, monkeypatch
):
    contract, home = _fixture(tmp_path)
    state = home / ".local" / "state" / "grabowski"
    state.mkdir(parents=True)
    database = state / "live.sqlite3"

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE payload(value TEXT NOT NULL)")
        connection.execute("INSERT INTO payload VALUES ('alpha')")
        connection.commit()

        value = json.loads(contract.read_text(encoding="utf-8"))
        value["exclusions"]["file_name_prefix_suffixes_under"] = [
            {
                "root": str(state),
                "prefixes": ["live.sqlite3"],
                "suffixes": ["-shm"],
                "class": "transient-sqlite-wal-index",
                "rationale": "test transient SQLite wal-index",
            }
        ]
        contract.write_text(
            json.dumps(value, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        real_open = inventory.os.open

        def missing_wal_open(path, flags, *args, **kwargs):
            if path == "live.sqlite3-wal" and kwargs.get("dir_fd") is not None:
                raise FileNotFoundError(path)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(inventory.os, "open", missing_wal_open)
        with pytest.raises(inventory.InventoryError, match="SQLite family did not stabilize"):
            inventory.collect_inventory(contract)
    finally:
        connection.close()


def test_cli_source_pinning_rejects_script_digest_mismatch(
    tmp_path, monkeypatch, capsys
):
    contract, _home = _fixture(tmp_path)
    contract_sha256 = hashlib.sha256(contract.read_bytes()).hexdigest()
    called = {"value": False}

    def forbidden_collect(*_args, **_kwargs):
        called["value"] = True
        raise AssertionError("digest mismatch must fail before traversal")

    monkeypatch.setattr(inventory, "collect_inventory", forbidden_collect)
    result = inventory.main(
        [
            "--contract",
            str(contract),
            "--classification-only",
            "--expected-script-sha256",
            "0" * 64,
            "--expected-contract-sha256",
            contract_sha256,
        ]
    )
    assert result == 2
    assert called["value"] is False
    assert "blocked by a safety check" in capsys.readouterr().err


def test_cli_source_pinning_uses_validated_contract_snapshot(
    tmp_path, monkeypatch, capsys
):
    contract, _home = _fixture(tmp_path)
    script_sha256 = hashlib.sha256(MODULE.read_bytes()).hexdigest()
    contract_payload = contract.read_bytes()
    contract_sha256 = hashlib.sha256(contract_payload).hexdigest()
    real_collect = inventory.collect_inventory

    def mutate_path_then_collect(*args, **kwargs):
        contract.write_text("{}\n", encoding="utf-8")
        return real_collect(*args, **kwargs)

    monkeypatch.setattr(inventory, "collect_inventory", mutate_path_then_collect)
    result = inventory.main(
        [
            "--contract",
            str(contract),
            "--classification-only",
            "--max-exclusion-samples",
            "0",
            "--expected-script-sha256",
            script_sha256,
            "--expected-contract-sha256",
            contract_sha256,
        ]
    )
    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["critical_scope_sha256"] == contract_sha256
    assert output["authoritative_inventory"] is False


def test_runtime_socket_and_fifo_are_excluded_without_hiding_neighbor_data(tmp_path):
    contract, home = _fixture(tmp_path)
    fifo = home / "included.fifo"
    sock_path = home / "included.sock"
    neighbor = home / "runtime-neighbor.txt"
    neighbor.write_text("keep-me\n", encoding="utf-8")
    os.mkfifo(fifo)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(sock_path))
    try:
        with_runtime = inventory.collect_inventory(contract)
        assert (
            with_runtime["exclusion_class_counts"]["transient-runtime-special"]
            == 2
        )
        digest = with_runtime["inventory_sha256"]
    finally:
        sock.close()
        sock_path.unlink(missing_ok=True)
        fifo.unlink(missing_ok=True)

    without_runtime = inventory.collect_inventory(contract)
    assert without_runtime["inventory_sha256"] == digest
    neighbor.write_text("changed\n", encoding="utf-8")
    assert inventory.collect_inventory(contract)["inventory_sha256"] != digest



def test_exact_root_exclusion_precedes_stat_but_other_disappearance_fails_closed(
    tmp_path, monkeypatch
):
    contract, home = _fixture(tmp_path)
    state = home / ".local" / "state" / "grabowski"
    state.mkdir(parents=True)
    shm = state / "resources.sqlite3-shm"
    shm.write_bytes(b"transient-wal-index")

    value = json.loads(contract.read_text(encoding="utf-8"))
    value["exclusions"]["roots"].append(
        {
            "path": str(shm),
            "class": "transient-sqlite-wal-index",
            "rationale": "test exact transient sqlite wal-index",
        }
    )
    contract.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    real_stat = inventory.os.stat

    def reject_shm_stat(path, *args, **kwargs):
        if path == "resources.sqlite3-shm" and kwargs.get("dir_fd") is not None:
            raise AssertionError("exact root exclusion must be resolved before stat")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(inventory.os, "stat", reject_shm_stat)
    result = inventory.collect_inventory(contract, classification_only=True)
    assert result["exclusion_class_counts"]["transient-sqlite-wal-index"] == 1

    monkeypatch.setattr(inventory.os, "stat", real_stat)
    vanishing = home / "vanishing-critical.txt"
    vanishing.write_text("must-fail-closed\n", encoding="utf-8")

    def missing_other_path(path, *args, **kwargs):
        if path == "vanishing-critical.txt" and kwargs.get("dir_fd") is not None:
            raise FileNotFoundError(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(inventory.os, "stat", missing_other_path)
    with pytest.raises(
        inventory.InventoryError,
        match="included path cannot be read: vanishing-critical.txt",
    ):
        inventory.collect_inventory(contract, classification_only=True)


def test_unknown_special_file_type_still_fails_closed(tmp_path, monkeypatch):
    contract, home = _fixture(tmp_path)
    fifo = home / "included.fifo"
    os.mkfifo(fifo)
    try:
        monkeypatch.setattr(inventory.stat, "S_ISFIFO", lambda _mode: False)
        with pytest.raises(inventory.InventoryError, match="special file"):
            inventory.collect_inventory(contract)
    finally:
        fifo.unlink()


def test_regular_file_change_during_hash_fails_closed(tmp_path, monkeypatch):
    contract, home = _fixture(tmp_path)
    target = home / "docs" / "a.txt"
    real_hash = inventory._hash_fd
    changed = {"done": False}

    def mutate_after_read(fd):
        digest = real_hash(fd)
        if not changed["done"]:
            target.write_text("changed-during-hash\n", encoding="utf-8")
            changed["done"] = True
        return digest

    monkeypatch.setattr(inventory, "_hash_fd", mutate_after_read)
    with pytest.raises(inventory.InventoryError, match="changed during hashing"):
        inventory.collect_inventory(contract)


def test_contract_rejects_exclusion_outside_home(tmp_path):
    contract, home = _fixture(tmp_path)
    value = json.loads(contract.read_text(encoding="utf-8"))
    value["exclusions"]["roots"][0]["path"] = str(tmp_path / "outside")
    contract.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(inventory.InventoryError, match="strictly beneath"):
        inventory.collect_inventory(contract)

def _explicit_contract(path: Path, home: Path, includes: list[dict]) -> Path:
    value = {
        "schema_version": 1,
        "kind": inventory.CONTRACT_KIND,
        "scope": "critical-user-data-home",
        "scope_semantics": "explicit-path-set",
        "root": str(home),
        "logical_root": str(home),
        "inventory": {
            "schema": inventory.INVENTORY_KIND,
            "algorithm": inventory.ALGORITHM,
            "same_filesystem_only": True,
            "follow_symlinks": False,
            "regular_file_content_sha256": True,
            "directory_mode_bound": True,
            "regular_file_mode_bound": True,
            "uid_gid_bound": True,
            "explicit_ancestor_metadata_bound": True,
            "xattrs_sha256_bound": True,
            "symlink_target_bound": True,
            "special_files": "excluded-runtime-only",
            "unreadable_included_path": "fail",
            "changed_during_hash": "fail",
            "authoritative_source_stability": inventory.SOURCE_STABILITY_MODE,
        },
        "includes": includes,
    }
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_explicit_path_set_rejects_symlinked_ancestor(tmp_path):
    home = tmp_path / "home"
    outside = tmp_path / "outside"
    home.mkdir()
    outside.mkdir()
    (outside / "value.txt").write_text("outside\n", encoding="utf-8")
    (home / "alias").symlink_to(outside, target_is_directory=True)
    selected = home / "alias" / "value.txt"
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(selected),
            "class": "valuable",
            "rationale": "must not traverse symlinked ancestor",
            "capture": "file",
            "restore_mode": "private",
        }],
    )

    with pytest.raises(inventory.InventoryError, match="ancestor cannot be opened safely"):
        inventory.collect_inventory(contract)



def test_explicit_path_set_fails_if_ancestor_is_replaced_during_hash(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    parent = home / "parent"
    parent.mkdir(parents=True)
    target = parent / "value.txt"
    target.write_text("old-bytes\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(target),
            "class": "valuable",
            "rationale": "path binding must remain stable",
            "capture": "file",
            "restore_mode": "private",
        }],
    )

    real_hash = inventory._hash_fd
    changed = {"done": False}

    def replace_ancestor_after_hash(fd):
        digest = real_hash(fd)
        if not changed["done"]:
            old_parent = home / "parent-old"
            parent.rename(old_parent)
            parent.mkdir()
            (parent / "value.txt").write_text("new-bytes\n", encoding="utf-8")
            changed["done"] = True
        return digest

    monkeypatch.setattr(inventory, "_hash_fd", replace_ancestor_after_hash)
    with pytest.raises(
        inventory.InventoryError,
        match="ancestor binding changed during capture",
    ):
        inventory.collect_inventory(contract)
    assert changed["done"] is True








def _configure_fake_sysfs_block_device(
    tmp_path,
    monkeypatch,
    *,
    device: tuple[int, int],
    name: str,
    virtual: bool,
    partition: bool = False,
    read_only: bool = True,
    parent_read_only: bool = True,
) -> Path:
    sys_root = tmp_path / "sys"
    devices_root = sys_root / "devices"
    dev_block_root = sys_root / "dev" / "block"
    virtual_root = devices_root / "virtual" / "block"
    dev_block_root.mkdir(parents=True)
    if virtual:
        target = virtual_root / name
    else:
        namespace = (
            devices_root
            / "pci0000:00"
            / "0000:00:01.0"
            / "nvme"
            / "nvme0"
            / "nvme0n1"
        )
        target = namespace / "nvme0n1p3" if partition else namespace
    target.mkdir(parents=True)
    (target / "ro").write_text("1\n" if read_only else "0\n", encoding="ascii")
    (target / "holders").mkdir()
    (target / "slaves").mkdir()
    if partition:
        (target / "partition").write_text("3\n", encoding="ascii")
        (target.parent / "ro").write_text(
            "1\n" if parent_read_only else "0\n",
            encoding="ascii",
        )
    major, minor = device
    (dev_block_root / f"{major}:{minor}").symlink_to(
        target,
        target_is_directory=True,
    )
    monkeypatch.setattr(inventory, "SYS_DEV_BLOCK_ROOT", dev_block_root)
    monkeypatch.setattr(inventory, "SYS_DEVICES_ROOT", devices_root)
    monkeypatch.setattr(inventory, "VIRTUAL_BLOCK_ROOT", virtual_root)
    return target


@pytest.mark.parametrize(
    ("device", "name"),
    [
        ((7, 0), "loop0"),
        ((43, 0), "nbd0"),
        ((253, 0), "dm-0"),
        ((9, 0), "md0"),
    ],
)
def test_authoritative_block_device_backing_rejects_virtual_devices(
    tmp_path,
    monkeypatch,
    device,
    name,
):
    _configure_fake_sysfs_block_device(
        tmp_path,
        monkeypatch,
        device=device,
        name=name,
        virtual=True,
        read_only=True,
    )
    assert inventory._block_device_is_read_only(device) is True
    with pytest.raises(
        inventory.InventoryError,
        match="virtual or indirect backing",
    ):
        inventory._verify_authoritative_block_device_backing(device)


def test_authoritative_block_device_backing_accepts_read_only_physical_partition(
    tmp_path,
    monkeypatch,
):
    device = (259, 4)
    target = _configure_fake_sysfs_block_device(
        tmp_path,
        monkeypatch,
        device=device,
        name="nvme0n1",
        virtual=False,
        partition=True,
        read_only=True,
        parent_read_only=True,
    )
    (target / "slaves").rmdir()
    assert inventory._block_device_is_read_only(device) is True
    inventory._verify_authoritative_block_device_backing(device)


def test_authoritative_block_device_backing_rejects_direct_remote_scsi_partition(
    tmp_path,
    monkeypatch,
):
    device = (8, 3)
    sys_root = tmp_path / "sys"
    devices_root = sys_root / "devices"
    dev_block_root = sys_root / "dev" / "block"
    virtual_root = devices_root / "virtual" / "block"
    dev_block_root.mkdir(parents=True)
    target = (
        devices_root
        / "pci0000:00"
        / "0000:00:02.0"
        / "host6"
        / "session1"
        / "target6:0:0"
        / "6:0:0:0"
        / "block"
        / "sda"
        / "sda3"
    )
    target.mkdir(parents=True)
    (target / "ro").write_text("1\n", encoding="ascii")
    (target / "partition").write_text("3\n", encoding="ascii")
    (target / "holders").mkdir()
    (target / "slaves").mkdir()
    (target.parent / "ro").write_text("1\n", encoding="ascii")
    (dev_block_root / "8:3").symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(inventory, "SYS_DEV_BLOCK_ROOT", dev_block_root)
    monkeypatch.setattr(inventory, "SYS_DEVICES_ROOT", devices_root)
    monkeypatch.setattr(inventory, "VIRTUAL_BLOCK_ROOT", virtual_root)

    with pytest.raises(
        inventory.InventoryError,
        match="not a local PCI NVMe partition",
    ):
        inventory._verify_authoritative_block_device_backing(device)


def test_authoritative_block_device_backing_rejects_writable_parent_device(
    tmp_path,
    monkeypatch,
):
    device = (259, 4)
    _configure_fake_sysfs_block_device(
        tmp_path,
        monkeypatch,
        device=device,
        name="nvme0n1",
        virtual=False,
        partition=True,
        read_only=True,
        parent_read_only=False,
    )
    assert inventory._block_device_is_read_only(device) is True
    with pytest.raises(
        inventory.InventoryError,
        match="parent block device is writable",
    ):
        inventory._verify_authoritative_block_device_backing(device)


def test_authoritative_inventory_rejects_writable_block_device_before_hash(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        inventory,
        "_verify_authoritative_source_stability",
        REAL_VERIFY_AUTHORITATIVE_SOURCE_STABILITY,
    )
    monkeypatch.setattr(
        inventory,
        "_verify_authoritative_block_device_backing",
        lambda _device: None,
    )
    home = tmp_path / "home"
    home.mkdir()
    target = home / "value.txt"
    target.write_text("stable\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(target),
            "class": "valuable",
            "rationale": "kernel block device must be read-only",
            "capture": "file",
            "restore_mode": "private",
        }],
    )
    device = target.lstat().st_dev
    dev = (os.major(device), os.minor(device))
    monkeypatch.setattr(
        inventory,
        "_read_mountinfo",
        lambda: [{
            "device": dev,
            "root": Path("/"),
            "mount_point": Path("/"),
            "read_only": True,
        }],
    )
    monkeypatch.setattr(
        inventory,
        "_block_device_is_read_only",
        lambda _device: False,
    )
    monkeypatch.setattr(
        inventory,
        "_hash_fd",
        lambda _fd: (_ for _ in ()).throw(
            AssertionError("writable block device reached content hashing")
        ),
    )
    with pytest.raises(
        inventory.InventoryError,
        match="block device is writable",
    ):
        inventory.collect_inventory(contract)


def test_authoritative_inventory_rejects_writable_covering_mount(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        inventory,
        "_verify_authoritative_source_stability",
        REAL_VERIFY_AUTHORITATIVE_SOURCE_STABILITY,
    )
    monkeypatch.setattr(
        inventory,
        "_verify_authoritative_block_device_backing",
        lambda _device: None,
    )
    home = tmp_path / "home"
    home.mkdir()
    target = home / "value.txt"
    target.write_text("stable\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(target),
            "class": "valuable",
            "rationale": "authoritative source must be quiesced",
            "capture": "file",
            "restore_mode": "private",
        }],
    )
    device = target.lstat().st_dev
    dev = (os.major(device), os.minor(device))
    monkeypatch.setattr(inventory, "_block_device_is_read_only", lambda _device: True)
    monkeypatch.setattr(
        inventory,
        "_read_mountinfo",
        lambda: [{
            "device": dev,
            "root": Path("/"),
            "mount_point": Path("/"),
            "read_only": False,
        }],
    )
    monkeypatch.setattr(
        inventory,
        "_hash_fd",
        lambda _fd: (_ for _ in ()).throw(
            AssertionError("writable source reached content hashing")
        ),
    )
    with pytest.raises(
        inventory.InventoryError,
        match="writable in current mount view",
    ):
        inventory.collect_inventory(contract)


def test_authoritative_tree_rejects_any_writable_alias_for_source_device(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        inventory,
        "_verify_authoritative_source_stability",
        REAL_VERIFY_AUTHORITATIVE_SOURCE_STABILITY,
    )
    monkeypatch.setattr(
        inventory,
        "_verify_authoritative_block_device_backing",
        lambda _device: None,
    )
    home = tmp_path / "home"
    tree = home / "tree"
    tree.mkdir(parents=True)
    (tree / "value.txt").write_text("stable\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(tree),
            "class": "valuable",
            "rationale": "tree must have no writable alias",
            "capture": "tree",
            "restore_mode": "byte-identical",
        }],
    )
    device = tree.lstat().st_dev
    dev = (os.major(device), os.minor(device))
    monkeypatch.setattr(inventory, "_block_device_is_read_only", lambda _device: True)
    monkeypatch.setattr(
        inventory,
        "_read_mountinfo",
        lambda: [
            {
                "device": dev,
                "root": Path("/"),
                "mount_point": Path("/"),
                "read_only": True,
            },
            {
                "device": dev,
                "root": Path("/unrelated-rw-subtree"),
                "mount_point": tmp_path / "rw-alias",
                "read_only": False,
            },
        ],
    )
    with pytest.raises(
        inventory.InventoryError,
        match="writable mount alias",
    ):
        inventory.collect_inventory(contract)


def test_classification_does_not_require_source_quiescence(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        inventory,
        "_verify_authoritative_source_stability",
        REAL_VERIFY_AUTHORITATIVE_SOURCE_STABILITY,
    )
    monkeypatch.setattr(
        inventory,
        "_verify_authoritative_block_device_backing",
        lambda _device: None,
    )
    home = tmp_path / "home"
    home.mkdir()
    target = home / "value.txt"
    target.write_text("stable\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(target),
            "class": "valuable",
            "rationale": "classification remains live-safe",
            "capture": "file",
            "restore_mode": "private",
        }],
    )
    monkeypatch.setattr(
        inventory,
        "_read_mountinfo",
        lambda: (_ for _ in ()).throw(
            AssertionError("classification consulted mount topology")
        ),
    )
    result = inventory.collect_inventory(contract, classification_only=True)
    assert result["authoritative_inventory"] is False
    assert result["source_stability_verified"] is False
    assert result["source_stability_proof"] is None


def test_authoritative_inventory_rejects_tree_same_name_replace_between_passes(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    tree = home / "tree"
    tree.mkdir(parents=True)
    early = tree / "a-early.txt"
    late = tree / "z-late.txt"
    early.write_text("early-a\n", encoding="utf-8")
    late.write_text("late\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(tree),
            "class": "valuable",
            "rationale": "tree capture must converge across full passes",
            "capture": "tree",
            "restore_mode": "byte-identical",
        }],
    )

    real_hash = inventory._hash_fd
    calls = {"count": 0}

    def replace_early_after_late_hash(fd):
        digest = real_hash(fd)
        calls["count"] += 1
        if calls["count"] == 2:
            replacement = tree / ".replacement"
            replacement.write_text("early-b\n", encoding="utf-8")
            replacement.replace(early)
        return digest

    monkeypatch.setattr(inventory, "_hash_fd", replace_early_after_late_hash)
    with pytest.raises(
        inventory.InventoryError,
        match="did not converge across full stability passes",
    ):
        inventory.collect_inventory(contract)
    assert calls["count"] == 4


def test_authoritative_inventory_rejects_cross_pass_content_drift(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    home.mkdir()
    early = home / "a-early.txt"
    late = home / "z-late.txt"
    early.write_text("early-a\n", encoding="utf-8")
    late.write_text("late\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [
            {
                "path": str(early),
                "class": "valuable",
                "rationale": "captured before later work",
                "capture": "file",
                "restore_mode": "private",
            },
            {
                "path": str(late),
                "class": "valuable",
                "rationale": "later capture creates the race window",
                "capture": "file",
                "restore_mode": "private",
            },
        ],
    )

    real_hash = inventory._hash_fd
    calls = {"count": 0}

    def mutate_early_after_late_hash(fd):
        digest = real_hash(fd)
        calls["count"] += 1
        if calls["count"] == 2:
            early.write_text("early-b\n", encoding="utf-8")
        return digest

    monkeypatch.setattr(inventory, "_hash_fd", mutate_early_after_late_hash)
    with pytest.raises(
        inventory.InventoryError,
        match="did not converge across full stability passes",
    ):
        inventory.collect_inventory(contract)
    assert calls["count"] == 4


def test_authoritative_inventory_reports_two_pass_stability_proof(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "value.txt"
    target.write_text("stable\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(target),
            "class": "valuable",
            "rationale": "stable source",
            "capture": "file",
            "restore_mode": "private",
        }],
    )

    result = inventory.collect_inventory(contract)
    assert result["authoritative_inventory"] is True
    assert result["stability_pass_count"] == 2
    assert result["stability_proof"] == "two-consecutive-identical-full-captures"
    assert result["source_stability_verified"] is True
    assert result["source_stability_proof"] == inventory.SOURCE_STABILITY_MODE


def test_explicit_path_set_excludes_unlisted_data_by_default(tmp_path):
    home = tmp_path / "home"
    keep = home / "keep"
    drop = home / "drop"
    keep.mkdir(parents=True)
    drop.mkdir()
    (keep / "value.txt").write_text("kept\n", encoding="utf-8")
    (drop / "value.txt").write_text("unlisted-a\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(keep),
            "class": "valuable",
            "rationale": "selected test data",
            "capture": "tree",
            "restore_mode": "byte-identical",
        }],
    )

    baseline = inventory.collect_inventory(contract)
    (drop / "value.txt").write_text("unlisted-b\n", encoding="utf-8")
    after_unlisted_change = inventory.collect_inventory(contract)
    assert after_unlisted_change["inventory_sha256"] == baseline["inventory_sha256"]

    (keep / "value.txt").write_text("changed\n", encoding="utf-8")
    after_selected_change = inventory.collect_inventory(contract)
    assert after_selected_change["inventory_sha256"] != baseline["inventory_sha256"]


def test_explicit_records_bind_uid_and_gid(tmp_path, monkeypatch):
    home = tmp_path / "home"
    keep = home / "keep"
    keep.mkdir(parents=True)
    (keep / "value.txt").write_text("kept\n", encoding="utf-8")
    (keep / "link").symlink_to("value.txt")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(keep),
            "class": "valuable",
            "rationale": "selected test data",
            "capture": "tree",
            "restore_mode": "byte-identical",
        }],
    )
    seen = []
    real = inventory._canonical_line

    def capture(value):
        if isinstance(value, dict) and value.get("type") in {"directory", "regular", "symlink"}:
            seen.append(dict(value))
        return real(value)

    monkeypatch.setattr(inventory, "_canonical_line", capture)
    inventory.collect_inventory(contract)
    assert seen
    assert all("uid" in item and "gid" in item for item in seen)


def test_explicit_file_ancestor_metadata_changes_inventory_digest(tmp_path):
    home = tmp_path / "home"
    parent = home / ".claude"
    parent.mkdir(parents=True)
    target = parent / "credential"
    target.write_text("secret-ish\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(target),
            "class": "credential",
            "rationale": "selected credential",
            "capture": "file",
            "restore_mode": "private",
        }],
    )

    baseline = inventory.collect_inventory(contract)
    parent.chmod(0o777)
    changed = inventory.collect_inventory(contract)

    assert changed["inventory_sha256"] != baseline["inventory_sha256"]


def test_explicit_file_xattr_changes_inventory_digest(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "credential"
    target.write_text("secret-ish\n", encoding="utf-8")
    try:
        os.setxattr(target, "user.heim-pc-inventory-test", b"one")
    except OSError as exc:
        if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM}:
            pytest.skip("test filesystem does not support user xattrs")
        raise
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(target),
            "class": "credential",
            "rationale": "selected credential",
            "capture": "file",
            "restore_mode": "private",
        }],
    )

    baseline = inventory.collect_inventory(contract)
    os.setxattr(target, "user.heim-pc-inventory-test", b"two")
    changed = inventory.collect_inventory(contract)

    assert changed["inventory_sha256"] != baseline["inventory_sha256"]


def test_explicit_ancestor_records_are_deduplicated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    parent = home / ".claude"
    parent.mkdir(parents=True)
    first = parent / "a"
    second = parent / "b"
    first.write_text("a\n", encoding="utf-8")
    second.write_text("b\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [
            {
                "path": str(first),
                "class": "credential",
                "rationale": "first credential",
                "capture": "file",
                "restore_mode": "private",
            },
            {
                "path": str(second),
                "class": "credential",
                "rationale": "second credential",
                "capture": "file",
                "restore_mode": "private",
            },
        ],
    )
    seen = []
    real = inventory._canonical_line

    def capture(value):
        if isinstance(value, dict) and value.get("type") == "directory":
            seen.append(value.get("path"))
        return real(value)

    monkeypatch.setattr(inventory, "_canonical_line", capture)
    inventory.collect_inventory(contract)

    assert seen.count(".claude") == 2


def test_explicit_tree_fails_if_directory_membership_changes_during_hash(tmp_path, monkeypatch):
    home = tmp_path / "home"
    keep = home / "keep"
    keep.mkdir(parents=True)
    (keep / "a.txt").write_text("a\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(keep),
            "class": "valuable",
            "rationale": "selected test data",
            "capture": "tree",
            "restore_mode": "byte-identical",
        }],
    )
    real_scandir = inventory.os.scandir
    calls = {"count": 0}

    def racing_scandir(target):
        entries = list(real_scandir(target))
        calls["count"] += 1
        if calls["count"] == 1:
            (keep / "late.txt").write_text("late\n", encoding="utf-8")
        return iter(entries)

    monkeypatch.setattr(inventory.os, "scandir", racing_scandir)
    with pytest.raises(inventory.InventoryError, match="membership changed"):
        inventory.collect_inventory(contract)


def test_explicit_classification_does_not_open_selected_file_contents(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "credential"
    target.write_text("secret-ish\n", encoding="utf-8")
    contract = _explicit_contract(
        tmp_path / "explicit.json",
        home,
        [{
            "path": str(target),
            "class": "credential",
            "rationale": "selected file",
            "capture": "file",
            "restore_mode": "private",
        }],
    )

    real_open = inventory.os.open
    def guarded_open(path, flags, *args, **kwargs):
        if path == target.name and kwargs.get("dir_fd") is not None:
            raise AssertionError("classification-only opened selected file content")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(inventory.os, "open", guarded_open)
    result = inventory.collect_inventory(contract, classification_only=True)
    assert result["authoritative_inventory"] is False
    assert result["inventory_sha256"] is None
    assert result["record_count"] == 2
    assert result["stability_pass_count"] == 1
    assert result["stability_proof"] == "classification-only-single-pass"
