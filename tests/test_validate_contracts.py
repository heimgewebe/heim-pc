from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Callable

import pytest


def test_validate_zones_reports_schema_failure_as_one_stable_diagnostic(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
    real_yaml_module: Any,
) -> None:
    config = write_utf8(tmp_path / "zones.yml", "{}\n")
    schema = write_utf8(
        tmp_path / "zones.schema.json",
        json.dumps({"type": "object", "required": ["zones"]}),
    )
    module = load_script_module("scripts/validate_contracts.py")
    module.utils.yaml = real_yaml_module

    assert module.validate_zones(str(config), str(schema)) is False

    captured = capsys.readouterr()
    assert captured.out == (
        f"Validating {config} against canonical JSON schema {schema}...\n"
    )
    assert captured.err == (
        f"::error::Validation Error in {config}: 'zones' is a required property\n"
    )


def test_validate_state_file_reports_json_and_schema_failures_atomically(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    load_script_module: Callable[[str], Any],
    write_utf8: Callable[[Path, str], Path],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    data_root = tmp_path / "data"
    schema_root = tmp_path / "schemas"
    write_utf8(data_root / "state" / "broken.json", "{")
    write_utf8(
        schema_root / "state" / "schema.json",
        json.dumps({"type": "object", "required": ["version"]}),
    )

    assert (
        module.validate_state_file(
            "state/broken.json",
            "state/schema.json",
            str(data_root),
            str(schema_root),
        )
        is False
    )
    first = capsys.readouterr()
    assert first.err == (
        "::error::Error processing state/broken.json: "
        "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)\n"
    )

    write_utf8(data_root / "state" / "broken.json", "{}")
    assert (
        module.validate_state_file(
            "state/broken.json",
            "state/schema.json",
            str(data_root),
            str(schema_root),
        )
        is False
    )
    second = capsys.readouterr()
    assert second.err == (
        "::error::Validation Error in state/broken.json: "
        "'version' is a required property\n"
    )


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def _init_git_repo(root: Path, repository: str = "heimgewebe/metarepo") -> str:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    _git(root, "config", "user.email", "tests@example.invalid")
    _git(root, "config", "user.name", "Contract Tests")
    _git(
        root,
        "remote",
        "add",
        "origin",
        f"https://github.com/{repository}.git",
    )
    return ""


def _commit_all(root: Path, message: str = "fixture") -> str:
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _write_schema(path: Path, schema: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(schema, sort_keys=True).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _make_metarepo(root: Path) -> tuple[Path, str, dict[str, str]]:
    _init_git_repo(root)
    hashes = {
        "contracts/heim-pc/config/zones.schema.json": _write_schema(
            root / "contracts/heim-pc/config/zones.schema.json",
            {
                "type": "object",
                "required": ["zones"],
                "properties": {"zones": {"type": "array"}},
            },
        ),
        "contracts/heim-pc/state/heim-pc.state.uncertainties.schema.json": _write_schema(
            root / "contracts/heim-pc/state/heim-pc.state.uncertainties.schema.json",
            {"type": "object"},
        ),
        "contracts/heim-pc/state/heim-pc.state.insights.schema.json": _write_schema(
            root / "contracts/heim-pc/state/heim-pc.state.insights.schema.json",
            {"type": "object"},
        ),
        "contracts/heim-pc/state/heim-pc.state.drift.schema.json": _write_schema(
            root / "contracts/heim-pc/state/heim-pc.state.drift.schema.json",
            {"type": "object"},
        ),
    }
    return root, _commit_all(root), hashes


def test_explicit_git_source_is_identity_and_commit_bound(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    root, head, _ = _make_metarepo(tmp_path / "metarepo")

    source = module.resolve_contract_source(
        source_path=str(root),
        manifest_path=None,
        expected_commit=head,
        allow_dirty=False,
    )

    assert source.repository == "heimgewebe/metarepo"
    assert source.commit == head
    assert source.source_kind == "git_checkout"
    assert source.dirty is False


def test_missing_explicit_source_ignores_environment_and_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    sibling, _, _ = _make_metarepo(tmp_path / "_metarepo")
    monkeypatch.setenv("METAREPO_PATH", str(sibling))
    monkeypatch.setattr(module.utils, "get_repo_root", lambda: str(tmp_path / "consumer"))

    with pytest.raises(SystemExit) as exc_info:
        module.main([])

    assert exc_info.value.code == 2
    assert "SOURCE_SELECTION" in capsys.readouterr().err


def test_wrong_repository_and_wrong_commit_fail_closed(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    root, head, _ = _make_metarepo(tmp_path / "metarepo")

    _git(root, "remote", "set-url", "origin", "https://github.com/heimgewebe/not-metarepo.git")
    with pytest.raises(module.ContractSourceError) as wrong_repo:
        module.resolve_contract_source(
            source_path=str(root),
            manifest_path=None,
            expected_commit=head,
            allow_dirty=False,
        )
    assert wrong_repo.value.code == "SOURCE_WRONG_REPOSITORY"

    _git(root, "remote", "set-url", "origin", "org-236528253@github.com:heimgewebe/metarepo.git")
    with pytest.raises(module.ContractSourceError) as wrong_commit:
        module.resolve_contract_source(
            source_path=str(root),
            manifest_path=None,
            expected_commit="a" * 40,
            allow_dirty=False,
        )
    assert wrong_commit.value.code == "SOURCE_COMMIT_MISMATCH"


def test_dirty_git_source_requires_narrow_explicit_override(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    root, head, _ = _make_metarepo(tmp_path / "metarepo")
    (root / "local-only.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(module.ContractSourceError) as dirty:
        module.resolve_contract_source(
            source_path=str(root),
            manifest_path=None,
            expected_commit=head,
            allow_dirty=False,
        )
    assert dirty.value.code == "SOURCE_DIRTY"

    source = module.resolve_contract_source(
        source_path=str(root),
        manifest_path=None,
        expected_commit=head,
        allow_dirty=True,
    )
    assert source.dirty is True


@pytest.mark.parametrize("source_kind", ["detached_archive", "offline_cache"])
def test_manifest_source_binds_archive_or_offline_cache_schema_hashes(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
    source_kind: str,
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    bundle = tmp_path / source_kind
    schema_relative = "contracts/heim-pc/config/zones.schema.json"
    digest = _write_schema(
        bundle / "content" / schema_relative,
        {"type": "object"},
    )
    commit = "b" * 40
    manifest = bundle / "metarepo-contract-source.v1.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repository": "heimgewebe/metarepo",
                "commit": commit,
                "source_kind": source_kind,
                "source_root": "content",
                "schemas": {schema_relative: digest},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    source = module.resolve_contract_source(
        source_path=None,
        manifest_path=str(manifest),
        expected_commit=commit,
        allow_dirty=False,
    )
    assert source.load_schema(schema_relative) == {"type": "object"}
    source.verify_stable()
    assert source.schema_receipts() == [{"path": schema_relative, "sha256": digest}]
    assert source.source_receipt()["source_kind"] == source_kind


def test_manifest_hash_mismatch_fails_before_schema_use(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    bundle = tmp_path / "bundle"
    schema_relative = "contracts/heim-pc/config/zones.schema.json"
    _write_schema(bundle / "content" / schema_relative, {"type": "object"})
    manifest = bundle / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repository": "heimgewebe/metarepo",
                "commit": "c" * 40,
                "source_kind": "detached_archive",
                "source_root": "content",
                "schemas": {schema_relative: "0" * 64},
            }
        ),
        encoding="utf-8",
    )

    source = module.resolve_contract_source(
        source_path=None,
        manifest_path=str(manifest),
        expected_commit=None,
        allow_dirty=False,
    )
    with pytest.raises(module.ContractSourceError) as mismatch:
        source.load_schema(schema_relative)
    assert mismatch.value.code == "MANIFEST_HASH_MISMATCH"


def test_git_source_movement_after_schema_read_fails_closed(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    root, head, _ = _make_metarepo(tmp_path / "metarepo")
    relative = "contracts/heim-pc/config/zones.schema.json"
    source = module.resolve_contract_source(
        source_path=str(root),
        manifest_path=None,
        expected_commit=head,
        allow_dirty=False,
    )
    source.load_schema(relative)

    (root / relative).write_text('{"type":"array"}', encoding="utf-8")

    with pytest.raises(module.ContractSourceError) as moved:
        source.verify_stable()
    assert moved.value.code == "SOURCE_MOVED"


def test_ci_style_sibling_checkout_works_only_when_explicitly_named(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    workspace = tmp_path / "workspace"
    root, head, _ = _make_metarepo(workspace / "_metarepo")
    (workspace / "heim-pc").mkdir()

    source = module.resolve_contract_source(
        source_path=str(root),
        manifest_path=None,
        expected_commit=head,
        allow_dirty=False,
    )
    assert source.commit == head


def test_validation_receipt_binds_source_schemas_consumer_and_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    metarepo, metarepo_head, hashes = _make_metarepo(tmp_path / "metarepo")

    consumer = tmp_path / "heim-pc"
    _init_git_repo(consumer, repository="heimgewebe/heim-pc")
    config = consumer / "config/zones.yml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("zones: []\n", encoding="utf-8")
    consumer_head = _commit_all(consumer, "consumer fixture")
    monkeypatch.setattr(module.utils, "get_repo_root", lambda: str(consumer))

    receipt_path = tmp_path / "receipt.json"
    module.main(
        [
            "--metarepo-source",
            str(metarepo),
            "--metarepo-expected-commit",
            metarepo_head,
            "--receipt",
            str(receipt_path),
        ]
    )

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["contract_source"] == {
        "repository": "heimgewebe/metarepo",
        "source_kind": "git_checkout",
        "commit": metarepo_head,
        "dirty": False,
    }
    assert receipt["consumer"] == {
        "repository": "heimgewebe/heim-pc",
        "head": consumer_head,
        "dirty": False,
    }
    assert receipt["schemas"] == [
        {
            "path": "contracts/heim-pc/config/zones.schema.json",
            "sha256": hashes["contracts/heim-pc/config/zones.schema.json"],
        }
    ]
    assert receipt["validated_artifacts"] == [
        {
            "path": "config/zones.yml",
            "sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        }
    ]

    emitted = capsys.readouterr().out.splitlines()[-1]
    assert json.loads(emitted) == receipt


@pytest.mark.parametrize(
    "origin",
    ["heimgewebe/metarepo", "github.com/heimgewebe/metarepo"],
)
def test_git_source_rejects_bare_or_relative_repository_identity(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
    origin: str,
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    root, head, _ = _make_metarepo(tmp_path / "metarepo")
    _git(root, "remote", "set-url", "origin", origin)

    with pytest.raises(module.ContractSourceError) as rejected:
        module.resolve_contract_source(
            source_path=str(root),
            manifest_path=None,
            expected_commit=head,
            allow_dirty=False,
        )

    assert rejected.value.code == "SOURCE_WRONG_REPOSITORY"


def test_rejected_credential_bearing_origin_is_redacted(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    root, head, _ = _make_metarepo(tmp_path / "metarepo")
    secret = "super-secret-token"
    origin = f"https://ci-user:{secret}@github.com/heimgewebe/not-metarepo.git"
    _git(root, "remote", "set-url", "origin", origin)

    with pytest.raises(module.ContractSourceError) as rejected:
        module.resolve_contract_source(
            source_path=str(root),
            manifest_path=None,
            expected_commit=head,
            allow_dirty=False,
        )

    diagnostic = str(rejected.value)
    assert rejected.value.code == "SOURCE_WRONG_REPOSITORY"
    assert secret not in diagnostic
    assert "ci-user" not in diagnostic
    assert origin not in diagnostic


def test_consumer_artifact_movement_after_validation_fails_closed(
    tmp_path: Path,
    load_script_module: Callable[[str], Any],
) -> None:
    module = load_script_module("scripts/validate_contracts.py")
    consumer = tmp_path / "heim-pc"
    config = consumer / "config/zones.yml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("zones: []\n", encoding="utf-8")

    valid, digest = module._validate_zones_bound(
        config,
        {"type": "object", "required": ["zones"]},
        "contracts/heim-pc/config/zones.schema.json",
    )
    assert valid is True
    assert digest == hashlib.sha256(b"zones: []\n").hexdigest()

    config.write_text("zones: [changed]\n", encoding="utf-8")
    with pytest.raises(module.ContractSourceError) as moved:
        module._verify_consumer_artifacts_stable(
            consumer, {"config/zones.yml": digest}
        )
    assert moved.value.code == "CONSUMER_MOVED"
