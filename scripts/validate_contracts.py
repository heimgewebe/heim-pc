#!/usr/bin/env python3
"""Validate heim-pc data against explicitly resolved canonical Metarepo schemas."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, List, Sequence, Tuple

from jsonschema import ValidationError, validate

from contract_source import ContractSourceError, resolve_contract_source
import utils


def validate_zones(config_path: str, schema_path: str) -> bool:
    """Validates the zones configuration."""
    utils.log_info(f'Validating {config_path} against canonical JSON schema {schema_path}...')

    if not os.path.exists(config_path):
        utils.log_error(f"Config file {config_path} not found.")
        return False

    if not os.path.exists(schema_path):
        utils.log_error(f"Schema {schema_path} not found.")
        return False

    try:
        data = utils.load_yaml(config_path)
        schema = utils.load_json(schema_path)

        validate(instance=data, schema=schema)
        utils.log_info(f'OK: {config_path}')
        return True
    except ValidationError as e:
        utils.log_error(f'Validation Error in {config_path}: {e.message}')
        return False
    except Exception as e:
        utils.log_error(f'Error processing {config_path}: {e}')
        return False


def validate_state_file(data_file: str, schema_file: str, base_dir: str, schema_base_dir: str) -> bool:
    """Validates a single state file against its schema."""
    data_file_path = os.path.join(base_dir, data_file)
    schema_file_path = os.path.join(schema_base_dir, schema_file)

    if not os.path.exists(data_file_path):
        utils.log_info(f'Skipping {data_file} (not found)')
        return True
    if not os.path.exists(schema_file_path):
        utils.log_error(f'Schema {schema_file} not found in metarepo at {schema_file_path}')
        return False

    utils.log_info(f'Validating {data_file} against canonical schema {schema_file}...')
    try:
        data = utils.load_json(data_file_path)
        schema = utils.load_json(schema_file_path)

        validate(instance=data, schema=schema)
        utils.log_info(f'OK: {data_file}')
        return True
    except ValidationError as e:
        utils.log_error(f'Validation Error in {data_file}: {e.message}')
        return False
    except Exception as e:
        utils.log_error(f'Error processing {data_file}: {e}')
        return False


def _read_consumer_artifact(path: Path, relative: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ContractSourceError(
            "CONSUMER_ARTIFACT_UNREADABLE",
            f"cannot read validated consumer artifact {relative}: {exc}",
        ) from exc


def _validate_zones_bound(
    config_path: Path,
    schema: dict[str, Any],
    schema_path: str,
) -> tuple[bool, str | None]:
    utils.log_info(
        f"Validating {config_path} against canonical JSON schema {schema_path}..."
    )
    if not config_path.exists():
        utils.log_error(f"Config file {config_path} not found.")
        return False, None
    relative = "config/zones.yml"
    data_bytes = _read_consumer_artifact(config_path, relative)
    digest = hashlib.sha256(data_bytes).hexdigest()
    try:
        data = utils.yaml.safe_load(data_bytes.decode("utf-8", errors="strict"))
        validate(instance=data, schema=schema)
        utils.log_info(f"OK: {config_path}")
        return True, digest
    except ValidationError as exc:
        utils.log_error(f"Validation Error in {config_path}: {exc.message}")
        return False, digest
    except Exception as exc:
        utils.log_error(f"Error processing {config_path}: {exc}")
        return False, digest


def _validate_state_bound(
    data_file: str,
    schema_path: str,
    repo_root: Path,
    schema: dict[str, Any],
) -> tuple[bool, str]:
    data_path = repo_root / data_file
    utils.log_info(
        f"Validating {data_file} against canonical schema {schema_path}..."
    )
    data_bytes = _read_consumer_artifact(data_path, data_file)
    digest = hashlib.sha256(data_bytes).hexdigest()
    try:
        data = json.loads(data_bytes.decode("utf-8", errors="strict"))
        validate(instance=data, schema=schema)
        utils.log_info(f"OK: {data_file}")
        return True, digest
    except ValidationError as exc:
        utils.log_error(f"Validation Error in {data_file}: {exc.message}")
        return False, digest
    except Exception as exc:
        utils.log_error(f"Error processing {data_file}: {exc}")
        return False, digest


def _verify_consumer_artifacts_stable(
    repo_root: Path, artifact_hashes: dict[str, str]
) -> None:
    for relative, expected_digest in sorted(artifact_hashes.items()):
        observed = hashlib.sha256(
            _read_consumer_artifact(repo_root / relative, relative)
        ).hexdigest()
        if observed != expected_digest:
            raise ContractSourceError(
                "CONSUMER_MOVED",
                f"validated consumer artifact changed during validation: {relative}",
            )


def _consumer_git_state(repo_root: Path) -> dict[str, Any]:
    def run(*args: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_root), *args],
                check=True,
                text=True,
                capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            stderr = getattr(exc, "stderr", "") or ""
            detail = stderr.strip() or str(exc)
            raise ContractSourceError("CONSUMER_GIT_STATE", detail) from exc
        return result.stdout.strip()

    head = run("rev-parse", "HEAD").lower()
    if len(head) != 40 or any(character not in "0123456789abcdef" for character in head):
        raise ContractSourceError(
            "CONSUMER_GIT_STATE", "consumer HEAD is not a full 40-hex commit"
        )
    status = run("status", "--porcelain=v1", "--untracked-files=all")
    return {
        "repository": "heimgewebe/heim-pc",
        "head": head,
        "dirty": bool(status),
    }


def build_validation_receipt(
    *,
    repo_root: Path,
    source: Any,
    artifact_hashes: dict[str, str],
    consumer_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    artifacts = [
        {"path": relative, "sha256": digest}
        for relative, digest in sorted(artifact_hashes.items())
    ]

    return {
        "schema_version": 1,
        "contract_source": source.source_receipt(),
        "schemas": source.schema_receipts(),
        "consumer": consumer_state or _consumer_git_state(repo_root),
        "validated_artifacts": artifacts,
    }


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    payload = json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8", errors="strict")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate heim-pc contracts from one explicit, identity-bound "
            "heimgewebe/metarepo source."
        )
    )
    parser.add_argument(
        "--metarepo-source",
        help="Path to the explicit heimgewebe/metarepo Git repository root.",
    )
    parser.add_argument(
        "--metarepo-manifest",
        help=(
            "Path to a manifest binding a detached archive or approved offline "
            "cache to repository identity, commit, and schema SHA-256 values. "
            "Exactly one source argument is required."
        ),
    )
    parser.add_argument(
        "--metarepo-expected-commit",
        help="Require the resolved Metarepo source to match this exact 40-hex commit.",
    )
    parser.add_argument(
        "--allow-dirty-metarepo-for-development",
        action="store_true",
        help=(
            "Explicit local-development override for a dirty Git source. "
            "Never implied by environment or checkout layout."
        ),
    )
    parser.add_argument(
        "--receipt",
        help="Optional path for the deterministic validation receipt JSON.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    repo_root = Path(utils.get_repo_root()).resolve()

    try:
        source = resolve_contract_source(
            source_path=args.metarepo_source,
            manifest_path=args.metarepo_manifest,
            expected_commit=args.metarepo_expected_commit,
            allow_dirty=args.allow_dirty_metarepo_for_development,
        )

        utils.log_info(f"Repo root: {repo_root}")
        utils.log_info(
            "Contract source: "
            f"{source.repository}@{source.commit} "
            f"({source.source_kind}, dirty={source.dirty})"
        )
        consumer_state = _consumer_git_state(repo_root)
        artifact_hashes: dict[str, str] = {}

        zones_schema_path = "contracts/heim-pc/config/zones.schema.json"
        zones_schema = source.load_schema(zones_schema_path)
        zones_success, zones_digest = _validate_zones_bound(
            repo_root / "config/zones.yml",
            zones_schema,
            zones_schema_path,
        )
        if zones_digest is not None:
            artifact_hashes["config/zones.yml"] = zones_digest

        files_to_validate: List[Tuple[str, str]] = [
            (
                "state/uncertainties.json",
                "contracts/heim-pc/state/heim-pc.state.uncertainties.schema.json",
            ),
            (
                "state/insights.json",
                "contracts/heim-pc/state/heim-pc.state.insights.schema.json",
            ),
            (
                "state/drift.json",
                "contracts/heim-pc/state/heim-pc.state.drift.schema.json",
            ),
        ]

        state_success = True
        for data_file, schema_path in files_to_validate:
            data_path = repo_root / data_file
            if not data_path.exists():
                utils.log_info(f"Skipping {data_file} (not found)")
                continue
            schema = source.load_schema(schema_path)
            valid, digest = _validate_state_bound(
                data_file, schema_path, repo_root, schema
            )
            artifact_hashes[data_file] = digest
            if not valid:
                state_success = False

        if not zones_success or not state_success:
            raise SystemExit(1)

        # Bind success to the exact source and consumer bytes observed above.
        source.verify_stable()
        _verify_consumer_artifacts_stable(repo_root, artifact_hashes)
        if _consumer_git_state(repo_root) != consumer_state:
            raise ContractSourceError(
                "CONSUMER_MOVED",
                "heim-pc HEAD or dirty state changed during validation",
            )

        receipt = build_validation_receipt(
            repo_root=repo_root,
            source=source,
            artifact_hashes=artifact_hashes,
            consumer_state=consumer_state,
        )
        payload = json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        print(payload)
        if args.receipt:
            _write_receipt(Path(args.receipt).expanduser(), receipt)

    except ContractSourceError as exc:
        utils.log_error(str(exc))
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
