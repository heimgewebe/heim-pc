#!/usr/bin/env python3
"""Identity-bound resolution for canonical Metarepo contract schemas."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any
from urllib.parse import urlparse

EXPECTED_REPOSITORY = "heimgewebe/metarepo"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_SOURCE_KINDS = {"detached_archive", "offline_cache"}


class ContractSourceError(RuntimeError):
    """Stable, typed contract-source failure."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _run_git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", "") or ""
        detail = stderr.strip() or str(exc)
        raise ContractSourceError("SOURCE_NOT_GIT", detail) from exc
    return result.stdout.strip()


def _repository_identity_from_remote(value: str) -> str:
    """Return owner/repo only for an explicit github.com Git remote URL."""

    raw = value.strip()
    if not raw:
        return ""

    path = ""
    if "://" in raw:
        parsed = urlparse(raw)
        if (parsed.hostname or "").lower() != "github.com":
            return ""
        if parsed.scheme.lower() not in {"https", "ssh", "git"}:
            return ""
        if parsed.query or parsed.fragment:
            return ""
        path = parsed.path
    elif ":" in raw:
        authority, candidate = raw.split(":", 1)
        host = authority.rsplit("@", 1)[-1].lower()
        if host != "github.com":
            return ""
        path = candidate
    else:
        # Bare owner/repo values are valid only inside a signed/bound manifest,
        # never as proof of a Git checkout's remote identity.
        return ""

    normalized = path.strip("/")
    if normalized.lower().endswith(".git"):
        normalized = normalized[:-4]
    parts = normalized.split("/")
    if len(parts) != 2 or not all(parts):
        return ""
    return normalized.lower()


def _validate_commit(value: str, code: str) -> str:
    commit = value.strip().lower()
    if not _HEX40.fullmatch(commit):
        raise ContractSourceError(code, "commit must be exactly 40 lowercase hex characters")
    return commit


def _relative_schema_path(value: str) -> str:
    candidate = PurePosixPath(value)
    if (
        not value
        or candidate.is_absolute()
        or ".." in candidate.parts
        or "." in candidate.parts
        or "\\" in value
    ):
        raise ContractSourceError(
            "MANIFEST_SCHEMA_PATH_INVALID",
            f"schema path must be a normalized relative POSIX path: {value!r}",
        )
    return candidate.as_posix()


def _safe_join(root: Path, relative_path: str) -> Path:
    relative = _relative_schema_path(relative_path)
    try:
        root_resolved = root.resolve(strict=True)
        target = (root_resolved / relative).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ContractSourceError(
            "SCHEMA_MISSING", f"contract schema is unavailable: {relative}"
        ) from exc
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise ContractSourceError(
            "SCHEMA_PATH_ESCAPE", f"contract schema escapes source root: {relative}"
        ) from exc
    if not target.is_file():
        raise ContractSourceError(
            "SCHEMA_MISSING", f"contract schema is not a regular file: {relative}"
        )
    return target


def _read_bytes(path: Path, code: str, detail: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ContractSourceError(code, f"{detail}: {exc}") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class ContractSource:
    """Resolved, provenance-bound contract source."""

    root: Path
    source_kind: str
    repository: str
    commit: str
    dirty: bool
    initial_git_status: str = ""
    manifest_sha256: str | None = None
    expected_schema_hashes: dict[str, str] | None = None
    consumed: dict[str, str] = field(default_factory=dict)

    def load_schema(self, relative_path: str) -> dict[str, Any]:
        relative = _relative_schema_path(relative_path)
        path = _safe_join(self.root, relative)
        data = _read_bytes(path, "SCHEMA_UNREADABLE", f"cannot read {relative}")
        digest = _sha256(data)

        if self.expected_schema_hashes is not None:
            expected = self.expected_schema_hashes.get(relative)
            if expected is None:
                raise ContractSourceError(
                    "MANIFEST_SCHEMA_UNBOUND",
                    f"manifest does not bind consumed schema: {relative}",
                )
            if digest != expected:
                raise ContractSourceError(
                    "MANIFEST_HASH_MISMATCH",
                    f"{relative} expected {expected}, observed {digest}",
                )

        try:
            loaded = json.loads(data.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractSourceError(
                "SCHEMA_INVALID_JSON", f"{relative}: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise ContractSourceError(
                "SCHEMA_INVALID_JSON", f"{relative}: schema root must be an object"
            )

        self.consumed[relative] = digest
        return loaded

    def verify_stable(self) -> None:
        for relative, expected_digest in sorted(self.consumed.items()):
            path = _safe_join(self.root, relative)
            observed = _sha256(
                _read_bytes(path, "SCHEMA_UNREADABLE", f"cannot re-read {relative}")
            )
            if observed != expected_digest:
                raise ContractSourceError(
                    "SOURCE_MOVED",
                    f"consumed schema changed during validation: {relative}",
                )

        if self.source_kind == "git_checkout":
            head = _run_git(self.root, "rev-parse", "HEAD").lower()
            status = _run_git(
                self.root, "status", "--porcelain=v1", "--untracked-files=all"
            )
            if head != self.commit or status != self.initial_git_status:
                raise ContractSourceError(
                    "SOURCE_MOVED",
                    "Metarepo HEAD or dirty projection changed during validation",
                )

    def source_receipt(self) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "repository": self.repository,
            "source_kind": self.source_kind,
            "commit": self.commit,
            "dirty": self.dirty,
        }
        if self.manifest_sha256 is not None:
            receipt["manifest_sha256"] = self.manifest_sha256
        return receipt

    def schema_receipts(self) -> list[dict[str, str]]:
        return [
            {"path": path, "sha256": digest}
            for path, digest in sorted(self.consumed.items())
        ]


def _resolve_git_source(
    source_path: str,
    expected_commit: str | None,
    allow_dirty: bool,
) -> ContractSource:
    try:
        root = Path(source_path).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ContractSourceError(
            "SOURCE_MISSING",
            f"explicit Metarepo Git source is unavailable: {source_path}",
        ) from exc
    if not root.is_dir():
        raise ContractSourceError("SOURCE_NOT_GIT", f"not a directory: {root}")

    try:
        top = Path(_run_git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ContractSourceError(
            "SOURCE_NOT_GIT", f"cannot resolve Git repository root: {root}"
        ) from exc
    if top != root:
        raise ContractSourceError(
            "SOURCE_NOT_REPOSITORY_ROOT",
            f"explicit source must be the Git repository root: {root}",
        )

    origin = _run_git(root, "config", "--get", "remote.origin.url")
    repository = _repository_identity_from_remote(origin)
    if repository != EXPECTED_REPOSITORY:
        raise ContractSourceError(
            "SOURCE_WRONG_REPOSITORY",
            f"expected GitHub repository {EXPECTED_REPOSITORY}; explicit origin did not resolve to that canonical identity",
        )

    head = _validate_commit(
        _run_git(root, "rev-parse", "HEAD").lower(), "SOURCE_COMMIT_INVALID"
    )
    if expected_commit is not None:
        expected = _validate_commit(expected_commit, "EXPECTED_COMMIT_INVALID")
        if head != expected:
            raise ContractSourceError(
                "SOURCE_COMMIT_MISMATCH",
                f"expected {expected}, observed {head}",
            )

    status = _run_git(root, "status", "--porcelain=v1", "--untracked-files=all")
    dirty = bool(status)
    if dirty and not allow_dirty:
        raise ContractSourceError(
            "SOURCE_DIRTY",
            "Metarepo source has tracked or untracked changes; "
            "use --allow-dirty-metarepo-for-development only for an intentional local check",
        )

    return ContractSource(
        root=root,
        source_kind="git_checkout",
        repository=repository,
        commit=head,
        dirty=dirty,
        initial_git_status=status,
    )


def _resolve_manifest_source(
    manifest_path: str,
    expected_commit: str | None,
) -> ContractSource:
    try:
        manifest_file = Path(manifest_path).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ContractSourceError(
            "MANIFEST_MISSING", f"contract source manifest is unavailable: {manifest_path}"
        ) from exc
    if not manifest_file.is_file():
        raise ContractSourceError(
            "MANIFEST_INVALID", f"manifest is not a regular file: {manifest_file}"
        )

    raw_bytes = _read_bytes(
        manifest_file, "MANIFEST_INVALID", "cannot read contract source manifest"
    )
    try:
        raw = json.loads(raw_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractSourceError("MANIFEST_INVALID", str(exc)) from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ContractSourceError(
            "MANIFEST_INVALID", "schema_version must be integer 1"
        )

    repository_value = raw.get("repository")
    if (
        not isinstance(repository_value, str)
        or repository_value.strip().lower() != EXPECTED_REPOSITORY
    ):
        raise ContractSourceError(
            "SOURCE_WRONG_REPOSITORY",
            f"manifest must bind repository {EXPECTED_REPOSITORY}",
        )
    repository = EXPECTED_REPOSITORY

    commit = _validate_commit(str(raw.get("commit", "")), "MANIFEST_COMMIT_INVALID")
    if expected_commit is not None:
        expected = _validate_commit(expected_commit, "EXPECTED_COMMIT_INVALID")
        if commit != expected:
            raise ContractSourceError(
                "SOURCE_COMMIT_MISMATCH",
                f"expected {expected}, manifest binds {commit}",
            )

    source_kind = raw.get("source_kind")
    if source_kind not in _MANIFEST_SOURCE_KINDS:
        raise ContractSourceError(
            "MANIFEST_INVALID",
            "source_kind must be detached_archive or offline_cache",
        )

    source_root_raw = raw.get("source_root")
    if not isinstance(source_root_raw, str) or not source_root_raw:
        raise ContractSourceError(
            "MANIFEST_INVALID", "source_root must be a non-empty relative path"
        )
    source_root_path = PurePosixPath(source_root_raw)
    if (
        source_root_path.is_absolute()
        or ".." in source_root_path.parts
        or "\\" in source_root_raw
    ):
        raise ContractSourceError(
            "MANIFEST_PATH_ESCAPE", "source_root must remain below manifest directory"
        )
    manifest_parent = manifest_file.parent.resolve()
    try:
        root = (manifest_parent / source_root_path.as_posix()).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ContractSourceError(
            "MANIFEST_INVALID", "source_root is unavailable"
        ) from exc
    try:
        root.relative_to(manifest_parent)
    except ValueError as exc:
        raise ContractSourceError(
            "MANIFEST_PATH_ESCAPE", "source_root escapes manifest directory"
        ) from exc
    if not root.is_dir():
        raise ContractSourceError(
            "MANIFEST_INVALID", "source_root does not resolve to a directory"
        )

    schemas_raw = raw.get("schemas")
    if not isinstance(schemas_raw, dict) or not schemas_raw:
        raise ContractSourceError(
            "MANIFEST_INVALID", "schemas must be a non-empty path-to-SHA-256 object"
        )
    expected_hashes: dict[str, str] = {}
    for raw_path, raw_digest in schemas_raw.items():
        if not isinstance(raw_path, str) or not isinstance(raw_digest, str):
            raise ContractSourceError(
                "MANIFEST_INVALID", "schema paths and SHA-256 values must be strings"
            )
        path = _relative_schema_path(raw_path)
        digest = raw_digest.lower()
        if not _HEX64.fullmatch(digest):
            raise ContractSourceError(
                "MANIFEST_INVALID", f"invalid SHA-256 for {path}"
            )
        expected_hashes[path] = digest

    return ContractSource(
        root=root,
        source_kind=str(source_kind),
        repository=repository,
        commit=commit,
        dirty=False,
        manifest_sha256=_sha256(raw_bytes),
        expected_schema_hashes=expected_hashes,
    )


def resolve_contract_source(
    *,
    source_path: str | None,
    manifest_path: str | None,
    expected_commit: str | None,
    allow_dirty: bool,
) -> ContractSource:
    """Resolve exactly one explicit Metarepo source and fail closed otherwise."""

    if bool(source_path) == bool(manifest_path):
        raise ContractSourceError(
            "SOURCE_SELECTION",
            "exactly one of --metarepo-source or --metarepo-manifest is required",
        )
    if manifest_path is not None and allow_dirty:
        raise ContractSourceError(
            "DIRTY_OVERRIDE_NOT_APPLICABLE",
            "--allow-dirty-metarepo-for-development is valid only for a Git checkout",
        )
    if source_path is not None:
        return _resolve_git_source(source_path, expected_commit, allow_dirty)
    assert manifest_path is not None
    return _resolve_manifest_source(manifest_path, expected_commit)
