#!/usr/bin/env python3
"""Narrow closure-bound NixOS Day-2 runtime executor.

The checked-in managed_nix contract remains validation-only.  This successor
executes only an already-built, already-authorized immutable system closure.
It does not evaluate Nix, resolve Git/branches/locks/inputs, reboot the host, or
grant itself request-staging/rootbroker authority.

Inputs are root-owned single-link 0600 JSON files below
/run/heim-pc/nixos-activation/requests/<request-id>. A privileged caller may
supply the exact digest-bound request in the same dedicated scope; this
executor stages only those fixed files. Capability authorization, scope launch,
and independent post-effect observation remain separate. This program emits
execution evidence, never the final activation or persistent-promotion receipt.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence


class RuntimeExecutorError(RuntimeError):
    """Fail-closed runtime-executor error."""


class _ExecutorInterrupted(Exception):
    """Internal controlled termination signal."""


class _ProcessTerminationUncertain(RuntimeExecutorError):
    """The mutating child/process group is not proven quiescent."""


def _load_managed_nix() -> Any:
    path = Path(__file__).resolve().with_name("managed_nix.py")
    spec = importlib.util.spec_from_file_location("heim_pc_managed_nix", path)
    if spec is None or spec.loader is None:
        raise RuntimeExecutorError("cannot load managed_nix validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


managed_nix = _load_managed_nix()

_CONTRACT_PATH = (
    Path(__file__).resolve().parents[1]
    / "nixos"
    / "deployment"
    / "runtime-executor-v1.json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
TRUSTED_UID = 0
REQUEST_ROOT = Path("/run/heim-pc/nixos-activation/requests")
CURRENT_SYSTEM_LINK = Path("/run/current-system")
SYSTEM_PROFILE_LINK = Path("/nix/var/nix/profiles/system")
BOOTED_SYSTEM_LINK = Path("/run/booted-system")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
BOOT_PROFILE_ROOT = Path("/nix/var/nix/profiles/system-profiles")
EFI_VAR_ROOT = Path("/sys/firmware/efi/efivars")
EFI_LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
LOADER_CONF = Path("/boot/loader/loader.conf")
BOOT_ENTRY_RE = re.compile(r"nixos-[A-Za-z0-9_.+\-]{1,180}\.conf\Z")
BOOT_STATE_FIELDS = (
    "current", "booted", "profile", "approved", "recovery",
    "approved_entry", "recovery_entry", "default", "sysfail",
    "oneshot", "loader_default",
)
LOCK_PATH = Path("/run/lock/heim-pc-nixos-activation.lock")
SELF_CGROUP_PATH = Path("/proc/self/cgroup")
CGROUP_ROOT = Path("/sys/fs/cgroup")
GC_ROOT_DIR = Path("/nix/var/nix/gcroots/heim-pc-day2")
DEDICATED_SCOPE_TEMPLATE = "/system.slice/heim-pc-nixos-day2-{request_id}.scope"
MAX_FILE_BYTES = 1024 * 1024
MAX_CGROUP_BYTES = 4096
MAX_CGROUP_PROCS_BYTES = 64 * 1024
MAX_CGROUP_NODES = 128
COMMAND_TIMEOUT_SECONDS = 1800
PROCESS_GROUP_QUIESCENCE_POLL_SECONDS = 0.05
NIX_RUNTIME_CONFIG = "substitute = false\nbuilders =\nmax-jobs = 0\n"
_REQUIRED_REQUEST_FILES = (
    "build-receipt.json",
    "authority.json",
    "plan.json",
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise RuntimeExecutorError(f"{name} must be lowercase SHA-256")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_contract() -> dict[str, Any]:
    try:
        raw = json.loads(_CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeExecutorError(f"cannot load runtime executor contract: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuntimeExecutorError("runtime executor contract must be an object")
    expected_top_level = {
        "schema_version",
        "kind",
        "component",
        "supported_operations",
        "request",
        "runtime",
        "execution_receipt",
        "forbidden_effects",
        "successor_boundaries",
        "persistent_state",
    }
    if set(raw) != expected_top_level:
        raise RuntimeExecutorError("runtime executor contract top-level fields drifted")
    if raw.get("schema_version") != 1:
        raise RuntimeExecutorError("unsupported runtime executor contract version")
    if raw.get("kind") != "heim_pc.nixos_activation_runtime_executor_contract":
        raise RuntimeExecutorError("unsupported runtime executor contract kind")
    if raw.get("component") != "heim-pc-nixos-activation-executor":
        raise RuntimeExecutorError("runtime executor component identity drifted")

    expected_operations = {
        "activation": {
            "plan_kind": managed_nix.ACTIVATION_PLAN_KIND,
            "executor_authority": managed_nix.ACTIVATION_EXECUTOR_AUTHORITY,
            "executable_modes": {"test": "test", "next-boot": "boot"},
            "deferred_modes": {},
        },
        "observe-next-boot": {
            "staging_receipt_file": "staging-receipt.json",
            "external_expected_sha256_required": True,
            "effect": "request-staging-and-read-only-boot-observation",
            "promotion_authorized": False,
            "persistent_state_kind": "heim_pc.nixos_persistent_runtime_state_v2",
        },
        "persistent-promotion": {
            "plan_kind": managed_nix.PERSISTENT_PROMOTION_PLAN_KIND,
            "executor_authority": managed_nix.PERSISTENT_PROMOTION_EXECUTOR_AUTHORITY,
            "switch_argument": "switch",
            "boot_critical_requires_next_boot_successor_proof": True,
            "boot_critical_execution_implemented_here": True,
            "named_approved_promotion_implemented_here": True,
            "boot_critical_staging_receipt_file": "staging-receipt.json",
            "boot_critical_external_expected_boot_id_required": True,
            "boot_critical_switch_argument": "boot",
        },
    }
    if raw.get("supported_operations") != expected_operations:
        raise RuntimeExecutorError("runtime executor operation contract drifted")

    expected_request = {
        "root": str(REQUEST_ROOT),
        "request_id_pattern": REQUEST_ID_RE.pattern,
        "required_files": list(_REQUIRED_REQUEST_FILES),
        "directory_mode": "0700",
        "file_mode": "0600",
        "owner_uid": 0,
        "single_link_required": True,
        "symlinks_allowed": False,
        "max_file_bytes": MAX_FILE_BYTES,
        "external_expected_sha256_required": True,
        "external_target_binding_required": True,
        "external_source_artifact_binding_required_for_persistent_promotion": True,
    }
    if raw.get("request") != expected_request:
        raise RuntimeExecutorError("runtime executor request contract drifted")

    expected_runtime = {
        "root_required": True,
        "lock_path": str(LOCK_PATH),
        "current_system_link": str(CURRENT_SYSTEM_LINK),
        "persistent_profile_link": str(SYSTEM_PROFILE_LINK),
        "switch_relative_path": "bin/switch-to-configuration",
        "prior_closure_nix_env_relative_path": "sw/bin/nix-env",
        "prior_closure_nix_store_relative_path": "sw/bin/nix-store",
        "target_closure_systemctl_relative_path": "sw/bin/systemctl",
        "self_cgroup_path": str(SELF_CGROUP_PATH),
        "cgroup_root": str(CGROUP_ROOT),
        "required_systemd_scope_template": DEDICATED_SCOPE_TEMPLATE,
        "scope_peer_quiescence_required": True,
        "transaction_gc_root_directory": str(GC_ROOT_DIR),
        "transaction_gc_root_roles": ["prior", "target"],
        "transaction_gc_root_registration": "nix-store-add-root-realise-existing-path",
        "transaction_gc_root_lifetime": "effect-and-recovery-transaction",
        "prior_closure_gc_root_required": True,
        "incomplete_recovery_gc_roots_retained": True,
        "nix_runtime_config": {
            "substitute": False,
            "builders": [],
            "max_jobs": 0,
        },
        "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        "source_reevaluation_allowed": False,
        "branch_resolution_allowed": False,
        "lock_resolution_allowed": False,
        "remote_input_resolution_allowed": False,
        "shell_execution_allowed": False,
        "nix_rebuild_allowed": False,
        "broad_root_shell_allowed": False,
        "request_staging_implemented_here": True,
        "rootbroker_authorization_implemented_here": False,
        "reboot_implemented_here": False,
    }
    if raw.get("runtime") != expected_runtime:
        raise RuntimeExecutorError("runtime executor effect boundary drifted")

    if raw.get("persistent_state") != {
        "schema_version": 2,
        "kind": "heim_pc.nixos_persistent_runtime_state_v2",
        "algorithm": "canonical-json-sha256-v1",
        "fields": ["schema_version", "kind", "target", "boot_state"],
        "boot_state_fields": list(BOOT_STATE_FIELDS),
        "target_source": "externally-bound-plan-target",
        "boot_state_source": "native-named-profile-and-EFI-readback",
    }:
        raise RuntimeExecutorError("persistent runtime state digest contract drifted")

    if raw.get("execution_receipt") != {
        "schema_version": 1,
        "kind": "heim_pc.nixos_activation_runtime_execution_v1",
        "result": "executed",
        "final_activation_receipt_established": False,
        "independent_runtime_readback_established": False,
        "persistent_state_observation_provenance_established": False,
        "dedicated_scope_membership_established": True,
        "transaction_gc_roots_released": True,
        "transaction_gc_root_release_established": True,
    }:
        raise RuntimeExecutorError("runtime execution receipt boundary drifted")

    if raw.get("forbidden_effects") != [
        "source-reevaluation",
        "git-resolution",
        "branch-resolution",
        "nix-input-resolution",
        "nixos-rebuild",
        "shell-eval",
        "reboot",
        "partition-table-mutation",
        "filesystem-create-destroy",
        "luks-container-mutation",
        "luks-metadata-mutation",
        "luks-keyslot-mutation",
        "efi-key-material-mutation",
        "secure-boot-key-material-mutation",
        "firmware-flash",
    ]:
        raise RuntimeExecutorError("runtime forbidden-effect contract drifted")

    if raw.get("successor_boundaries") != [
        "dedicated transient scope launch and capability authorization",
        "boot-critical one-shot post-boot proof",
        "independent live-closure readback",
        "independent persistent-state observation provenance",
        "controlled reboot and post-boot readback",
        "final activation or persistent-promotion receipt publication",
    ]:
        raise RuntimeExecutorError("runtime successor-boundary contract drifted")
    return raw

CONTRACT = _load_contract()
PERSISTENT_STATE_KIND = str(CONTRACT["persistent_state"]["kind"])


def _require_exact_mode(st: os.stat_result, expected_mode: int, label: str) -> None:
    if stat.S_IMODE(st.st_mode) != expected_mode:
        raise RuntimeExecutorError(
            f"{label} mode must be {expected_mode:04o}, got {stat.S_IMODE(st.st_mode):04o}"
        )


def _require_secure_dir(path: Path, *, label: str) -> None:
    try:
        st = path.lstat()
    except OSError as exc:
        raise RuntimeExecutorError(f"{label} is unavailable: {exc}") from exc
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeExecutorError(f"{label} must be a directory")
    if st.st_uid != TRUSTED_UID:
        raise RuntimeExecutorError(f"{label} must be owned by uid {TRUSTED_UID}")
    _require_exact_mode(st, 0o700, label)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeExecutorError(f"{label} cannot be resolved safely: {exc}") from exc
    if resolved != path:
        raise RuntimeExecutorError(f"{label} must not contain symlink indirection")


def _request_dir(request_id: str) -> Path:
    if REQUEST_ID_RE.fullmatch(request_id) is None:
        raise RuntimeExecutorError("request_id is not canonical")
    _require_secure_dir(REQUEST_ROOT, label="request root")
    candidate = REQUEST_ROOT / request_id
    if candidate.parent != REQUEST_ROOT:
        raise RuntimeExecutorError("request path escaped the canonical root")
    _require_secure_dir(candidate, label="request directory")
    return candidate


def _read_bound_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeExecutorError(f"cannot securely open request file {path.name}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeExecutorError(f"request file {path.name} must be regular")
        if st.st_uid != TRUSTED_UID:
            raise RuntimeExecutorError(
                f"request file {path.name} must be owned by uid {TRUSTED_UID}"
            )
        _require_exact_mode(st, 0o600, f"request file {path.name}")
        if st.st_nlink != 1:
            raise RuntimeExecutorError(f"request file {path.name} must have one link")
        if st.st_size <= 1 or st.st_size > MAX_FILE_BYTES:
            raise RuntimeExecutorError(f"request file {path.name} size is invalid")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != st.st_size:
            raise RuntimeExecutorError(f"request file {path.name} changed while reading")
        if os.fstat(fd).st_size != st.st_size:
            raise RuntimeExecutorError(f"request file {path.name} size changed while reading")
    finally:
        os.close(fd)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeExecutorError(f"request file {path.name} is not canonical JSON input") from exc
    if not isinstance(value, dict):
        raise RuntimeExecutorError(f"request file {path.name} must contain an object")
    return value


def _load_request(request_id: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    directory = _request_dir(request_id)
    values = tuple(_read_bound_json(directory / name) for name in _REQUIRED_REQUEST_FILES)
    return values[0], values[1], values[2]


def _require_canonical_digest(value: Mapping[str, Any], expected: str, label: str) -> str:
    expected_value = _require_sha256(expected, f"expected {label} sha256")
    actual = managed_nix.sha256_json(value)
    if actual != expected_value:
        raise RuntimeExecutorError(f"{label} does not match externally bound digest")
    return actual


def _stage_bound_request_files(
    request_id: str,
    files: Mapping[str, Any],
    expected_digests: Mapping[str, str],
) -> None:
    """Stage an exact request under the existing root-only scope lock.

    No arbitrary path or filename is accepted. Identical readback is a no-op;
    a conflicting existing request is never replaced.
    """
    if REQUEST_ID_RE.fullmatch(request_id) is None:
        raise RuntimeExecutorError("request_id is not canonical")
    if set(expected_digests) not in (
        set(_REQUIRED_REQUEST_FILES), {"staging-receipt.json"},
        set(_REQUIRED_REQUEST_FILES) | {"staging-receipt.json"},
    ) or not isinstance(files, Mapping) or set(files) != set(expected_digests):
        raise RuntimeExecutorError("invalid request bundle fields")
    encoded = {}
    for name, value in files.items():
        if not isinstance(value, dict):
            raise RuntimeExecutorError(f"request bundle {name} must be an object")
        _require_canonical_digest(value, expected_digests[name], name)
        encoded[name] = _canonical_json(value) + b"\n"
        if len(encoded[name]) > MAX_FILE_BYTES:
            raise RuntimeExecutorError(f"request bundle {name} exceeds size limit")
    _require_secure_dir(REQUEST_ROOT, label="request root")
    destination = REQUEST_ROOT / request_id
    if os.path.lexists(destination):
        directory = _request_dir(request_id)
        for name, digest in expected_digests.items():
            _require_canonical_digest(_read_bound_json(directory / name), digest, name)
        return
    try:
        # A complete directory is published atomically under the same lock
        # used by activation. Incomplete temporary directories are not requests.
        with tempfile.TemporaryDirectory(prefix=".staging-", dir=REQUEST_ROOT) as tmp:
            directory = Path(tmp)
            for name, data in encoded.items():
                fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
            if os.path.lexists(destination):
                raise RuntimeExecutorError("request destination appeared during staging")
            directory.rename(destination)
    except OSError as exc:
        raise RuntimeExecutorError(f"request staging failed: {exc}") from exc
    for name, digest in expected_digests.items():
        _require_canonical_digest(_read_bound_json(_request_dir(request_id) / name), digest, name)


def _parse_request_bundle(text: str | None) -> dict[str, Any] | None:
    if text is None:
        return None
    if len(text.encode("utf-8")) > 4 * MAX_FILE_BYTES:
        raise RuntimeExecutorError("request bundle exceeds size limit")
    try:
        value = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise RuntimeExecutorError("request bundle is not valid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeExecutorError("request bundle must be an object")
    return value


def _resolve_link(path: Path, *, label: str) -> str:
    try:
        st = path.lstat()
    except OSError as exc:
        raise RuntimeExecutorError(f"{label} link is unavailable: {exc}") from exc
    if not stat.S_ISLNK(st.st_mode):
        raise RuntimeExecutorError(f"{label} must be a symlink")
    try:
        resolved = str(path.resolve(strict=True))
    except OSError as exc:
        raise RuntimeExecutorError(f"{label} cannot be resolved: {exc}") from exc
    return resolved


def _require_link_target(path: Path, expected: str, *, label: str) -> str:
    observed = _resolve_link(path, label=label)
    if observed != expected:
        raise RuntimeExecutorError(
            f"{label} mismatch: expected {expected}, observed {observed}"
        )
    return observed

def _persistent_state_payload(
    *, target: str, boot_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the real boot default, not just the ordinary system profile.

    Version 1 aliased a successful OneShot testboot with its later Approved
    promotion. Its digests must not satisfy this version's preimage gate.
    """
    if not isinstance(boot_state, Mapping) or set(boot_state) != set(BOOT_STATE_FIELDS):
        raise RuntimeExecutorError("invalid persistent boot state fields")
    state = dict(boot_state)
    try:
        target = managed_nix._require_canonical_string(target, "target")
        for key in ("current", "booted", "profile", "approved", "recovery"):
            state[key] = managed_nix._require_closure(state[key], key)
    except managed_nix.ManagedNixError as exc:
        raise RuntimeExecutorError("invalid persistent boot state identity") from exc
    for key in ("approved_entry", "recovery_entry", "default", "sysfail", "loader_default"):
        state[key] = _boot_entry_id(state[key])
    if state["oneshot"] is not None:
        state["oneshot"] = _boot_entry_id(state["oneshot"])
    _require_approved_defaults(state)
    return {
        "schema_version": 2,
        "kind": PERSISTENT_STATE_KIND,
        "target": target,
        "boot_state": state,
    }


def persistent_state_sha256(*, target: str, boot_state: Mapping[str, Any]) -> str:
    return _sha256_json(_persistent_state_payload(target=target, boot_state=boot_state))


def _read_persistent_state_sha256(
    *, target: str, current_closure: str, profile_closure: str,
) -> str:
    # Observe using the verified running closure, never a new unapproved
    # executable selected by a prospective promotion request.
    state = _observe_boot_state(current_closure)
    if state["current"] != current_closure or state["profile"] != profile_closure:
        raise RuntimeExecutorError("persistent boot state drifted during readback")
    if state["oneshot"] is not None:
        raise RuntimeExecutorError("pending OneShot must be reconciled before promotion")
    return persistent_state_sha256(target=target, boot_state=state)


def _require_executable(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        st = resolved.stat()
    except OSError as exc:
        raise RuntimeExecutorError(f"{label} is unavailable: {exc}") from exc
    if not stat.S_ISREG(st.st_mode) or not (st.st_mode & stat.S_IXUSR):
        raise RuntimeExecutorError(f"{label} must resolve to an executable regular file")
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise RuntimeExecutorError(f"{label} executable metadata is unsafe")
    if not str(resolved).startswith("/nix/store/"):
        raise RuntimeExecutorError(f"{label} must resolve inside the immutable Nix store")
    return path


def _switch_argv(closure: str, mode: str) -> list[str]:
    path = _require_executable(
        Path(closure) / "bin" / "switch-to-configuration",
        label="switch-to-configuration",
    )
    _require_executable(
        Path(closure) / "sw" / "bin" / "systemctl",
        label="closure-bound systemctl",
    )
    return [str(path), mode]


def _profile_set_argv(executor_closure: str, target_closure: str) -> list[str]:
    nix_env = _require_executable(
        Path(executor_closure) / "sw" / "bin" / "nix-env",
        label="closure-bound nix-env",
    )
    return [
        str(nix_env),
        "--profile",
        str(SYSTEM_PROFILE_LINK),
        "--set",
        target_closure,
    ]


def _preflight_recovery_commands(prior_closure: str, mode: str) -> None:
    # Validate every closure-bound executable that _recover() may need while
    # both transaction closures are still pinned, but do not execute anything.
    _switch_argv(prior_closure, mode)
    _profile_set_argv(prior_closure, prior_closure)


def _require_recovery_transaction_state(
    *,
    prior_closure: str,
    target_closure: str,
) -> tuple[str, str]:
    allowed = {prior_closure, target_closure}
    current = _resolve_link(
        CURRENT_SYSTEM_LINK,
        label="current system before recovery mutation",
    )
    profile = _resolve_link(
        SYSTEM_PROFILE_LINK,
        label="persistent system profile before recovery mutation",
    )
    if current not in allowed:
        raise RuntimeExecutorError(
            "recovery refused because current system drifted outside bound "
            "transaction closures"
        )
    if profile not in allowed:
        raise RuntimeExecutorError(
            "recovery refused because persistent system profile drifted outside "
            "bound transaction closures"
        )
    return current, profile


def _gc_root_path(request_id: str, role: str) -> Path:
    if REQUEST_ID_RE.fullmatch(request_id) is None:
        raise RuntimeExecutorError("request id is invalid")
    if role not in {"prior", "target"}:
        raise RuntimeExecutorError("transaction GC root role is invalid")
    return GC_ROOT_DIR / f"{request_id}-{role}"


def _gc_root_argv(
    executor_closure: str,
    root_path: Path,
    target_closure: str,
) -> list[str]:
    nix_store = _require_executable(
        Path(executor_closure) / "sw" / "bin" / "nix-store",
        label="closure-bound nix-store",
    )
    return [
        str(nix_store),
        "--realise",
        target_closure,
        "--add-root",
        str(root_path),
        "--option",
        "substitute",
        "false",
        "--option",
        "max-jobs",
        "0",
    ]


# Only the verified Day-2 recovery of the previous closure may bypass
# pre-switch checks inherited from immutable older generations. Never inherit
# an ambient NIXOS_NO_CHECK into ordinary activation.
_RECOVERY_SKIP_PRE_SWITCH_CHECKS: ContextVar[bool] = ContextVar(
    "heim_pc_day2_recovery_skip_pre_switch_checks", default=False,
)


def _minimal_env(target_closure: str) -> dict[str, str]:
    env = {
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{target_closure}/sw/bin",
        "NIX_PATH": "",
        "NIX_CONFIG": NIX_RUNTIME_CONFIG,
    }
    if _RECOVERY_SKIP_PRE_SWITCH_CHECKS.get():
        env["NIXOS_NO_CHECK"] = "1"
    return env


def _expected_dedicated_scope(request_id: str) -> str:
    if REQUEST_ID_RE.fullmatch(request_id) is None:
        raise RuntimeExecutorError("request id is invalid")
    return DEDICATED_SCOPE_TEMPLATE.format(request_id=request_id)


def _scope_cgroup_dir(scope_path: str) -> Path:
    if (
        not scope_path.startswith("/system.slice/")
        or not scope_path.endswith(".scope")
        or "\x00" in scope_path
    ):
        raise RuntimeExecutorError("dedicated transient scope path is invalid")
    relative = Path(scope_path.lstrip("/"))
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise RuntimeExecutorError("dedicated transient scope path is invalid")
    try:
        root = CGROUP_ROOT.resolve(strict=True)
        system_slice = (root / "system.slice").resolve(strict=True)
        cgroup_dir = (root / relative).resolve(strict=True)
    except OSError as exc:
        raise RuntimeExecutorError(
            f"dedicated transient scope cgroup is unavailable: {exc}"
        ) from exc
    if system_slice.parent != root or cgroup_dir.parent != system_slice:
        raise RuntimeExecutorError("dedicated transient scope escaped the cgroup boundary")
    return cgroup_dir


def _read_cgroup_procs(path: Path) -> set[int]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RuntimeExecutorError(
            f"cannot read dedicated transient scope members: {exc}"
        ) from exc
    if len(raw) > MAX_CGROUP_PROCS_BYTES:
        raise RuntimeExecutorError(
            "dedicated transient scope membership exceeds safety boundary"
        )
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeExecutorError(
            "dedicated transient scope membership is invalid"
        ) from exc
    pids: set[int] = set()
    for line in text.splitlines():
        if not line or not line.isdigit():
            raise RuntimeExecutorError(
                "dedicated transient scope membership is invalid"
            )
        pid = int(line)
        if pid <= 0:
            raise RuntimeExecutorError(
                "dedicated transient scope membership is invalid"
            )
        pids.add(pid)
    return pids


def _read_scope_pids(cgroup_dir: Path) -> set[int]:
    pending = [cgroup_dir]
    visited = 0
    pids: set[int] = set()
    while pending:
        current = pending.pop()
        visited += 1
        if visited > MAX_CGROUP_NODES:
            raise RuntimeExecutorError(
                "dedicated transient scope cgroup tree exceeds safety boundary"
            )
        pids.update(_read_cgroup_procs(current / "cgroup.procs"))
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            raise RuntimeExecutorError(
                f"cannot enumerate dedicated transient scope cgroups: {exc}"
            ) from exc
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
            except OSError as exc:
                raise RuntimeExecutorError(
                    f"cannot inspect dedicated transient scope cgroup: {exc}"
                ) from exc
    if not pids:
        raise RuntimeExecutorError("dedicated transient scope membership is empty")
    return pids


def _require_scope_self_only(scope_path: str) -> Path:
    cgroup_dir = _scope_cgroup_dir(scope_path)
    if _read_scope_pids(cgroup_dir) != {os.getpid()}:
        raise RuntimeExecutorError(
            "dedicated transient scope must contain only the executor before mutation"
        )
    return cgroup_dir


def _require_dedicated_scope(request_id: str) -> str:
    expected = _expected_dedicated_scope(request_id)
    try:
        raw = SELF_CGROUP_PATH.read_bytes()
    except OSError as exc:
        raise RuntimeExecutorError(f"cannot read executor cgroup membership: {exc}") from exc
    if len(raw) > MAX_CGROUP_BYTES:
        raise RuntimeExecutorError("executor cgroup membership exceeds safety boundary")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeExecutorError("executor cgroup membership is not valid UTF-8") from exc
    unified: list[str] = []
    for line in text.splitlines():
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            unified.append(parts[2])
    if unified != [expected]:
        observed = unified[0] if len(unified) == 1 else "<ambiguous>"
        raise RuntimeExecutorError(
            "runtime activation executor must run in dedicated transient scope "
            f"{expected}; observed {observed}"
        )
    _require_scope_self_only(expected)
    return expected


Runner = Callable[[Sequence[str], str], None]
_TERMINATION_SIGNALS = (
    signal.SIGINT,
    signal.SIGTERM,
    signal.SIGHUP,
    signal.SIGQUIT,
)


class _TerminationState:
    def __init__(self) -> None:
        self.signum: int | None = None
        self.defer_depth = 0

    def record(self, signum: int) -> None:
        if self.signum is None:
            self.signum = signum

    @property
    def requested(self) -> bool:
        return self.signum is not None

    @property
    def deferred(self) -> bool:
        return self.defer_depth > 0


_ACTIVE_TERMINATION_STATE: ContextVar[_TerminationState | None] = ContextVar(
    "heim_pc_day2_termination_state",
    default=None,
)
_ACTIVE_LOCK_FD: ContextVar[int | None] = ContextVar(
    "heim_pc_day2_activation_lock_fd",
    default=None,
)
_ACTIVE_SCOPE_CGROUP: ContextVar[Path | None] = ContextVar(
    "heim_pc_day2_activation_scope_cgroup",
    default=None,
)


def _set_termination_handlers(
    handler: signal.Handlers | Callable[[int, Any], None],
    *,
    preserve_ignored: bool = False,
) -> dict[int, Any]:
    previous: dict[int, Any] = {}
    try:
        for signum in _TERMINATION_SIGNALS:
            prior = signal.getsignal(signum)
            previous[signum] = prior
            if preserve_ignored and prior == signal.SIG_IGN:
                continue
            signal.signal(signum, handler)
    except (OSError, ValueError) as exc:
        for signum, prior in previous.items():
            signal.signal(signum, prior)
        raise RuntimeExecutorError(
            "cannot install controlled termination handlers"
        ) from exc
    return previous


def _restore_termination_handlers(previous: Mapping[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


@contextmanager
def _controlled_termination(
    *,
    preserve_ignored: bool = False,
) -> Iterator[_TerminationState]:
    active = _ACTIVE_TERMINATION_STATE.get()
    if active is not None:
        yield active
        return

    state = _TerminationState()

    def _handle_termination(signum: int, _frame: Any) -> None:
        # Never throw asynchronously from a signal handler.  Mutating paths
        # observe this flag only at explicit safe boundaries, after a child
        # process group is proven quiescent when one exists.
        state.record(signum)

    previous = _set_termination_handlers(
        _handle_termination,
        preserve_ignored=preserve_ignored,
    )
    token = _ACTIVE_TERMINATION_STATE.set(state)
    try:
        yield state
    finally:
        try:
            _restore_termination_handlers(previous)
        finally:
            _ACTIVE_TERMINATION_STATE.reset(token)


@contextmanager
def _defer_termination() -> Iterator[None]:
    state = _ACTIVE_TERMINATION_STATE.get()
    if state is None:
        yield
        return
    state.defer_depth += 1
    try:
        yield
    finally:
        state.defer_depth -= 1


def _raise_if_termination_requested(state: _TerminationState) -> None:
    if state.requested and not state.deferred:
        raise _ExecutorInterrupted()


@contextmanager
def _default_sigchld() -> Iterator[None]:
    previous = signal.getsignal(signal.SIGCHLD)
    try:
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    except (OSError, ValueError) as exc:
        raise RuntimeExecutorError(
            "cannot normalize SIGCHLD before executor child start"
        ) from exc
    try:
        yield
    finally:
        try:
            signal.signal(signal.SIGCHLD, previous)
        except (OSError, ValueError) as exc:
            raise RuntimeExecutorError(
                "cannot restore SIGCHLD after executor child cleanup"
            ) from exc


def _wait_for_process_group_quiescence(pgid: int) -> None:
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        except OSError:
            # An uncertain probe must not release the activation lock.  Keep
            # checking until kernel state positively establishes that the
            # private process group no longer exists.
            time.sleep(PROCESS_GROUP_QUIESCENCE_POLL_SECONDS)
            continue
        time.sleep(PROCESS_GROUP_QUIESCENCE_POLL_SECONDS)


def _wait_for_active_scope_peer_quiescence() -> None:
    cgroup_dir = _ACTIVE_SCOPE_CGROUP.get()
    if cgroup_dir is None:
        return
    while True:
        try:
            pids = _read_scope_pids(cgroup_dir)
        except RuntimeExecutorError:
            # Missing or malformed cgroup readback is uncertainty, not proof
            # of quiescence. Keep the activation lock and retry fail-closed.
            time.sleep(PROCESS_GROUP_QUIESCENCE_POLL_SECONDS)
            continue
        if pids == {os.getpid()}:
            return
        time.sleep(PROCESS_GROUP_QUIESCENCE_POLL_SECONDS)


def _wait_for_process_exit_without_reaping(
    process: subprocess.Popen[bytes],
    argv: Sequence[str],
) -> int:
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    flags = os.WEXITED | os.WNOWAIT | os.WNOHANG
    while True:
        state = _ACTIVE_TERMINATION_STATE.get()
        if state is not None:
            _raise_if_termination_requested(state)
        try:
            observed = os.waitid(os.P_PID, process.pid, flags)
        except InterruptedError:
            continue
        except (ChildProcessError, OSError) as exc:
            raise _ProcessTerminationUncertain(
                "executor process exit could not be observed before reap"
            ) from exc
        if observed is not None:
            if observed.si_code == os.CLD_EXITED:
                return int(observed.si_status)
            if observed.si_code in {os.CLD_KILLED, os.CLD_DUMPED}:
                return -int(observed.si_status)
            raise _ProcessTerminationUncertain(
                "executor process exit status was unexpected"
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(list(argv), COMMAND_TIMEOUT_SECONDS)
        time.sleep(min(PROCESS_GROUP_QUIESCENCE_POLL_SECONDS, remaining))

def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    # A completed Popen has already reaped its leader.  Never send a destructive
    # signal to that numeric PGID again: it may have been recycled meanwhile.
    if getattr(process, "returncode", None) is not None:
        return

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        # Do not treat an unsuccessful signal attempt as proof that the
        # mutation is still running or stopped.  The blocking wait and
        # process-group disappearance check below remain authoritative.
        pass

    while True:
        try:
            # No second timeout is allowed here.  Cleanup must finish before
            # recovery or another mutation can start.
            process.wait()
            break
        except (InterruptedError, KeyboardInterrupt):
            continue
        except OSError:
            break
    _wait_for_process_group_quiescence(process.pid)
    _wait_for_active_scope_peer_quiescence()


def _run_exact(argv: Sequence[str], target_closure: str) -> None:
    # systemd-boot defines the empty entry ID as the exact OneShot clear
    # operation. No other empty argument is admitted by this executor.
    clear_oneshot = (
        len(argv) == 4
        and isinstance(argv[0], str)
        and Path(argv[0]).name == "bootctl"
        and list(argv[1:]) == ["--esp-path=/boot", "set-oneshot", ""]
    )
    if not argv or any(not isinstance(item, str) for item in argv) or (
        any(not item for item in argv) and not clear_oneshot
    ):
        raise RuntimeExecutorError("executor argv is invalid")
    if not argv[0].startswith("/nix/store/"):
        raise RuntimeExecutorError("executor command must be closure-bound")

    process: subprocess.Popen[bytes] | None = None
    cleanup_complete = False
    lock_fd = _ACTIVE_LOCK_FD.get()
    pass_fds = () if lock_fd is None else (lock_fd,)

    with _default_sigchld():
        with _controlled_termination(preserve_ignored=True) as termination:
            try:
                try:
                    process = subprocess.Popen(
                        list(argv),
                        cwd="/",
                        env=_minimal_env(target_closure),
                        stdin=subprocess.DEVNULL,
                        stdout=sys.stderr,
                        stderr=sys.stderr,
                        shell=False,
                        close_fds=True,
                        pass_fds=pass_fds,
                        start_new_session=True,
                    )
                except OSError as exc:
                    raise RuntimeExecutorError(
                        f"executor command failed to start: {exc}"
                    ) from exc

                _raise_if_termination_requested(termination)
                try:
                    returncode = _wait_for_process_exit_without_reaping(process, argv)
                except subprocess.TimeoutExpired as exc:
                    _terminate_process_group(process)
                    cleanup_complete = True
                    raise RuntimeExecutorError(
                        "executor command timed out; process group terminated"
                    ) from exc
                except _ProcessTerminationUncertain as exc:
                    # Exit identity is uncertain, so never send a destructive
                    # signal here. Reap only this Popen child first: a waitable
                    # but unreaped zombie keeps its process group visible to
                    # killpg(..., 0), preventing the quiescence proof forever.
                    # Blocking wait is fail-closed if the child is still alive.
                    while True:
                        try:
                            process.wait()
                            break
                        except (InterruptedError, KeyboardInterrupt):
                            continue
                        except OSError as reap_error:
                            # The numeric PGID may no longer be trustworthy when
                            # reaping itself failed. Keep the global activation
                            # lock until the request-bound scope is positively
                            # self-only before propagating the uncertainty.
                            _wait_for_active_scope_peer_quiescence()
                            raise _ProcessTerminationUncertain(
                                "executor leader could not be reaped after uncertain exit"
                            ) from reap_error
                    _wait_for_process_group_quiescence(process.pid)
                    _wait_for_active_scope_peer_quiescence()
                    cleanup_complete = True
                    raise RuntimeExecutorError(
                        "executor exit status is uncertain after process group "
                        "quiescence; recovery required"
                    ) from exc

                # The leader remains unreaped until SIGKILL has been dispatched
                # to the private process group.  Its zombie pins the PGID while
                # same-group descendants are removed.  The inherited activation
                # lock fd keeps the flock alive even if this executor itself dies.
                _terminate_process_group(process)
                cleanup_complete = True
                _raise_if_termination_requested(termination)

                if returncode != 0:
                    raise RuntimeExecutorError(
                        f"executor command returned non-zero status {returncode}"
                    )
                _raise_if_termination_requested(termination)
            except (_ExecutorInterrupted, KeyboardInterrupt) as exc:
                if process is not None and not cleanup_complete:
                    _terminate_process_group(process)
                    cleanup_complete = True
                raise RuntimeExecutorError(
                    "executor command interrupted; process group terminated"
                ) from exc


def _run_gc_root_command(argv: Sequence[str], executor_closure: str) -> None:
    _run_exact(argv, executor_closure)


def _require_gc_root(path: Path, expected_target: str) -> str:
    try:
        st = path.lstat()
        target = os.readlink(path)
    except OSError as exc:
        raise RuntimeExecutorError(f"transaction GC root is unavailable: {exc}") from exc
    if not stat.S_ISLNK(st.st_mode) or st.st_uid != TRUSTED_UID:
        raise RuntimeExecutorError("transaction GC root metadata is unsafe")
    if target != expected_target:
        raise RuntimeExecutorError(
            "transaction GC root target mismatch: "
            f"expected {expected_target}, observed {target}"
        )
    try:
        resolved = str(path.resolve(strict=True))
    except OSError as exc:
        raise RuntimeExecutorError(
            f"transaction GC root target is unavailable: {exc}"
        ) from exc
    if resolved != expected_target:
        raise RuntimeExecutorError(
            "transaction GC root resolved target mismatch: "
            f"expected {expected_target}, observed {resolved}"
        )
    return target


def _remove_gc_root(path: Path, expected_target: str) -> None:
    _require_gc_root(path, expected_target)
    try:
        path.unlink()
    except OSError as exc:
        raise RuntimeExecutorError(f"cannot remove transaction GC root: {exc}") from exc
    if os.path.lexists(path):
        raise RuntimeExecutorError("transaction GC root remained after unlink")


@contextmanager
def _pinned_transaction_closures(
    *,
    request_id: str,
    prior_closure: str,
    target_closure: str,
) -> Iterator[
    tuple[
        dict[str, Path],
        tuple[list[str], list[str]],
        Callable[[], None],
        Callable[[], None],
    ]
]:
    _require_secure_dir(GC_ROOT_DIR, label="transaction GC root directory")
    roots = {
        "prior": _gc_root_path(request_id, "prior"),
        "target": _gc_root_path(request_id, "target"),
    }
    targets = {"prior": prior_closure, "target": target_closure}
    for role, root_path in roots.items():
        if os.path.lexists(root_path):
            raise RuntimeExecutorError(
                f"transaction {role} GC root already exists: {root_path}"
            )

    argvs = (
        _gc_root_argv(prior_closure, roots["prior"], prior_closure),
        _gc_root_argv(prior_closure, roots["target"], target_closure),
    )
    try:
        for role, argv in zip(("prior", "target"), argvs):
            _run_gc_root_command(argv, prior_closure)
            _require_gc_root(roots[role], targets[role])
    except _ProcessTerminationUncertain:
        # Preserve any possibly-created roots when registration is not proven
        # quiescent. A safe leak is preferable to unpinning a closure that may
        # still be required by an in-flight child.
        raise
    except BaseException as setup_error:
        cleanup_errors: list[str] = []
        for role in ("target", "prior"):
            root_path = roots[role]
            if not os.path.lexists(root_path):
                continue
            try:
                _remove_gc_root(root_path, targets[role])
            except RuntimeExecutorError as cleanup_error:
                cleanup_errors.append(f"{role}: {cleanup_error}")
        if cleanup_errors:
            raise RuntimeExecutorError(
                "transaction GC root setup failed and cleanup is incomplete: "
                + "; ".join(cleanup_errors)
            ) from setup_error
        raise

    release_roots = True
    released = False
    body_error: BaseException | None = None

    def release() -> None:
        nonlocal released
        # Validate both roots before removing either so a missing/wrong target
        # enters the caller's guarded recovery path while rollback is pinned.
        _require_gc_root(roots["prior"], prior_closure)
        _require_gc_root(roots["target"], target_closure)
        # Remove target first. If prior cleanup then fails, rollback remains
        # pinned and the caller can recover before this context retries cleanup.
        _remove_gc_root(roots["target"], target_closure)
        _remove_gc_root(roots["prior"], prior_closure)
        released = True

    def retain() -> None:
        nonlocal release_roots
        # Incomplete recovery is not a transaction endpoint.  Preserve every
        # remaining exact root so the prior closure stays available for
        # operator recovery after this executor returns an error.
        release_roots = False

    try:
        yield roots, argvs, release, retain
    except _ProcessTerminationUncertain:
        release_roots = False
        raise
    except BaseException as exc:
        body_error = exc
        raise
    finally:
        if release_roots and not released:
            cleanup_errors: list[str] = []
            last_cleanup_error: RuntimeExecutorError | None = None
            for role in ("target", "prior"):
                root_path = roots[role]
                if not os.path.lexists(root_path):
                    continue
                try:
                    _remove_gc_root(root_path, targets[role])
                except RuntimeExecutorError as cleanup_error:
                    last_cleanup_error = cleanup_error
                    cleanup_errors.append(f"{role}: {cleanup_error}")
            if cleanup_errors:
                message = "transaction GC root cleanup is incomplete: " + "; ".join(
                    cleanup_errors
                )
                if body_error is not None:
                    raise RuntimeExecutorError(
                        f"{body_error}; {message}"
                    ) from last_cleanup_error
                raise RuntimeExecutorError(message) from last_cleanup_error


@contextmanager
def _exclusive_lock(scope_path: str | None = None) -> Iterator[None]:
    # Repeat the self-only cgroup proof immediately before lock acquisition so
    # request parsing cannot hide a peer that entered the scope in between.
    scope_cgroup = None if scope_path is None else _require_scope_self_only(scope_path)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    old_umask = os.umask(0o077)
    try:
        fd = os.open(LOCK_PATH, flags, 0o600)
    except OSError as exc:
        raise RuntimeExecutorError(f"cannot open activation lock: {exc}") from exc
    finally:
        os.umask(old_umask)
    lock_token = None
    scope_token = None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
            raise RuntimeExecutorError("activation lock metadata is unsafe")
        _require_exact_mode(st, 0o600, "activation lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeExecutorError(
                "another NixOS activation executor holds the lock"
            ) from exc
        if (
            scope_cgroup is not None
            and _read_scope_pids(scope_cgroup) != {os.getpid()}
        ):
            raise RuntimeExecutorError(
                "dedicated transient scope gained a peer before mutation"
            )
        lock_token = _ACTIVE_LOCK_FD.set(fd)
        if scope_cgroup is not None:
            scope_token = _ACTIVE_SCOPE_CGROUP.set(scope_cgroup)
        yield
    finally:
        if scope_token is not None:
            _ACTIVE_SCOPE_CGROUP.reset(scope_token)
        if lock_token is not None:
            _ACTIVE_LOCK_FD.reset(lock_token)
        # Do not explicitly unlock the shared open-file description. Closing
        # only this process' descriptor lets any inherited descendant retain
        # the flock, keeping later executors fail-closed until every holder exits.
        os.close(fd)


def _require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeExecutorError("runtime activation execution requires root")


def _recover(
    *,
    prior_closure: str,
    target_closure: str,
    mode: str,
    runner: Runner,
    profile_may_have_changed: bool,
) -> None:
    errors: list[str] = []
    # Recovery must run to a verified postcondition even when more interactive
    # termination requests arrive.  The shared flag-only handler records them,
    # while nested _run_exact calls defer acting on them until recovery ends.
    with _defer_termination():
        _, observed_profile = _require_recovery_transaction_state(
            prior_closure=prior_closure,
            target_closure=target_closure,
        )
        if profile_may_have_changed and observed_profile != prior_closure:
            try:
                profile_argv = _profile_set_argv(prior_closure, prior_closure)
                # External activation tools do not share our private flock.
                # Refuse to overwrite any third closure observed immediately
                # before this rollback effect.
                _require_recovery_transaction_state(
                    prior_closure=prior_closure,
                    target_closure=target_closure,
                )
                runner(profile_argv, prior_closure)
                _require_recovery_transaction_state(
                    prior_closure=prior_closure,
                    target_closure=target_closure,
                )
                _require_link_target(
                    SYSTEM_PROFILE_LINK,
                    prior_closure,
                    label="recovered persistent system profile",
                )
            except _ProcessTerminationUncertain:
                raise
            except RuntimeExecutorError as exc:
                errors.append(f"profile rollback failed: {exc}")

        switch_argv = _switch_argv(prior_closure, mode)
        # Re-check after any profile rollback so third-party drift between
        # recovery effects stays visible instead of being overwritten.
        _require_recovery_transaction_state(
            prior_closure=prior_closure,
            target_closure=target_closure,
        )
        # A prior immutable closure can still contain the faulty downgrade
        # preSwitchCheck even after new builds have removed that check.
        # Bypass it ONLY during this transaction-verified recovery effect.
        token = _RECOVERY_SKIP_PRE_SWITCH_CHECKS.set(True)
        try:
            runner(switch_argv, prior_closure)
        except _ProcessTerminationUncertain:
            raise
        except RuntimeExecutorError as exc:
            errors.append(f"prior closure recovery activation failed: {exc}")
        finally:
            _RECOVERY_SKIP_PRE_SWITCH_CHECKS.reset(token)

        try:
            _require_link_target(
                CURRENT_SYSTEM_LINK,
                prior_closure,
                label="recovered current system",
            )
        except RuntimeExecutorError as exc:
            errors.append(f"current-system recovery verification failed: {exc}")
        try:
            _require_link_target(
                SYSTEM_PROFILE_LINK,
                prior_closure,
                label="recovered persistent system profile",
            )
        except RuntimeExecutorError as exc:
            errors.append(f"profile recovery verification failed: {exc}")
    if errors:
        raise RuntimeExecutorError("; ".join(errors))


def _execution_receipt(
    *,
    request_id: str,
    operation: str,
    mode: str,
    plan: Mapping[str, Any],
    build_receipt_sha256: str,
    plan_sha256: str,
    argv: Sequence[str],
    effect_argvs: Sequence[Sequence[str]],
    gc_root_argvs: Sequence[Sequence[str]],
    executor_cgroup: str,
    prior_gc_root: str,
    target_gc_root: str,
    pre_current: str,
    pre_profile: str,
    post_current: str,
    post_profile: str,
    profile_mutated: bool,
) -> dict[str, Any]:
    receipt = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_activation_runtime_execution_v1",
        "result": "executed",
        "request_id": request_id,
        "operation": operation,
        "mode": mode,
        "target": plan["target"],
        "source_revision": plan["source_revision"],
        "system_closure": plan["system_closure"],
        "prior_closure": plan["prior_closure"],
        "build_receipt_sha256": build_receipt_sha256,
        "authority_sha256": plan["authority_sha256"],
        "plan_sha256": plan_sha256,
        "command_sha256": _sha256_json(list(argv)),
        "effect_commands_sha256": _sha256_json(
            [list(effect_argv) for effect_argv in effect_argvs]
        ),
        "gc_root_command_sha256": _sha256_json(list(gc_root_argvs[1])),
        "gc_root_commands_sha256": _sha256_json(
            [list(gc_root_argv) for gc_root_argv in gc_root_argvs]
        ),
        "executor_cgroup": executor_cgroup,
        "prior_gc_root": prior_gc_root,
        "target_gc_root": target_gc_root,
        "prior_gc_root_released": True,
        "target_gc_root_released": True,
        "transaction_gc_roots_released": True,
        "dedicated_scope_membership_established": True,
        "transaction_gc_root_release_established": True,
        "profile_mutated": profile_mutated,
        "pre_current_closure": pre_current,
        "pre_persistent_profile_closure": pre_profile,
        "post_current_closure": post_current,
        "post_persistent_profile_closure": post_profile,
        "executed_at": _utc_now(),
        "source_reevaluation_used": False,
        "branch_resolution_used": False,
        "lock_resolution_used": False,
        "remote_input_resolution_used": False,
        "final_activation_receipt_established": False,
        "independent_runtime_readback_established": False,
        "persistent_state_observation_provenance_established": False,
        "does_not_establish": [
            "rootbroker or request-staging authorization",
            "independent live-closure readback",
            "independent persistent-state observation provenance",
            "controlled reboot completion",
            "final activation receipt",
            "final persistent-promotion receipt",
            "named Approved boot promotion",
        ],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    return receipt


def _boot_profile_tool(closure: str) -> Path:
    return _require_executable(
        Path(closure) / "sw" / "bin" / "heim-pc-boot-profile-selection",
        label="closure-bound boot profile resolver",
    )


def _boot_entry_id(value: str) -> str:
    if not isinstance(value, str) or BOOT_ENTRY_RE.fullmatch(value) is None:
        raise RuntimeExecutorError("invalid native NixOS boot entry identity")
    return value


def _resolve_boot_entry(closure: str, profile: str, expected: str) -> str:
    argv = [str(_boot_profile_tool(closure)), "--resolve-profile-entry", profile, expected]
    try:
        result = subprocess.run(
            argv, cwd="/", env=_minimal_env(closure), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise RuntimeExecutorError(f"boot entry resolution failed: {exc}") from exc
    if result.returncode:
        raise RuntimeExecutorError(
            f"boot profile {profile} resolution failed: {result.stderr[-1000:]}"
        )
    return _boot_entry_id(result.stdout.strip())


def _read_efi_entry(name: str, *, optional: bool = False) -> str | None:
    path = EFI_VAR_ROOT / f"{name}-{EFI_LOADER_GUID}"
    try:
        if path.is_symlink():
            raise RuntimeExecutorError(f"{name} must not be a symlink")
        with path.open("rb") as stream:
            raw = stream.read(513)
    except FileNotFoundError as exc:
        if optional and EFI_VAR_ROOT.is_dir():
            return None
        raise RuntimeExecutorError(f"{name} unavailable: {exc}") from exc
    except OSError as exc:
        raise RuntimeExecutorError(f"{name} unavailable: {exc}") from exc
    if not 6 <= len(raw) <= 512 or len(raw) % 2:
        raise RuntimeExecutorError(f"{name} has invalid EFI variable length")
    try:
        value = raw[4:].decode("utf-16-le")
    except UnicodeError as exc:
        raise RuntimeExecutorError(f"{name} is not valid UTF-16") from exc
    if not value.endswith("\0") or "\0" in value[:-1]:
        raise RuntimeExecutorError(f"{name} has invalid EFI string terminator")
    return _boot_entry_id(value[:-1])


def _require_boot_id(value: Any) -> str:
    if not isinstance(value, str) or BOOT_ID_RE.fullmatch(value) is None:
        raise RuntimeExecutorError("invalid kernel boot ID")
    return value


def _read_boot_id() -> str:
    try:
        with BOOT_ID_PATH.open(encoding="ascii") as stream:
            value = stream.read(80)
    except (OSError, UnicodeError) as exc:
        raise RuntimeExecutorError(f"kernel boot ID unavailable: {exc}") from exc
    return _require_boot_id(value.removesuffix("\n"))


def _observe_boot_links_and_defaults() -> dict[str, Any]:
    """Read the partial boot state even before a new named entry exists."""
    def observed(path: Path, label: str) -> str:
        value = _resolve_link(path, label=label)
        try:
            return managed_nix._require_closure(value, label)
        except managed_nix.ManagedNixError as exc:
            raise RuntimeExecutorError(f"{label} is not a system closure") from exc

    state = {
        "current": observed(CURRENT_SYSTEM_LINK, "current system"),
        "booted": observed(BOOTED_SYSTEM_LINK, "booted system"),
        "profile": observed(SYSTEM_PROFILE_LINK, "system profile"),
        "approved": observed(BOOT_PROFILE_ROOT / "heim-pc-approved", "approved profile"),
        "recovery": observed(BOOT_PROFILE_ROOT / "heim-pc-recovery", "recovery profile"),
    }
    state["default"] = _read_efi_entry("LoaderEntryDefault")
    state["sysfail"] = _read_efi_entry("LoaderEntrySysFail")
    state["oneshot"] = _read_efi_entry("LoaderEntryOneShot", optional=True)
    try:
        if LOADER_CONF.is_symlink():
            raise RuntimeExecutorError("loader.conf must not be a symlink")
        with LOADER_CONF.open(encoding="utf-8") as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise RuntimeExecutorError("loader.conf is unexpectedly large")
        defaults = [line[8:] for line in data.splitlines() if line.startswith("default ")]
        if len(defaults) != 1:
            raise RuntimeExecutorError("loader.conf must contain one default")
        state["loader_default"] = _boot_entry_id(defaults[0])
    except (OSError, UnicodeError) as exc:
        raise RuntimeExecutorError(f"loader.conf unavailable: {exc}") from exc
    return state


def _observe_boot_state(closure: str) -> dict[str, Any]:
    state = _observe_boot_links_and_defaults()
    state["approved_entry"] = _resolve_boot_entry(closure, "heim-pc-approved", state["approved"])
    state["recovery_entry"] = _resolve_boot_entry(closure, "heim-pc-recovery", state["recovery"])
    return state


def _require_approved_defaults(state: Mapping[str, Any]) -> None:
    if (
        state["default"] != state["approved_entry"]
        or state["loader_default"] != state["approved_entry"]
        or state["sysfail"] != state["recovery_entry"]
    ):
        raise RuntimeExecutorError("EFI/loader defaults do not match approved and recovery profiles")


def _require_boot_state(
    observed: Mapping[str, Any], baseline: Mapping[str, Any], *,
    profile: str, oneshot: str | None,
) -> None:
    expected = dict(baseline, profile=profile, oneshot=oneshot)
    if dict(observed) != expected:
        changed = sorted(key for key in expected if observed.get(key) != expected[key])
        raise RuntimeExecutorError("boot state drift: " + ", ".join(changed))


def _oneshot_argv(closure: str, entry: str | None) -> list[str]:
    path = _require_executable(
        Path(closure) / "sw" / "bin" / "bootctl", label="closure-bound bootctl"
    )
    return [str(path), "--esp-path=/boot", "set-oneshot", "" if entry is None else _boot_entry_id(entry)]


def _recover_next_boot(
    *, baseline: Mapping[str, Any], target: str, candidate: str | None,
    boot_attempted: bool, oneshot_attempted: bool, runner: Runner,
) -> None:
    # Do not overwrite another operator's pending boot or changed named pins.
    # A failed native boot install can temporarily select our exact candidate.
    # Only that candidate (or the original default) is recoverable here.
    with _defer_termination():
        observed = _observe_boot_state(target)
        pinned_keys = ("current", "booted", "approved", "recovery", "approved_entry", "recovery_entry")
        if any(observed[key] != baseline[key] for key in pinned_keys):
            raise RuntimeExecutorError("boot recovery refused: named pins or running system drifted")
        if observed["profile"] not in {baseline["profile"], target}:
            raise RuntimeExecutorError("boot recovery refused: system profile drifted")
        if boot_attempted and candidate is None and observed["profile"] == target:
            try:
                candidate = _resolve_boot_entry(target, "system", target)
            except RuntimeExecutorError:
                # The boot installation may have failed before writing its entry.
                # This is recoverable only if the existing defaults are intact.
                pass
        allowed_defaults = {baseline["default"]}
        if boot_attempted and candidate is not None:
            allowed_defaults.add(candidate)
        if (
            observed["default"] not in allowed_defaults
            or observed["loader_default"] not in allowed_defaults
            or observed["sysfail"] != baseline["sysfail"]
            or (observed["oneshot"] is not None and (
                not oneshot_attempted or candidate is None or observed["oneshot"] != candidate
            ))
        ):
            raise RuntimeExecutorError("boot recovery refused: unrelated EFI selection observed")
        if observed["oneshot"] is not None:
            runner(_oneshot_argv(target, None), target)
            if _read_efi_entry("LoaderEntryOneShot", optional=True) is not None:
                raise RuntimeExecutorError("boot recovery failed to clear owned OneShot")
        if observed["profile"] != baseline["profile"]:
            runner(_profile_set_argv(baseline["current"], baseline["profile"]), baseline["current"])
        if boot_attempted:
            # Older immutable generations can still carry the removed
            # downgrade check. Only this verified recovery invocation may skip it.
            token = _RECOVERY_SKIP_PRE_SWITCH_CHECKS.set(True)
            try:
                runner(_switch_argv(baseline["profile"], "boot"), baseline["profile"])
            finally:
                _RECOVERY_SKIP_PRE_SWITCH_CHECKS.reset(token)
            # The normal install hook already restores defaults. Reuse its
            # fixed action only if an older immutable closure did not do so.
            restored = _observe_boot_state(target)
            if any(restored[key] != baseline[key] for key in pinned_keys) or restored["oneshot"] is not None:
                raise RuntimeExecutorError("boot recovery refused: state drift during restoration")
            if restored["profile"] != baseline["profile"]:
                raise RuntimeExecutorError("boot recovery failed to restore system profile")
            if any(restored[key] != baseline[key] for key in ("default", "sysfail", "loader_default")):
                runner([str(_boot_profile_tool(target))], target)
        _require_boot_state(
            _observe_boot_state(target), baseline, profile=baseline["profile"], oneshot=None,
        )


def _execute_next_boot(
    *, request_id: str, plan: Mapping[str, Any], build_digest: str,
    plan_digest: str, executor_cgroup: str, reauthorize: Callable[[], Mapping[str, Any]],
    runner: Runner,
) -> dict[str, Any]:
    target = plan["system_closure"]
    prior = plan["prior_closure"]
    staging_boot_id = _read_boot_id()
    baseline = _observe_boot_state(target)
    _require_approved_defaults(baseline)
    if baseline["current"] != prior or baseline["booted"] != baseline["approved"]:
        raise RuntimeExecutorError("next-boot requires bound current system and booted approved fallback")
    if baseline["oneshot"] is not None:
        raise RuntimeExecutorError("existing OneShot must be reconciled before staging a new boot")
    # The normal profile can differ from the live/approved closure. Pin its
    # actual preimage, rather than inventing equality and blocking valid work.
    gc_prior = baseline["profile"] if baseline["profile"] != target else prior
    profile_argv = _profile_set_argv(prior, target)
    boot_argv = _switch_argv(target, "boot")
    _profile_set_argv(prior, baseline["profile"])
    _switch_argv(baseline["profile"], "boot")
    _oneshot_argv(target, None)
    commands: list[list[str]] = []
    candidate: str | None = None
    boot_attempted = False
    oneshot_attempted = False
    with _pinned_transaction_closures(
        request_id=request_id, prior_closure=gc_prior, target_closure=target,
    ) as (gc_roots, gc_root_argvs, release_gc_roots, retain_gc_roots):
        with _controlled_termination() as termination:
            _require_boot_state(_observe_boot_state(target), baseline, profile=baseline["profile"], oneshot=None)
            plan = reauthorize()
            _raise_if_termination_requested(termination)
            try:
                if baseline["profile"] != target:
                    commands.append(profile_argv)
                    runner(profile_argv, prior)
                    _raise_if_termination_requested(termination)
                    _require_boot_state(_observe_boot_state(target), baseline, profile=target, oneshot=None)
                boot_attempted = True
                commands.append(boot_argv)
                runner(boot_argv, target)
                _raise_if_termination_requested(termination)
                candidate = _resolve_boot_entry(target, "system", target)
                _require_boot_state(_observe_boot_state(target), baseline, profile=target, oneshot=None)
                oneshot_argv = _oneshot_argv(target, candidate)
                commands.append(oneshot_argv)
                oneshot_attempted = True
                runner(oneshot_argv, target)
                _raise_if_termination_requested(termination)
                post = _observe_boot_state(target)
                _require_boot_state(post, baseline, profile=target, oneshot=candidate)
                if _resolve_boot_entry(target, "system", target) != candidate:
                    raise RuntimeExecutorError("candidate boot entry changed during staging")
                if _read_boot_id() != staging_boot_id:
                    raise RuntimeExecutorError("boot ID changed during staging")
                release_gc_roots()
            except _ProcessTerminationUncertain:
                raise
            except (_ExecutorInterrupted, KeyboardInterrupt, RuntimeExecutorError) as effect_error:
                try:
                    _recover_next_boot(
                        baseline=baseline, target=target, candidate=candidate,
                        boot_attempted=boot_attempted, oneshot_attempted=oneshot_attempted, runner=runner,
                    )
                except _ProcessTerminationUncertain:
                    raise
                except RuntimeExecutorError as recovery_error:
                    retain_gc_roots()
                    raise RuntimeExecutorError(
                        f"next-boot staging failed and recovery is incomplete: {effect_error}; {recovery_error}"
                    ) from recovery_error
                raise RuntimeExecutorError(
                    f"next-boot staging failed; prior boot state restored: {effect_error}"
                ) from effect_error
    receipt = _execution_receipt(
        request_id=request_id, operation="activation", mode="next-boot",
        plan=plan, build_receipt_sha256=build_digest, plan_sha256=plan_digest,
        argv=boot_argv, effect_argvs=commands, gc_root_argvs=gc_root_argvs,
        executor_cgroup=executor_cgroup, prior_gc_root=str(gc_roots["prior"]),
        target_gc_root=str(gc_roots["target"]), pre_current=baseline["current"],
        pre_profile=baseline["profile"], post_current=post["current"],
        post_profile=post["profile"], profile_mutated=baseline["profile"] != target,
    )
    receipt.update(
        boot_state_before=baseline, boot_state_after=post, candidate_entry=candidate,
        prior_gc_root_closure=gc_prior, next_boot_staged=True, boot_proven=False,
        staging_boot_id=staging_boot_id,
    )
    receipt.pop("receipt_sha256")
    receipt["receipt_sha256"] = _sha256_json(receipt)
    return receipt


def observe_next_boot(
    *, request_id: str, expected_staging_receipt_sha256: str,
    expected_target: str,
    request_bundle: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Observe a staged boot after restart, without changing any profile or EFI variable.

    The authorized caller supplies the staging receipt after reboot, either
    as a bound bundle or through the existing root-owned request directory.
    This observation does not authorize promotion or establish application health.
    """
    _require_root()
    executor_cgroup = _require_dedicated_scope(request_id)
    with _exclusive_lock(executor_cgroup):
        if request_bundle is not None:
            _stage_bound_request_files(request_id, request_bundle, {
                "staging-receipt.json": expected_staging_receipt_sha256,
            })
        receipt = _read_bound_json(_request_dir(request_id) / "staging-receipt.json")
        return _observe_bound_next_boot(
            request_id=request_id, receipt=receipt,
            expected_staging_receipt_sha256=expected_staging_receipt_sha256,
            expected_target=expected_target,
        )


def _observe_bound_next_boot(
    *, request_id: str, receipt: Mapping[str, Any],
    expected_staging_receipt_sha256: str, expected_target: str,
) -> dict[str, Any]:
    """Reuse the exact native successor proof while the caller holds the lock."""
    digest = _require_canonical_digest(
        receipt, expected_staging_receipt_sha256, "staging receipt"
    )
    material = dict(receipt)
    self_digest = material.pop("receipt_sha256", None)
    if self_digest != _sha256_json(material):
        raise RuntimeExecutorError("invalid staging receipt self digest")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("kind") != "heim_pc.nixos_activation_runtime_execution_v1"
        or receipt.get("result") != "executed"
        or receipt.get("operation") != "activation"
        or receipt.get("mode") != "next-boot"
        or receipt.get("target") != expected_target
        or receipt.get("next_boot_staged") is not True
        or receipt.get("boot_proven") is not False
    ):
        raise RuntimeExecutorError("receipt is not a bound staged next-boot activation")
    try:
        target = managed_nix._require_closure(receipt.get("system_closure"), "staged closure")
    except managed_nix.ManagedNixError as exc:
        raise RuntimeExecutorError("invalid staged closure") from exc
    candidate = _boot_entry_id(receipt.get("candidate_entry", ""))
    before = receipt.get("boot_state_before")
    staged = receipt.get("boot_state_after")
    if not isinstance(before, dict) or not isinstance(staged, dict):
        raise RuntimeExecutorError("missing staged boot state")
    required = set(BOOT_STATE_FIELDS)
    if set(before) != required or set(staged) != required:
        raise RuntimeExecutorError("invalid staged boot state fields")
    _require_approved_defaults(before)
    if (
        before["oneshot"] is not None
        or before["booted"] != before["approved"]
        or before["current"] != receipt.get("prior_closure")
    ):
        raise RuntimeExecutorError("invalid staged boot preimage")
    _require_boot_state(staged, before, profile=target, oneshot=candidate)
    staging_id = _require_boot_id(receipt.get("staging_boot_id"))
    boot_id = _read_boot_id()
    if boot_id == staging_id:
        raise RuntimeExecutorError("new boot not observed")
    expected = dict(staged, current=target, booted=target, oneshot=None)
    observed = _observe_boot_state(target)
    if observed != expected:
        raise RuntimeExecutorError("post-boot state does not match staged target and preserved fallback")
    selected = _read_efi_entry("LoaderEntrySelected")
    if selected != candidate or _resolve_boot_entry(target, "system", target) != candidate:
        raise RuntimeExecutorError("selected boot entry does not match staged candidate")
    if (
        _observe_boot_state(target) != observed
        or _read_efi_entry("LoaderEntrySelected") != selected
        or _read_boot_id() != boot_id
    ):
        raise RuntimeExecutorError("post-boot observation changed during readback")
    result = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_next_boot_observation_v1",
        "result": "observed",
        "request_id": request_id,
        "staging_request_id": receipt.get("request_id"),
        "staging_receipt_sha256": digest,
        "target": expected_target,
        "system_closure": target,
        "staging_boot_id": staging_id,
        "observed_boot_id": boot_id,
        "selected_entry": selected,
        "boot_state": observed,
        "persistent_state_kind": PERSISTENT_STATE_KIND,
        "persistent_state_sha256": persistent_state_sha256(
            target=expected_target, boot_state=observed,
        ),
        "observed_at": _utc_now(),
        "boot_identity_established": True,
        "application_health_established": False,
        "independent_runtime_readback_established": False,
        "persistent_promotion_authorized": False,
        "does_not_establish": [
            "controlled reboot causality", "application health",
            "independent runtime observation", "persistent promotion authority",
        ],
    }
    result["receipt_sha256"] = _sha256_json(result)
    return result


def execute_activation(
    *,
    request_id: str,
    expected_build_receipt_sha256: str,
    expected_authority_sha256: str,
    expected_plan_sha256: str,
    expected_target: str,
    runner: Runner = _run_exact,
    request_bundle: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _require_root()
    executor_cgroup = _require_dedicated_scope(request_id)
    if request_bundle is not None:
        with _exclusive_lock(executor_cgroup):
            _stage_bound_request_files(request_id, request_bundle, {
                "build-receipt.json": expected_build_receipt_sha256,
                "authority.json": expected_authority_sha256,
                "plan.json": expected_plan_sha256,
            })
    build_receipt, authority, candidate_plan = _load_request(request_id)
    build_digest = _require_canonical_digest(
        build_receipt, expected_build_receipt_sha256, "build receipt"
    )
    authority_digest = _require_canonical_digest(
        authority, expected_authority_sha256, "activation authority"
    )
    plan_digest = _require_canonical_digest(
        candidate_plan, expected_plan_sha256, "activation plan"
    )
    if authority_digest != _require_sha256(
        expected_authority_sha256, "expected authority sha256"
    ):
        raise RuntimeExecutorError("activation authority digest binding drifted")

    with _exclusive_lock(executor_cgroup):
        locked_build, locked_authority, locked_plan = _load_request(request_id)
        _require_canonical_digest(
            locked_build, expected_build_receipt_sha256, "locked build receipt"
        )
        _require_canonical_digest(
            locked_authority, expected_authority_sha256, "locked activation authority"
        )
        _require_canonical_digest(
            locked_plan, expected_plan_sha256, "locked activation plan"
        )
        plan = managed_nix.authorize_activation_plan_execution(
            locked_build,
            locked_authority,
            locked_plan,
            expected_authority_sha256=expected_authority_sha256,
            expected_target=expected_target,
            now=_utc_now(),
        )
        if plan["mode"] == "next-boot":
            return _execute_next_boot(
                request_id=request_id, plan=plan, build_digest=build_digest,
                plan_digest=plan_digest, executor_cgroup=executor_cgroup,
                reauthorize=lambda: managed_nix.authorize_activation_plan_execution(
                    locked_build, locked_authority, locked_plan,
                    expected_authority_sha256=expected_authority_sha256,
                    expected_target=expected_target, now=_utc_now(),
                ),
                runner=runner,
            )
        if plan["mode"] != "test":
            raise RuntimeExecutorError("unsupported activation mode")

        pre_current = _require_link_target(
            CURRENT_SYSTEM_LINK,
            plan["prior_closure"],
            label="current system before test activation",
        )
        pre_profile = _require_link_target(
            SYSTEM_PROFILE_LINK,
            plan["prior_closure"],
            label="persistent system profile before test activation",
        )
        with _pinned_transaction_closures(
            request_id=request_id,
            prior_closure=plan["prior_closure"],
            target_closure=plan["system_closure"],
        ) as (gc_roots, gc_root_argvs, release_gc_roots, retain_gc_roots):
            switch_mode = CONTRACT["supported_operations"]["activation"][
                "executable_modes"
            ]["test"]
            switch_argv = _switch_argv(plan["system_closure"], switch_mode)
            with _controlled_termination() as termination:
                _raise_if_termination_requested(termination)
                # GC-root registration may take a full command timeout. Re-read
                # the live prior state after pinning so another activation tool
                # cannot change the host underneath this exact-bound request.
                pre_current = _require_link_target(
                    CURRENT_SYSTEM_LINK,
                    plan["prior_closure"],
                    label="current system immediately before test activation",
                )
                _raise_if_termination_requested(termination)
                pre_profile = _require_link_target(
                    SYSTEM_PROFILE_LINK,
                    plan["prior_closure"],
                    label="persistent system profile immediately before test activation",
                )
                _raise_if_termination_requested(termination)
                _preflight_recovery_commands(plan["prior_closure"], "test")
                plan = managed_nix.authorize_activation_plan_execution(
                    locked_build,
                    locked_authority,
                    locked_plan,
                    expected_authority_sha256=expected_authority_sha256,
                    expected_target=expected_target,
                    now=_utc_now(),
                )
                # Keep every no-effect check outside the recovery guard. If a
                # termination was requested before the runner starts, there is
                # no mutation to roll back.
                _raise_if_termination_requested(termination)
                try:
                    runner(switch_argv, plan["system_closure"])
                    _raise_if_termination_requested(termination)
                    post_current = _require_link_target(
                        CURRENT_SYSTEM_LINK,
                        plan["system_closure"],
                        label="current system after test activation",
                    )
                    _raise_if_termination_requested(termination)
                    post_profile = _require_link_target(
                        SYSTEM_PROFILE_LINK,
                        plan["prior_closure"],
                        label="persistent system profile after test activation",
                    )
                    _raise_if_termination_requested(termination)
                    release_gc_roots()
                except _ProcessTerminationUncertain:
                    raise
                except (
                    _ExecutorInterrupted,
                    KeyboardInterrupt,
                    RuntimeExecutorError,
                ) as effect_error:
                    try:
                        _recover(
                            prior_closure=plan["prior_closure"],
                            target_closure=plan["system_closure"],
                            mode="test",
                            runner=runner,
                            profile_may_have_changed=True,
                        )
                    except _ProcessTerminationUncertain:
                        raise
                    except RuntimeExecutorError as recovery_error:
                        retain_gc_roots()
                        raise RuntimeExecutorError(
                            f"test activation failed and recovery is incomplete: "
                            f"{effect_error}; {recovery_error}"
                        ) from recovery_error
                    raise RuntimeExecutorError(
                        f"test activation failed; prior closure recovery completed: "
                        f"{effect_error}"
                    ) from effect_error
        return _execution_receipt(
            request_id=request_id,
            operation="activation",
            mode="test",
            plan=plan,
            build_receipt_sha256=build_digest,
            plan_sha256=plan_digest,
            argv=switch_argv,
            effect_argvs=(switch_argv,),
            gc_root_argvs=gc_root_argvs,
            executor_cgroup=executor_cgroup,
            prior_gc_root=str(gc_roots["prior"]),
            target_gc_root=str(gc_roots["target"]),
            pre_current=pre_current,
            pre_profile=pre_profile,
            post_current=post_current,
            post_profile=post_profile,
            profile_mutated=False,
        )

def _require_approved_generation(generation: int, expected: str) -> None:
    _require_link_target(
        BOOT_PROFILE_ROOT / f"heim-pc-approved-{generation}-link", expected,
        label="retained named Approved generation",
    )


def _read_approved_generation(expected: str) -> int:
    path = BOOT_PROFILE_ROOT / "heim-pc-approved"
    try:
        name = os.readlink(path)
    except OSError as exc:
        raise RuntimeExecutorError("Approved generation link unavailable") from exc
    match = re.fullmatch(r"heim-pc-approved-([1-9][0-9]*)-link", name)
    if match is None:
        raise RuntimeExecutorError("invalid named Approved generation link")
    generation = int(match.group(1))
    _require_link_target(path, expected, label="named Approved profile")
    _require_approved_generation(generation, expected)
    try:
        unchanged = os.readlink(path) == name
    except OSError as exc:
        raise RuntimeExecutorError("Approved generation vanished during readback") from exc
    if not unchanged:
        raise RuntimeExecutorError("Approved generation changed during readback")
    return generation


def _approved_profile_argv(closure: str, *, target: str | None = None,
                           generation: int | None = None) -> list[str]:
    nix_env = _require_executable(Path(closure) / "sw/bin/nix-env", label="closure-bound nix-env")
    argv = [str(nix_env), "--profile", str(BOOT_PROFILE_ROOT / "heim-pc-approved")]
    if target is not None and generation is None:
        return argv + ["--set", target]
    if target is None and type(generation) is int and generation > 0:
        return argv + ["--switch-generation", str(generation)]
    raise RuntimeExecutorError("invalid named Approved profile operation")


def _require_promotion_boot_identity(proof: Mapping[str, Any]) -> None:
    if (
        _read_boot_id() != proof["observed_boot_id"]
        or _read_efi_entry("LoaderEntrySelected") != proof["selected_entry"]
    ):
        raise RuntimeExecutorError("testboot identity changed during promotion")


def _recover_approved_promotion(
    *, proof: Mapping[str, Any], prior_generation: int, target: str,
    boot_attempted: bool, promoted_generation: int | None, runner: Runner,
) -> None:
    """Restore only the original named profile; never switch/reboot the live system."""
    baseline = proof["boot_state"]
    prior = baseline["approved"]
    with _defer_termination():
        _require_promotion_boot_identity(proof)
        _require_approved_generation(prior_generation, prior)
        observed = _observe_boot_links_and_defaults()
        pinned = ("current", "booted", "profile", "recovery", "sysfail", "oneshot")
        if any(observed[key] != baseline[key] for key in pinned):
            raise RuntimeExecutorError("Approved recovery refused: unrelated boot state drift")
        if observed["approved"] not in {prior, target}:
            raise RuntimeExecutorError("Approved recovery refused: unrelated named profile")
        if _resolve_boot_entry(target, "heim-pc-recovery", baseline["recovery"]) != baseline["recovery_entry"]:
            raise RuntimeExecutorError("Approved recovery refused: recovery entry drift")
        allowed = {baseline["approved_entry"]}
        if boot_attempted and observed["approved"] == target:
            try:
                allowed.add(_resolve_boot_entry(target, "heim-pc-approved", target))
            except RuntimeExecutorError:
                # The native install may not yet have generated the entry.
                # Only the previous known defaults are then recoverable.
                pass
        if observed["default"] not in allowed or observed["loader_default"] not in allowed:
            raise RuntimeExecutorError("Approved recovery refused: unrelated boot default")
        if observed["approved"] == target:
            if promoted_generation is not None and _read_approved_generation(target) != promoted_generation:
                raise RuntimeExecutorError("Approved recovery refused: named generation drift")
            runner(_approved_profile_argv(target, generation=prior_generation), target)
        if _read_approved_generation(prior) != prior_generation:
            raise RuntimeExecutorError("Approved recovery did not restore original generation")
        if boot_attempted:
            runner(_switch_argv(target, "boot"), target)
        if _observe_boot_state(target) != baseline:
            raise RuntimeExecutorError("Approved recovery did not restore exact boot state")
        _require_promotion_boot_identity(proof)


def _execute_approved_promotion(
    *, request_id: str, build: Mapping[str, Any], authority: Mapping[str, Any],
    candidate_plan: Mapping[str, Any], build_digest: str, plan_digest: str,
    expected_authority_sha256: str, expected_target: str,
    source_artifact_digest: str, executor_cgroup: str,
    expected_staging_receipt_sha256: str, expected_observed_boot_id: str,
    runner: Runner,
) -> dict[str, Any]:
    """Promote a proven OneShot boot using the existing native boot installer.

    The external scope authorizer must bind the exact tested boot identity and
    its application acceptance; the staging proof alone grants no authority.
    """
    staging = _read_bound_json(_request_dir(request_id) / "staging-receipt.json")
    structural = managed_nix.validate_persistent_promotion_plan(candidate_plan)
    expected_boot_id = _require_boot_id(expected_observed_boot_id)
    target = structural["system_closure"]
    prior = structural["prior_closure"]

    def observe_and_authorize() -> tuple[dict[str, Any], dict[str, Any]]:
        _require_canonical_digest(staging, expected_staging_receipt_sha256, "staging receipt")
        if (
            staging.get("build_receipt_sha256") != build_digest
            or staging.get("source_revision") != structural["source_revision"]
            or staging.get("system_closure") != target
        ):
            raise RuntimeExecutorError("next-boot proof does not bind promotion build and rollback generation")
        proof = _observe_bound_next_boot(
            request_id=request_id, receipt=staging,
            expected_staging_receipt_sha256=expected_staging_receipt_sha256,
            expected_target=expected_target,
        )
        if proof["system_closure"] != target or proof["boot_state"]["approved"] != prior:
            raise RuntimeExecutorError("next-boot proof does not bind promotion build and rollback generation")
        if proof["observed_boot_id"] != expected_boot_id:
            raise RuntimeExecutorError("next-boot proof does not match externally expected tested boot ID")
        plan = managed_nix.authorize_persistent_promotion_execution(
            build, authority, candidate_plan,
            expected_authority_sha256=expected_authority_sha256,
            expected_target=expected_target,
            expected_source_artifact_sha256=source_artifact_digest,
            expected_prior_closure=proof["boot_state"]["approved"],
            expected_prior_persistent_state_sha256=proof["persistent_state_sha256"],
            now=_utc_now(),
        )
        return proof, plan

    proof, plan = observe_and_authorize()
    baseline = proof["boot_state"]
    prior_generation = _read_approved_generation(prior)
    set_argv = _approved_profile_argv(target, target=target)
    boot_argv = _switch_argv(target, "boot")
    _approved_profile_argv(target, generation=prior_generation)
    boot_attempted = False
    promoted_generation: int | None = None
    with _pinned_transaction_closures(
        request_id=request_id, prior_closure=prior, target_closure=target,
    ) as (gc_roots, gc_root_argvs, release_gc_roots, retain_gc_roots):
        with _controlled_termination() as termination:
            fresh_proof, plan = observe_and_authorize()
            if (
                fresh_proof["boot_state"] != baseline
                or fresh_proof["observed_boot_id"] != proof["observed_boot_id"]
                or fresh_proof["selected_entry"] != proof["selected_entry"]
                or _read_approved_generation(prior) != prior_generation
            ):
                raise RuntimeExecutorError("testboot or Approved generation drifted before promotion")
            _raise_if_termination_requested(termination)
            try:
                runner(set_argv, target)
                _raise_if_termination_requested(termination)
                promoted_generation = _read_approved_generation(target)
                if promoted_generation == prior_generation:
                    raise RuntimeExecutorError("Approved promotion reused prior generation")
                _require_approved_generation(prior_generation, prior)
                _require_promotion_boot_identity(proof)
                expected_partial = {
                    k: v for k, v in baseline.items()
                    if k not in ("approved_entry", "recovery_entry")
                }
                expected_partial["approved"] = target
                if (
                    _observe_boot_links_and_defaults() != expected_partial
                    or _resolve_boot_entry(target, "heim-pc-recovery", baseline["recovery"])
                    != baseline["recovery_entry"]
                ):
                    raise RuntimeExecutorError("boot state drifted after named profile staging")
                boot_attempted = True
                runner(boot_argv, target)
                _raise_if_termination_requested(termination)
                post = _observe_boot_state(target)
                expected = dict(
                    baseline, approved=target, approved_entry=post["approved_entry"],
                    default=post["approved_entry"], loader_default=post["approved_entry"],
                )
                if post != expected or post["approved_entry"] == baseline["approved_entry"]:
                    raise RuntimeExecutorError("Approved promotion did not establish exact boot default")
                _require_approved_defaults(post)
                _require_approved_generation(prior_generation, prior)
                if _read_approved_generation(target) != promoted_generation:
                    raise RuntimeExecutorError("Approved generation drifted after boot installation")
                _require_promotion_boot_identity(proof)
                if _observe_boot_state(target) != post:
                    raise RuntimeExecutorError("Approved boot state changed during readback")
                post_state_digest = persistent_state_sha256(target=expected_target, boot_state=post)
                if post_state_digest == proof["persistent_state_sha256"]:
                    raise RuntimeExecutorError("Approved persistent state did not change")
                release_gc_roots()
            except _ProcessTerminationUncertain:
                raise
            except (_ExecutorInterrupted, KeyboardInterrupt, RuntimeExecutorError) as effect_error:
                try:
                    _recover_approved_promotion(
                        proof=proof, prior_generation=prior_generation, target=target,
                        boot_attempted=boot_attempted, promoted_generation=promoted_generation,
                        runner=runner,
                    )
                except _ProcessTerminationUncertain:
                    raise
                except RuntimeExecutorError as recovery_error:
                    retain_gc_roots()
                    raise RuntimeExecutorError(
                        f"Approved promotion failed and recovery is incomplete: {effect_error}; {recovery_error}"
                    ) from recovery_error
                raise RuntimeExecutorError(
                    f"Approved promotion failed; prior boot state restored: {effect_error}"
                ) from effect_error
    result = _execution_receipt(
        request_id=request_id, operation="persistent-promotion", mode="boot-critical-approved",
        plan=plan, build_receipt_sha256=build_digest, plan_sha256=plan_digest,
        argv=boot_argv, effect_argvs=(set_argv, boot_argv), gc_root_argvs=gc_root_argvs,
        executor_cgroup=executor_cgroup, prior_gc_root=str(gc_roots["prior"]),
        target_gc_root=str(gc_roots["target"]), pre_current=baseline["current"],
        pre_profile=baseline["profile"], post_current=post["current"],
        post_profile=post["profile"], profile_mutated=False,
    )
    result["does_not_establish"].remove("named Approved boot promotion")
    result.update(
        named_approved_promoted=True, boot_state_before=baseline, boot_state_after=post,
        prior_approved_generation=prior_generation, promoted_approved_generation=promoted_generation,
        staging_receipt_sha256=proof["staging_receipt_sha256"],
        postboot_observation_sha256=managed_nix.sha256_json(fresh_proof),
        boot_id=proof["observed_boot_id"],
        pre_persistent_state_sha256=proof["persistent_state_sha256"],
        post_persistent_state_sha256=post_state_digest,
    )
    result.pop("receipt_sha256")
    result["receipt_sha256"] = _sha256_json(result)
    return result


def execute_persistent_promotion(
    *,
    request_id: str,
    expected_build_receipt_sha256: str,
    expected_authority_sha256: str,
    expected_plan_sha256: str,
    expected_target: str,
    expected_source_artifact_sha256: str,
    expected_staging_receipt_sha256: str | None = None,
    expected_observed_boot_id: str | None = None,
    request_bundle: Mapping[str, Any] | None = None,
    runner: Runner = _run_exact,
) -> dict[str, Any]:
    _require_root()
    executor_cgroup = _require_dedicated_scope(request_id)
    source_artifact_digest = _require_sha256(
        expected_source_artifact_sha256, "expected source artifact sha256"
    )
    with _exclusive_lock(executor_cgroup):
        if request_bundle is not None:
            digests = {
                "build-receipt.json": expected_build_receipt_sha256,
                "authority.json": expected_authority_sha256,
                "plan.json": expected_plan_sha256,
            }
            if expected_staging_receipt_sha256 is not None:
                digests["staging-receipt.json"] = expected_staging_receipt_sha256
            _stage_bound_request_files(request_id, request_bundle, digests)
        locked_build, locked_authority, locked_plan = _load_request(request_id)
        build_digest = _require_canonical_digest(
            locked_build, expected_build_receipt_sha256, "locked build receipt"
        )
        _require_canonical_digest(
            locked_authority, expected_authority_sha256, "locked persistent promotion authority"
        )
        plan_digest = _require_canonical_digest(
            locked_plan, expected_plan_sha256, "locked persistent promotion plan"
        )
        validated_build = managed_nix.validate_build_receipt(locked_build)
        if validated_build["effect_scope"] == "boot-critical":
            if expected_staging_receipt_sha256 is None or expected_observed_boot_id is None:
                raise RuntimeExecutorError(
                    "boot-critical persistent promotion requires a successful next-boot successor proof and externally expected tested boot ID"
                )
            return _execute_approved_promotion(
                request_id=request_id, build=locked_build, authority=locked_authority,
                candidate_plan=locked_plan, build_digest=build_digest, plan_digest=plan_digest,
                expected_authority_sha256=expected_authority_sha256,
                expected_target=expected_target, source_artifact_digest=source_artifact_digest,
                executor_cgroup=executor_cgroup,
                expected_staging_receipt_sha256=expected_staging_receipt_sha256,
                expected_observed_boot_id=expected_observed_boot_id, runner=runner,
            )
        if expected_staging_receipt_sha256 is not None or expected_observed_boot_id is not None:
            raise RuntimeExecutorError("staging receipt and tested boot ID are only valid for boot-critical promotion")
        structural_plan = managed_nix.validate_persistent_promotion_plan(locked_plan)
        pre_current = _require_link_target(
            CURRENT_SYSTEM_LINK,
            structural_plan["prior_closure"],
            label="current system before persistent promotion",
        )
        pre_profile = _require_link_target(
            SYSTEM_PROFILE_LINK,
            structural_plan["prior_closure"],
            label="persistent system profile before persistent promotion",
        )
        prior_state_digest = _read_persistent_state_sha256(
            target=structural_plan["target"],
            current_closure=pre_current,
            profile_closure=pre_profile,
        )
        now = _utc_now()
        plan = managed_nix.authorize_persistent_promotion_execution(
            locked_build,
            locked_authority,
            locked_plan,
            expected_authority_sha256=expected_authority_sha256,
            expected_target=expected_target,
            expected_source_artifact_sha256=source_artifact_digest,
            expected_prior_closure=pre_current,
            expected_prior_persistent_state_sha256=prior_state_digest,
            now=now,
        )
        with _pinned_transaction_closures(
            request_id=request_id,
            prior_closure=plan["prior_closure"],
            target_closure=plan["system_closure"],
        ) as (gc_roots, gc_root_argvs, release_gc_roots, retain_gc_roots):
            profile_changed = False
            profile_set_argv = _profile_set_argv(
                plan["prior_closure"], plan["system_closure"]
            )
            switch_argv = _switch_argv(plan["system_closure"], "switch")
            with _controlled_termination() as termination:
                _raise_if_termination_requested(termination)
                # GC-root pinning can be long-running. Refresh both live prior
                # links after pinning, recompute the bound persistent-state
                # digest, and abort before effects if any external tool drifted
                # the host while this private activation lock was held.
                pre_current = _require_link_target(
                    CURRENT_SYSTEM_LINK,
                    plan["prior_closure"],
                    label="current system immediately before persistent promotion",
                )
                _raise_if_termination_requested(termination)
                pre_profile = _require_link_target(
                    SYSTEM_PROFILE_LINK,
                    plan["prior_closure"],
                    label="persistent system profile immediately before persistent promotion",
                )
                _raise_if_termination_requested(termination)
                _preflight_recovery_commands(plan["prior_closure"], "switch")
                prior_state_digest = _read_persistent_state_sha256(
                    target=plan["target"],
                    current_closure=pre_current,
                    profile_closure=pre_profile,
                )
                plan = managed_nix.authorize_persistent_promotion_execution(
                    locked_build,
                    locked_authority,
                    locked_plan,
                    expected_authority_sha256=expected_authority_sha256,
                    expected_target=expected_target,
                    expected_source_artifact_sha256=source_artifact_digest,
                    expected_prior_closure=pre_current,
                    expected_prior_persistent_state_sha256=prior_state_digest,
                    now=_utc_now(),
                )
                # No effect has started yet, so a pending termination here must
                # exit without dispatching recovery. Once runner() is entered,
                # _run_exact starts the private child before observing the flag,
                # making recovery conservative and appropriate from that point.
                _raise_if_termination_requested(termination)
                try:
                    # The profile command may mutate successfully and still report a
                    # timeout/non-zero status. Treat the profile as potentially changed
                    # before invoking it so every failure enters rollback.
                    profile_changed = True
                    runner(profile_set_argv, plan["prior_closure"])
                    _raise_if_termination_requested(termination)
                    _require_link_target(
                        SYSTEM_PROFILE_LINK,
                        plan["system_closure"],
                        label="persistent system profile after promotion staging",
                    )
                    _raise_if_termination_requested(termination)
                    runner(switch_argv, plan["system_closure"])
                    _raise_if_termination_requested(termination)
                    post_current = _require_link_target(
                        CURRENT_SYSTEM_LINK,
                        plan["system_closure"],
                        label="current system after persistent promotion",
                    )
                    _raise_if_termination_requested(termination)
                    post_profile = _require_link_target(
                        SYSTEM_PROFILE_LINK,
                        plan["system_closure"],
                        label="persistent system profile after persistent promotion",
                    )
                    _raise_if_termination_requested(termination)
                    release_gc_roots()
                except _ProcessTerminationUncertain:
                    raise
                except (
                    _ExecutorInterrupted,
                    KeyboardInterrupt,
                    RuntimeExecutorError,
                ) as effect_error:
                    try:
                        _recover(
                            prior_closure=plan["prior_closure"],
                            target_closure=plan["system_closure"],
                            mode="switch",
                            runner=runner,
                            profile_may_have_changed=profile_changed,
                        )
                    except _ProcessTerminationUncertain:
                        raise
                    except RuntimeExecutorError as recovery_error:
                        retain_gc_roots()
                        raise RuntimeExecutorError(
                            f"persistent promotion failed and recovery is incomplete: "
                            f"{effect_error}; {recovery_error}"
                        ) from recovery_error
                    raise RuntimeExecutorError(
                        f"persistent promotion failed; prior closure recovery completed: "
                        f"{effect_error}"
                    ) from effect_error
        return _execution_receipt(
            request_id=request_id,
            operation="persistent-promotion",
            mode="persistent",
            plan=plan,
            build_receipt_sha256=build_digest,
            plan_sha256=plan_digest,
            argv=switch_argv,
            effect_argvs=(profile_set_argv, switch_argv),
            gc_root_argvs=gc_root_argvs,
            executor_cgroup=executor_cgroup,
            prior_gc_root=str(gc_roots["prior"]),
            target_gc_root=str(gc_roots["target"]),
            pre_current=pre_current,
            pre_profile=pre_profile,
            post_current=post_current,
            post_profile=post_profile,
            profile_mutated=True,
        )

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Execute only an externally authorized, exact-closure NixOS Day-2 "
            "activation request. This does not stage authority or finalize "
            "independent runtime evidence."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--request-id", required=True)
        command.add_argument("--expected-build-receipt-sha256", required=True)
        command.add_argument("--expected-authority-sha256", required=True)
        command.add_argument("--expected-plan-sha256", required=True)
        command.add_argument("--expected-target", required=True)

    activation = sub.add_parser("execute-activation")
    common(activation)
    activation.add_argument("--request-bundle-json")

    observe = sub.add_parser("observe-next-boot")
    observe.add_argument("--request-id", required=True)
    observe.add_argument("--expected-staging-receipt-sha256", required=True)
    observe.add_argument("--expected-target", required=True)
    observe.add_argument("--request-bundle-json")

    promotion = sub.add_parser("execute-persistent-promotion")
    common(promotion)
    promotion.add_argument("--expected-source-artifact-sha256", required=True)
    promotion.add_argument("--expected-staging-receipt-sha256")
    promotion.add_argument("--expected-observed-boot-id")
    promotion.add_argument("--request-bundle-json")
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        with _controlled_termination(preserve_ignored=True) as termination:
            if args.command == "execute-activation":
                result = execute_activation(
                    request_id=args.request_id,
                    expected_build_receipt_sha256=args.expected_build_receipt_sha256,
                    expected_authority_sha256=args.expected_authority_sha256,
                    expected_plan_sha256=args.expected_plan_sha256,
                    expected_target=args.expected_target,
                    request_bundle=_parse_request_bundle(args.request_bundle_json),
                )
            elif args.command == "observe-next-boot":
                result = observe_next_boot(
                    request_id=args.request_id,
                    expected_staging_receipt_sha256=args.expected_staging_receipt_sha256,
                    expected_target=args.expected_target,
                    request_bundle=_parse_request_bundle(args.request_bundle_json),
                )
            elif args.command == "execute-persistent-promotion":
                result = execute_persistent_promotion(
                    request_id=args.request_id,
                    expected_build_receipt_sha256=args.expected_build_receipt_sha256,
                    expected_authority_sha256=args.expected_authority_sha256,
                    expected_plan_sha256=args.expected_plan_sha256,
                    expected_target=args.expected_target,
                    expected_source_artifact_sha256=args.expected_source_artifact_sha256,
                    expected_staging_receipt_sha256=args.expected_staging_receipt_sha256,
                    expected_observed_boot_id=args.expected_observed_boot_id,
                    request_bundle=_parse_request_bundle(args.request_bundle_json),
                )
            else:
                parser.error("unsupported command")
            # The mutation and its postconditions are already committed here.
            # Do not let a late interactive signal erase success evidence:
            # finish the canonical execution receipt while the flag-only
            # handlers remain installed, then return success.
            with _defer_termination():
                sys.stdout.buffer.write(_canonical_json(result) + b"\n")
                sys.stdout.buffer.flush()
            del termination
    except (_ExecutorInterrupted, KeyboardInterrupt):
        print(
            "nixos day2 activation error: interrupted before controlled completion",
            file=sys.stderr,
        )
        return 1
    except (RuntimeExecutorError, managed_nix.ManagedNixError) as exc:
        print(f"nixos day2 activation error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
