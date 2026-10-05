#!/usr/bin/env python3
"""Narrow closure-bound NixOS Day-2 runtime executor.

The checked-in managed_nix contract remains validation-only.  This successor
executes only an already-built, already-authorized immutable system closure.
It does not evaluate Nix, resolve Git/branches/locks/inputs, reboot the host, or
grant itself request-staging/rootbroker authority.

Inputs must already be staged as root-owned single-link 0600 JSON files below
/run/heim-pc/nixos-activation/requests/<request-id>.  The caller must also bind
their canonical JSON digests out-of-band.  That staging/capability boundary and
the independent post-effect observer are intentionally separate successor
work; this program emits execution evidence, never the final activation or
persistent-promotion receipt.
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
            "executable_modes": {"test": "test"},
            "deferred_modes": {
                "next-boot": "requires-reviewed-one-shot-boot-state-contract"
            },
        },
        "persistent-promotion": {
            "plan_kind": managed_nix.PERSISTENT_PROMOTION_PLAN_KIND,
            "executor_authority": managed_nix.PERSISTENT_PROMOTION_EXECUTOR_AUTHORITY,
            "switch_argument": "switch",
            "boot_critical_requires_next_boot_successor_proof": True,
            "boot_critical_execution_implemented_here": False,
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
        "request_staging_implemented_here": False,
        "rootbroker_authorization_implemented_here": False,
        "reboot_implemented_here": False,
    }
    if raw.get("runtime") != expected_runtime:
        raise RuntimeExecutorError("runtime executor effect boundary drifted")

    if raw.get("persistent_state") != {
        "schema_version": 1,
        "kind": "heim_pc.nixos_persistent_runtime_state_v1",
        "algorithm": "canonical-json-sha256-v1",
        "fields": [
            "schema_version",
            "kind",
            "target",
            "current_closure",
            "persistent_profile_closure",
        ],
        "target_source": "externally-bound-plan-target",
        "current_closure_source": str(CURRENT_SYSTEM_LINK),
        "persistent_profile_closure_source": str(SYSTEM_PROFILE_LINK),
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
        "root-owned request staging, dedicated transient scope launch, and capability authorization",
        "boot-critical one-shot next-boot activation and post-boot proof",
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


def _persistent_state_payload(*, target: str, current_closure: str, profile_closure: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": PERSISTENT_STATE_KIND,
        "target": target,
        "current_closure": current_closure,
        "persistent_profile_closure": profile_closure,
    }


def persistent_state_sha256(*, target: str, current_closure: str, profile_closure: str) -> str:
    return _sha256_json(
        _persistent_state_payload(
            target=target,
            current_closure=current_closure,
            profile_closure=profile_closure,
        )
    )


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


def _minimal_env(target_closure: str) -> dict[str, str]:
    return {
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{target_closure}/sw/bin",
        "NIX_PATH": "",
        "NIX_CONFIG": NIX_RUNTIME_CONFIG,
    }


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
    if not argv or any(not isinstance(item, str) or not item for item in argv):
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
    mode: str,
    runner: Runner,
    profile_may_have_changed: bool,
) -> None:
    errors: list[str] = []
    # Recovery must run to a verified postcondition even when more interactive
    # termination requests arrive.  The shared flag-only handler records them,
    # while nested _run_exact calls defer acting on them until recovery ends.
    with _defer_termination():
        if profile_may_have_changed:
            try:
                observed_profile = _resolve_link(
                    SYSTEM_PROFILE_LINK,
                    label="persistent system profile before recovery rollback",
                )
            except RuntimeExecutorError as exc:
                errors.append(f"profile rollback precheck failed: {exc}")
            else:
                if observed_profile != prior_closure:
                    try:
                        runner(
                            _profile_set_argv(prior_closure, prior_closure),
                            prior_closure,
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
        try:
            runner(_switch_argv(prior_closure, mode), prior_closure)
        except _ProcessTerminationUncertain:
            raise
        except RuntimeExecutorError as exc:
            errors.append(f"prior closure recovery activation failed: {exc}")

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
        ],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    return receipt


def execute_activation(
    *,
    request_id: str,
    expected_build_receipt_sha256: str,
    expected_authority_sha256: str,
    expected_plan_sha256: str,
    expected_target: str,
    runner: Runner = _run_exact,
) -> dict[str, Any]:
    _require_root()
    executor_cgroup = _require_dedicated_scope(request_id)
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
        if plan["mode"] != "test":
            raise RuntimeExecutorError(
                "next-boot runtime execution is deferred until a reviewed "
                "one-shot boot-state contract exists"
            )

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

def execute_persistent_promotion(
    *,
    request_id: str,
    expected_build_receipt_sha256: str,
    expected_authority_sha256: str,
    expected_plan_sha256: str,
    expected_target: str,
    expected_source_artifact_sha256: str,
    runner: Runner = _run_exact,
) -> dict[str, Any]:
    _require_root()
    executor_cgroup = _require_dedicated_scope(request_id)
    build_receipt, authority, candidate_plan = _load_request(request_id)
    build_digest = _require_canonical_digest(
        build_receipt, expected_build_receipt_sha256, "build receipt"
    )
    _require_canonical_digest(
        authority, expected_authority_sha256, "persistent promotion authority"
    )
    plan_digest = _require_canonical_digest(
        candidate_plan, expected_plan_sha256, "persistent promotion plan"
    )
    source_artifact_digest = _require_sha256(
        expected_source_artifact_sha256, "expected source artifact sha256"
    )

    with _exclusive_lock(executor_cgroup):
        locked_build, locked_authority, locked_plan = _load_request(request_id)
        _require_canonical_digest(
            locked_build, expected_build_receipt_sha256, "locked build receipt"
        )
        _require_canonical_digest(
            locked_authority,
            expected_authority_sha256,
            "locked persistent promotion authority",
        )
        _require_canonical_digest(
            locked_plan, expected_plan_sha256, "locked persistent promotion plan"
        )
        validated_build = managed_nix.validate_build_receipt(locked_build)
        if validated_build["effect_scope"] == "boot-critical":
            raise RuntimeExecutorError(
                "boot-critical persistent promotion requires a successful "
                "next-boot successor proof; that runtime path is not implemented here"
            )
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
        prior_state_digest = persistent_state_sha256(
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

    promotion = sub.add_parser("execute-persistent-promotion")
    common(promotion)
    promotion.add_argument("--expected-source-artifact-sha256", required=True)
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
                )
            elif args.command == "execute-persistent-promotion":
                result = execute_persistent_promotion(
                    request_id=args.request_id,
                    expected_build_receipt_sha256=args.expected_build_receipt_sha256,
                    expected_authority_sha256=args.expected_authority_sha256,
                    expected_plan_sha256=args.expected_plan_sha256,
                    expected_target=args.expected_target,
                    expected_source_artifact_sha256=args.expected_source_artifact_sha256,
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
