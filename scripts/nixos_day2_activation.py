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
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence


class RuntimeExecutorError(RuntimeError):
    """Fail-closed runtime-executor error."""


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
MAX_FILE_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 1800
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
        "root-owned request staging and capability authorization",
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


def _minimal_env(target_closure: str) -> dict[str, str]:
    return {
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{target_closure}/sw/bin",
        "NIX_PATH": "",
    }


Runner = Callable[[Sequence[str], str], None]


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeExecutorError(
            "executor process group did not terminate after SIGKILL"
        ) from exc


def _run_exact(argv: Sequence[str], target_closure: str) -> None:
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise RuntimeExecutorError("executor argv is invalid")
    if not argv[0].startswith("/nix/store/"):
        raise RuntimeExecutorError("executor command must be closure-bound")
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
            start_new_session=True,
        )
    except OSError as exc:
        raise RuntimeExecutorError(f"executor command failed to start: {exc}") from exc
    try:
        returncode = process.wait(timeout=COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        raise RuntimeExecutorError(
            "executor command timed out; process group terminated"
        ) from exc
    if returncode != 0:
        # A failing switch helper must not leave a still-running child in its
        # private process group racing the explicit recovery activation.
        _terminate_process_group(process)
        raise RuntimeExecutorError(
            f"executor command returned non-zero status {returncode}"
        )

@contextmanager
def _exclusive_lock() -> Iterator[None]:
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
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
            raise RuntimeExecutorError("activation lock metadata is unsafe")
        _require_exact_mode(st, 0o600, "activation lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeExecutorError("another NixOS activation executor holds the lock") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeExecutorError("runtime activation execution requires root")


def _recover(
    *,
    prior_closure: str,
    mode: str,
    runner: Runner,
    profile_was_changed: bool,
) -> None:
    errors: list[str] = []
    if profile_was_changed:
        try:
            runner(_profile_set_argv(prior_closure, prior_closure), prior_closure)
            _require_link_target(
                SYSTEM_PROFILE_LINK,
                prior_closure,
                label="recovered persistent system profile",
            )
        except RuntimeExecutorError as exc:
            errors.append(f"profile rollback failed: {exc}")
    try:
        runner(_switch_argv(prior_closure, mode), prior_closure)
    except RuntimeExecutorError as exc:
        errors.append(f"prior closure recovery activation failed: {exc}")
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

    with _exclusive_lock():
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
        switch_mode = CONTRACT["supported_operations"]["activation"][
            "executable_modes"
        ]["test"]
        switch_argv = _switch_argv(plan["system_closure"], switch_mode)
        try:
            runner(switch_argv, plan["system_closure"])
        except RuntimeExecutorError as effect_error:
            try:
                _recover(
                    prior_closure=plan["prior_closure"],
                    mode="test",
                    runner=runner,
                    profile_was_changed=False,
                )
            except RuntimeExecutorError as recovery_error:
                raise RuntimeExecutorError(
                    f"test activation failed and recovery is incomplete: "
                    f"{effect_error}; {recovery_error}"
                ) from recovery_error
            raise RuntimeExecutorError(
                f"test activation failed; prior closure recovery completed: {effect_error}"
            ) from effect_error

        post_current = _require_link_target(
            CURRENT_SYSTEM_LINK,
            plan["system_closure"],
            label="current system after test activation",
        )
        post_profile = _require_link_target(
            SYSTEM_PROFILE_LINK,
            plan["prior_closure"],
            label="persistent system profile after test activation",
        )
        return _execution_receipt(
            request_id=request_id,
            operation="activation",
            mode="test",
            plan=plan,
            build_receipt_sha256=build_digest,
            plan_sha256=plan_digest,
            argv=switch_argv,
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

    with _exclusive_lock():
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
        profile_changed = False
        switch_argv = _switch_argv(plan["system_closure"], "switch")
        try:
            runner(
                _profile_set_argv(plan["prior_closure"], plan["system_closure"]),
                plan["prior_closure"],
            )
            profile_changed = True
            _require_link_target(
                SYSTEM_PROFILE_LINK,
                plan["system_closure"],
                label="persistent system profile after promotion staging",
            )
            runner(switch_argv, plan["system_closure"])
        except RuntimeExecutorError as effect_error:
            try:
                _recover(
                    prior_closure=plan["prior_closure"],
                    mode="switch",
                    runner=runner,
                    profile_was_changed=profile_changed,
                )
            except RuntimeExecutorError as recovery_error:
                raise RuntimeExecutorError(
                    f"persistent promotion failed and recovery is incomplete: "
                    f"{effect_error}; {recovery_error}"
                ) from recovery_error
            raise RuntimeExecutorError(
                f"persistent promotion failed; prior closure recovery completed: {effect_error}"
            ) from effect_error

        post_current = _require_link_target(
            CURRENT_SYSTEM_LINK,
            plan["system_closure"],
            label="current system after persistent promotion",
        )
        post_profile = _require_link_target(
            SYSTEM_PROFILE_LINK,
            plan["system_closure"],
            label="persistent system profile after persistent promotion",
        )
        return _execution_receipt(
            request_id=request_id,
            operation="persistent-promotion",
            mode="persistent",
            plan=plan,
            build_receipt_sha256=build_digest,
            plan_sha256=plan_digest,
            argv=switch_argv,
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
    except (RuntimeExecutorError, managed_nix.ManagedNixError) as exc:
        print(f"nixos day2 activation error: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(_canonical_json(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
