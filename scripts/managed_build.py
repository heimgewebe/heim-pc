#!/usr/bin/env python3
"""Plan and execute bounded managed builds without changing interactive shell behavior."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit, urlunsplit

try:
    from scripts.storage_inventory import ScanResult, scan_path
except ModuleNotFoundError:  # Direct execution from scripts/.
    from storage_inventory import ScanResult, scan_path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "config" / "managed-build.v1.json"
MAX_VERSION_OUTPUT_BYTES = 4096
VERSION_TIMEOUT_SECONDS = 5


class PolicyError(ValueError):
    """Raised when the managed-build policy is malformed."""


class ManagedBuildError(RuntimeError):
    """Raised when a managed build cannot be planned or executed safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_nonnegative_budget(value: Any, name: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise PolicyError(f"{name} must be an object")
    warning = value.get("warning")
    hard = value.get("hard")
    if (
        not isinstance(warning, int)
        or isinstance(warning, bool)
        or not isinstance(hard, int)
        or isinstance(hard, bool)
        or warning < 0
        or hard < warning
    ):
        raise PolicyError(
            f"{name} must contain ordered non-negative integer warning/hard values"
        )
    return {"warning": warning, "hard": hard}


def _validate_relative_path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PolicyError(f"{name} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or value in {".", "./"}:
        raise PolicyError(f"{name} must stay below the repository root")
    return value


def _validate_home_template(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.startswith("${HOME}/") or "\x00" in value:
        raise PolicyError(f"{name} must be a ${{HOME}}-rooted path template")
    remainder = value.removeprefix("${HOME}/")
    _validate_relative_path(remainder, name)
    return value


def _validate_executable_search_path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PolicyError(f"{name} must be a non-empty path template")
    if value.startswith("${HOME}/"):
        return _validate_home_template(value, name)
    path = Path(value)
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise PolicyError(f"{name} must be absolute or ${{HOME}}-rooted")
    return value


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read managed-build policy {path}: {exc}") from exc
    if not isinstance(policy, dict):
        raise PolicyError("managed-build policy must be an object")
    if policy.get("schema_version") != 1:
        raise PolicyError("unsupported managed-build policy schema_version")
    if policy.get("kind") != "heim_pc.managed_build_policy":
        raise PolicyError("unexpected managed-build policy kind")
    if policy.get("interactive_shell_behavior") != "unchanged":
        raise PolicyError("interactive_shell_behavior must remain unchanged")
    if policy.get("automatic_cleanup_authorized") is not False:
        raise PolicyError("automatic_cleanup_authorized must remain false")

    _validate_home_template(policy.get("cache_root"), "cache_root")
    _validate_home_template(policy.get("state_root"), "state_root")
    search_paths = policy.get("executable_search_paths")
    if not isinstance(search_paths, list) or not search_paths:
        raise PolicyError("executable_search_paths must be a non-empty list")
    validated_search_paths = [
        _validate_executable_search_path(value, f"executable_search_paths[{index}]")
        for index, value in enumerate(search_paths)
    ]
    if len(validated_search_paths) != len(set(validated_search_paths)):
        raise PolicyError("executable_search_paths must be unique")
    _require_nonnegative_budget(
        policy.get("managed_worktree_budget_bytes"),
        "managed_worktree_budget_bytes",
    )
    _require_nonnegative_budget(
        policy.get("per_identity_cache_budget_bytes"),
        "per_identity_cache_budget_bytes",
    )

    max_receipts = policy.get("max_receipts")
    if not isinstance(max_receipts, int) or isinstance(max_receipts, bool) or max_receipts < 1:
        raise PolicyError("max_receipts must be a positive integer")

    tools = policy.get("tools")
    if not isinstance(tools, dict) or set(tools) != {"cargo", "node", "python", "playwright"}:
        raise PolicyError("tools must define cargo, node, python and playwright exactly")
    executable_owners: dict[str, str] = {}
    for tool_name, spec in tools.items():
        if not isinstance(spec, dict):
            raise PolicyError(f"tool {tool_name} must be an object")
        executables = spec.get("executables")
        lockfiles = spec.get("lockfiles")
        payloads = spec.get("worktree_payloads")
        environment = spec.get("environment")
        if not isinstance(executables, list) or not executables:
            raise PolicyError(f"tool {tool_name} requires executables")
        for executable in executables:
            if (
                not isinstance(executable, str)
                or not executable
                or "/" in executable
                or executable in executable_owners
            ):
                raise PolicyError(f"tool {tool_name} has invalid or duplicate executable")
            executable_owners[executable] = tool_name
        if not isinstance(lockfiles, list):
            raise PolicyError(f"tool {tool_name} lockfiles must be a list")
        for index, lockfile in enumerate(lockfiles):
            _validate_relative_path(lockfile, f"tools.{tool_name}.lockfiles[{index}]")
        if not isinstance(payloads, list):
            raise PolicyError(f"tool {tool_name} worktree_payloads must be a list")
        for index, payload in enumerate(payloads):
            _validate_relative_path(payload, f"tools.{tool_name}.worktree_payloads[{index}]")
        if not isinstance(environment, dict) or not environment:
            raise PolicyError(f"tool {tool_name} requires environment mappings")
        for variable, suffix in environment.items():
            if (
                not isinstance(variable, str)
                or not variable
                or not variable.replace("_", "").isalnum()
            ):
                raise PolicyError(f"tool {tool_name} has invalid environment variable")
            _validate_relative_path(suffix, f"tools.{tool_name}.environment.{variable}")
    return policy


def _expand_home(template: str, home: Path) -> Path:
    home = home.expanduser().resolve()
    prefix = "${HOME}/"
    if not template.startswith(prefix):
        raise PolicyError("path template is not HOME-rooted")
    return home / template.removeprefix(prefix)


def _run_readonly(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int = VERSION_TIMEOUT_SECONDS,
) -> str:
    try:
        result = subprocess.run(
            list(argv),
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable:{type(exc).__name__}"
    output = result.stdout[:MAX_VERSION_OUTPUT_BYTES].strip()
    return f"rc={result.returncode}\n{output}"


def _git(repo: Path, *arguments: str, required: bool = True) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=VERSION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ManagedBuildError(f"cannot inspect repository: {exc}") from exc
    if result.returncode != 0:
        if required:
            detail = result.stderr.strip() or result.stdout.strip()
            raise ManagedBuildError(f"git {' '.join(arguments)} failed: {detail}")
        return ""
    return result.stdout.strip()


def _sanitize_remote(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.lower(), f"{host.lower()}{port}", parsed.path, "", ""))
    if "@" in value and ":" in value.split("@", 1)[1]:
        host_path = value.split("@", 1)[1]
        host, path = host_path.split(":", 1)
        return f"ssh://{host.lower()}/{path}"
    return value


def repository_facts(repo: Path) -> dict[str, str]:
    requested = repo.expanduser().resolve()
    root = Path(_git(requested, "rev-parse", "--show-toplevel")).resolve()
    common_raw = _git(root, "rev-parse", "--git-common-dir")
    common = Path(common_raw)
    if not common.is_absolute():
        common = (root / common).resolve()
    remote = _sanitize_remote(_git(root, "config", "--get", "remote.origin.url", required=False))
    identity = {
        "git_common_dir": str(common),
        "origin": remote,
    }
    return {
        "root": str(root),
        "git_common_dir": str(common),
        "repository_identity_sha256": _sha256_json(identity),
    }


def _files_digest(repo: Path, relative_paths: Sequence[str]) -> dict[str, Any]:
    entries: list[dict[str, str]] = []
    for relative in sorted(set(relative_paths)):
        path = repo / relative
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ManagedBuildError(f"cannot inspect identity file {path}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ManagedBuildError(f"identity file must not be a symlink: {path}")
        if not stat.S_ISREG(info.st_mode):
            raise ManagedBuildError(f"identity file must be regular: {path}")
        entries.append({"path": relative, "sha256": _sha256_file(path)})
    return {"files": entries, "sha256": _sha256_json(entries)}


def _command_basename(command: Sequence[str]) -> str:
    if not command or not isinstance(command[0], str) or not command[0]:
        raise ManagedBuildError("managed build requires a command")
    return Path(command[0]).name


def classify_tool(
    policy: dict[str, Any],
    command: Sequence[str],
    *,
    explicit_tool: str | None = None,
) -> str:
    basename = _command_basename(command)
    lowered = [str(item).lower() for item in command[1:]]
    if explicit_tool is not None:
        if explicit_tool not in policy["tools"]:
            raise ManagedBuildError(f"unknown managed build tool: {explicit_tool}")
        allowed = policy["tools"][explicit_tool]["executables"]
        if basename not in allowed:
            if not (
                explicit_tool == "playwright"
                and basename in {"npx", "npm", "pnpm", "yarn", "python", "python3"}
                and "playwright" in lowered
            ):
                raise ManagedBuildError(
                    f"executable {basename!r} is not allowed for tool {explicit_tool}"
                )
        return explicit_tool
    if "playwright" in lowered and basename in {
        "npx",
        "npm",
        "pnpm",
        "yarn",
        "python",
        "python3",
    }:
        return "playwright"
    for tool_name, spec in policy["tools"].items():
        if basename in spec["executables"]:
            return tool_name
    raise ManagedBuildError(f"unsupported managed build executable: {basename}")


def infer_profile(tool: str, command: Sequence[str], explicit_profile: str | None) -> str:
    if explicit_profile:
        if not explicit_profile.replace("-", "").replace("_", "").isalnum():
            raise ManagedBuildError("profile must be alphanumeric with '-' or '_'")
        return explicit_profile
    args = [str(item) for item in command[1:]]
    if tool == "cargo":
        if "--profile" in args:
            index = args.index("--profile")
            if index + 1 >= len(args):
                raise ManagedBuildError("--profile requires a value")
            return infer_profile(tool, command, args[index + 1])
        if "--release" in args:
            return "release"
        for candidate in ("test", "bench", "check", "doc"):
            if candidate in args:
                return candidate
        return "dev"
    if tool == "playwright":
        return "browser"
    if any("test" in item.lower() for item in args):
        return "test"
    if any("build" in item.lower() for item in args):
        return "build"
    return "default"


def _companion_executable(executable: str, companion: str) -> str:
    candidate = Path(executable).parent / companion
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate.absolute())
    return companion


def _toolchain_digest(
    tool: str,
    command: Sequence[str],
    repo: Path,
) -> dict[str, Any]:
    basename = _command_basename(command)
    observations: dict[str, str] = {}
    if tool == "cargo":
        observations["cargo"] = _run_readonly([command[0], "--version"], cwd=repo)
        rustc = _companion_executable(command[0], "rustc")
        observations["rustc"] = _run_readonly([rustc, "-Vv"], cwd=repo)
        observations["files"] = _files_digest(
            repo, ["rust-toolchain", "rust-toolchain.toml"]
        )["sha256"]
    elif tool in {"node", "playwright"}:
        node = command[0] if basename == "node" else _companion_executable(command[0], "node")
        observations["node"] = _run_readonly([node, "--version"], cwd=repo)
        if basename not in {"npx"}:
            observations[basename] = _run_readonly([command[0], "--version"], cwd=repo)
    else:
        observations["python_runtime"] = sys.version
        observations[basename] = _run_readonly([command[0], "--version"], cwd=repo)
    return {"observations": observations, "sha256": _sha256_json(observations)}


def _status(size_bytes: int, budget: dict[str, int]) -> str:
    if size_bytes >= budget["hard"]:
        return "hard_limit"
    if size_bytes >= budget["warning"]:
        return "warning"
    return "ok"


def scan_worktree_payloads(
    repo: Path,
    payloads: Sequence[str],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    total = 0
    for relative in sorted(set(payloads)):
        path = repo if relative == "." else repo / relative
        if not path.exists() and not path.is_symlink():
            continue
        result: ScanResult = scan_path(path, cross_filesystems=False)
        entry = {
            "relative_path": relative,
            "allocated_bytes": result.size_bytes,
            "logical_bytes": result.apparent_size_bytes,
            "file_count": result.file_count,
            "directory_count": result.directory_count,
            "error_count": result.error_count,
        }
        entries.append(entry)
        total += result.size_bytes
    return {"allocated_bytes": total, "entries": entries}


def _pin_path(state_root: Path, repository_id: str, tool: str) -> Path:
    return state_root / "pins" / f"{repository_id}-{tool}.json"


def read_pin(
    state_root: Path,
    repository_id: str,
    tool: str,
    *,
    now_epoch: int | None = None,
) -> dict[str, Any] | None:
    path = _pin_path(state_root, repository_id, tool)
    now = int(time.time()) if now_epoch is None else now_epoch
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ManagedBuildError(f"cannot inspect pin {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ManagedBuildError(f"pin must be a regular non-symlink file: {path}")
    try:
        pin = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedBuildError(f"cannot read pin {path}: {exc}") from exc
    valid = (
        isinstance(pin, dict)
        and pin.get("schema_version") == 1
        and pin.get("repository_identity_sha256") == repository_id
        and pin.get("tool") == tool
        and isinstance(pin.get("reason"), str)
        and bool(pin["reason"].strip())
        and isinstance(pin.get("expires_at_unix"), int)
        and pin["expires_at_unix"] > now
    )
    if not valid:
        return None
    return {
        "path": str(path),
        "reason": pin["reason"],
        "expires_at_unix": pin["expires_at_unix"],
        "sha256": _sha256_file(path),
    }


def _build_environment(tool: str, base: Path, spec: dict[str, Any]) -> dict[str, str]:
    environment = {
        variable: str(base / relative)
        for variable, relative in sorted(spec["environment"].items())
    }
    if tool == "playwright":
        node_environment = {
            "NPM_CONFIG_CACHE": str(base / "npm"),
            "npm_config_cache": str(base / "npm"),
            "YARN_CACHE_FOLDER": str(base / "yarn"),
            "PNPM_STORE_DIR": str(base / "pnpm-store"),
        }
        node_environment.update(environment)
        return node_environment
    return environment


def build_plan(
    policy: dict[str, Any],
    *,
    repo: Path,
    command: Sequence[str],
    home: Path,
    explicit_tool: str | None = None,
    explicit_profile: str | None = None,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    facts = repository_facts(repo)
    root = Path(facts["root"])
    tool = classify_tool(policy, command, explicit_tool=explicit_tool)
    profile = infer_profile(tool, command, explicit_profile)
    spec = policy["tools"][tool]
    lockfiles = _files_digest(root, spec["lockfiles"])
    toolchain = _toolchain_digest(tool, command, root)
    identity_payload = {
        "schema_version": 1,
        "repository_identity_sha256": facts["repository_identity_sha256"],
        "tool": tool,
        "toolchain_sha256": toolchain["sha256"],
        "lockfiles_sha256": lockfiles["sha256"],
        "profile": profile,
    }
    cache_key = _sha256_json(identity_payload)
    cache_root = _expand_home(policy["cache_root"], home)
    state_root = _expand_home(policy["state_root"], home)
    cache_path = cache_root / tool / cache_key
    if cache_path == root or root in cache_path.parents:
        raise ManagedBuildError("managed cache path must stay outside the repository")
    if state_root == root or root in state_root.parents:
        raise ManagedBuildError("managed state path must stay outside the repository")

    worktree = scan_worktree_payloads(root, spec["worktree_payloads"])
    worktree_budget = _require_nonnegative_budget(
        policy["managed_worktree_budget_bytes"],
        "managed_worktree_budget_bytes",
    )
    worktree_status = _status(worktree["allocated_bytes"], worktree_budget)
    pin = read_pin(
        state_root,
        facts["repository_identity_sha256"],
        tool,
        now_epoch=now_epoch,
    )
    blocked = worktree_status == "hard_limit" and pin is None

    cache_scan = (
        scan_worktree_payloads(cache_path, ["."])
        if cache_path.exists() and cache_path.is_dir() and not cache_path.is_symlink()
        else {"allocated_bytes": 0, "entries": []}
    )
    cache_budget = _require_nonnegative_budget(
        policy["per_identity_cache_budget_bytes"],
        "per_identity_cache_budget_bytes",
    )
    return {
        "schema_version": 1,
        "kind": "heim_pc.managed_build_plan",
        "generated_at": _utc_now(),
        "policy_sha256": _sha256_json(policy),
        "repository_root": str(root),
        "git_common_dir": facts["git_common_dir"],
        "repository_identity_sha256": facts["repository_identity_sha256"],
        "tool": tool,
        "profile": profile,
        "identity": identity_payload,
        "cache_key": cache_key,
        "cache_path": str(cache_path),
        "state_root": str(state_root),
        "environment": _build_environment(tool, cache_path, spec),
        "command": {
            "executable": _command_basename(command),
            "argv_sha256": _sha256_json(list(command)),
        },
        "guard": {
            "status": "blocked" if blocked else worktree_status,
            "blocked": blocked,
            "worktree": worktree,
            "budget_bytes": worktree_budget,
            "pin": pin,
        },
        "cache_observation": {
            "allocated_bytes": cache_scan["allocated_bytes"],
            "status": _status(cache_scan["allocated_bytes"], cache_budget),
            "budget_bytes": cache_budget,
        },
        "interactive_shell_behavior": "unchanged",
        "automatic_cleanup_authorized": False,
        "does_not_establish": [
            "execution authority for the child command",
            "permission to delete worktree or cache payloads",
            "correctness of the child build",
            "safe reuse across changed repository, toolchain, lockfile or profile identities",
        ],
    }


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        _fsync_directory(path.parent)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _ensure_secure_directory(path: Path, home: Path) -> None:
    home = home.expanduser().resolve()
    try:
        relative = path.relative_to(home)
    except ValueError as exc:
        raise ManagedBuildError(f"managed path escapes HOME: {path}") from exc
    current = home
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ManagedBuildError(f"managed path component is not a real directory: {current}")


def create_pin(
    policy: dict[str, Any],
    *,
    repo: Path,
    tool: str,
    reason: str,
    ttl_hours: int,
    home: Path,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    if tool not in policy["tools"]:
        raise ManagedBuildError(f"unknown managed build tool: {tool}")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise ManagedBuildError("pin reason must contain 1-500 characters")
    if not isinstance(ttl_hours, int) or isinstance(ttl_hours, bool) or not 1 <= ttl_hours <= 168:
        raise ManagedBuildError("pin ttl_hours must be between 1 and 168")
    facts = repository_facts(repo)
    state_root = _expand_home(policy["state_root"], home)
    _ensure_secure_directory(state_root / "pins", home)
    now = int(time.time()) if now_epoch is None else now_epoch
    path = _pin_path(state_root, facts["repository_identity_sha256"], tool)
    pin = {
        "schema_version": 1,
        "kind": "heim_pc.managed_build_pin",
        "repository_identity_sha256": facts["repository_identity_sha256"],
        "tool": tool,
        "reason": reason.strip(),
        "created_at_unix": now,
        "expires_at_unix": now + ttl_hours * 3600,
        "automatic_cleanup_authorized": False,
    }
    _atomic_write_json(path, pin)
    return {"path": str(path), "sha256": _sha256_file(path), "pin": pin}


def _trim_receipts(directory: Path, max_receipts: int) -> None:
    receipts = sorted(
        (
            path
            for path in directory.glob("*.json")
            if path.is_file() and not path.is_symlink()
        ),
        key=lambda path: (path.stat().st_mtime_ns, path.name),
        reverse=True,
    )
    for path in receipts[max_receipts:]:
        path.unlink()


def execute_plan(
    policy: dict[str, Any],
    plan: dict[str, Any],
    command: Sequence[str],
    *,
    home: Path,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> int:
    if plan["guard"]["blocked"]:
        raise ManagedBuildError(
            "managed build blocked: worktree regenerable payload is at or above the hard budget"
        )
    root = Path(plan["repository_root"])
    cache_path = Path(plan["cache_path"])
    state_root = Path(plan["state_root"])
    _ensure_secure_directory(cache_path, home)
    _ensure_secure_directory(state_root / "receipts", home)
    for value in plan["environment"].values():
        _ensure_secure_directory(Path(value), home)

    environment = os.environ.copy()
    environment.update(plan["environment"])
    started_at = _utc_now()
    result = runner(
        list(command),
        cwd=root,
        env=environment,
        check=False,
    )
    finished_at = _utc_now()
    after = scan_worktree_payloads(
        root,
        policy["tools"][plan["tool"]]["worktree_payloads"],
    )
    receipt = {
        "schema_version": 1,
        "kind": "heim_pc.managed_build_receipt",
        "started_at": started_at,
        "finished_at": finished_at,
        "plan_sha256": _sha256_json(plan),
        "policy_sha256": plan["policy_sha256"],
        "repository_identity_sha256": plan["repository_identity_sha256"],
        "tool": plan["tool"],
        "profile": plan["profile"],
        "cache_key": plan["cache_key"],
        "cache_path": plan["cache_path"],
        "environment": plan["environment"],
        "command": plan["command"],
        "returncode": int(result.returncode),
        "worktree_allocated_bytes_before": plan["guard"]["worktree"]["allocated_bytes"],
        "worktree_allocated_bytes_after": after["allocated_bytes"],
        "automatic_cleanup_authorized": False,
    }
    receipt_name = (
        f"{int(time.time() * 1_000_000)}-"
        f"{plan['repository_identity_sha256'][:12]}-{plan['tool']}.json"
    )
    receipts = state_root / "receipts"
    receipt_path = receipts / receipt_name
    _atomic_write_json(receipt_path, receipt)
    _trim_receipts(receipts, int(policy["max_receipts"]))
    return int(result.returncode)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    plan = subparsers.add_parser("plan", help="emit a read-only managed-build plan")
    plan.add_argument("--repo", type=Path, required=True)
    plan.add_argument("--tool", choices=["cargo", "node", "python", "playwright"])
    plan.add_argument("--profile")
    plan.add_argument("command", nargs=argparse.REMAINDER)

    guard = subparsers.add_parser("guard", help="inspect worktree build payloads")
    guard.add_argument("--repo", type=Path, required=True)
    guard.add_argument("--tool", choices=["cargo", "node", "python", "playwright"])

    run = subparsers.add_parser("run", help="execute through the managed environment")
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--tool", choices=["cargo", "node", "python", "playwright"])
    run.add_argument("--profile")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER)

    pin = subparsers.add_parser("pin", help="create one explicit expiring hard-budget pin")
    pin.add_argument("--repo", type=Path, required=True)
    pin.add_argument("--tool", choices=["cargo", "node", "python", "playwright"], required=True)
    pin.add_argument("--reason", required=True)
    pin.add_argument("--ttl-hours", type=int, default=24)
    return parser


def _normalized_command(
    command: Sequence[str],
    *,
    policy: dict[str, Any],
    home: Path,
) -> list[str]:
    result = list(command)
    if result and result[0] == "--":
        result = result[1:]
    if not result:
        raise ManagedBuildError("command is required after '--'")
    if any(not isinstance(item, str) or "\x00" in item for item in result):
        raise ManagedBuildError("command contains an invalid argument")
    if "/" in result[0]:
        raise ManagedBuildError("managed executable must be named without a path")
    search_paths = [
        _expand_home(template, home) if template.startswith("${HOME}/") else Path(template)
        for template in policy["executable_search_paths"]
    ]
    search_path = os.pathsep.join(str(path) for path in search_paths)
    executable = shutil.which(result[0], path=search_path)
    if executable is None:
        raise ManagedBuildError(
            f"managed executable not found in policy search paths: {result[0]}"
        )
    result[0] = str(Path(executable).absolute())
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
        home = Path(os.environ.get("HOME", "~")).expanduser().resolve()
        if args.operation == "pin":
            result = create_pin(
                policy,
                repo=args.repo,
                tool=args.tool,
                reason=args.reason,
                ttl_hours=args.ttl_hours,
                home=home,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.operation == "guard":
            tools = [args.tool] if args.tool else sorted(policy["tools"])
            payloads = sorted(
                {
                    payload
                    for tool in tools
                    for payload in policy["tools"][tool]["worktree_payloads"]
                }
            )
            root = Path(repository_facts(args.repo)["root"])
            observation = scan_worktree_payloads(root, payloads)
            budget = _require_nonnegative_budget(
                policy["managed_worktree_budget_bytes"],
                "managed_worktree_budget_bytes",
            )
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "heim_pc.managed_build_guard",
                        "repository_root": str(root),
                        "tools": tools,
                        "observation": observation,
                        "budget_bytes": budget,
                        "status": _status(observation["allocated_bytes"], budget),
                        "automatic_cleanup_authorized": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        command = _normalized_command(args.command, policy=policy, home=home)
        plan = build_plan(
            policy,
            repo=args.repo,
            command=command,
            home=home,
            explicit_tool=args.tool,
            explicit_profile=args.profile,
        )
        if args.operation == "plan" or args.dry_run:
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 3 if plan["guard"]["blocked"] else 0
        return execute_plan(policy, plan, command, home=home)
    except (PolicyError, ManagedBuildError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "heim_pc.managed_build_error",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
