#!/usr/bin/env python3
"""Plan and execute bounded managed builds without changing interactive shell behavior."""

from __future__ import annotations

import argparse
import hashlib
import fcntl
import json
import os
import re
import shutil
import signal
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
NIX_STORE_MONITOR_INTERVAL_SECONDS = 0.5
NIX_STORE_FINAL_SCAN_TIMEOUT_SECONDS = 30.0
INTERNAL_NIX_STORE_SCAN_OPERATION = "--internal-nix-store-scan"
NIX_CANCEL_GRACE_SECONDS = 5
NIX_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
NIX_CONTAINER_LABEL_RE = re.compile(r"^heim-pc\.managed-nix=[0-9a-f]{64}-[0-9a-f]{12}$")
NIX_RECEIPT_SUFFIX = ".managed-build-receipt.json"


class PolicyError(ValueError):
    """Raised when the managed-build policy is malformed."""


class ManagedBuildError(RuntimeError):
    """Raised when a managed build cannot be planned or executed safely."""


class StoreScanTimeout(ManagedBuildError):
    """Raised when a managed Nix store scan exceeds its bounded observation window."""


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
    nix_store_budget = _require_nonnegative_budget(
        policy.get("nix_store_budget_bytes"),
        "nix_store_budget_bytes",
    )
    if not 0 < nix_store_budget["warning"] < nix_store_budget["hard"]:
        raise PolicyError(
            "nix_store_budget_bytes.warning must be a positive active stop threshold below hard"
        )
    nix_runtime_budget = _require_nonnegative_budget(
        policy.get("nix_runtime_budget_seconds"),
        "nix_runtime_budget_seconds",
    )
    if nix_runtime_budget["hard"] <= 0:
        raise PolicyError("nix_runtime_budget_seconds.hard must be positive")

    max_receipts = policy.get("max_receipts")
    if not isinstance(max_receipts, int) or isinstance(max_receipts, bool) or max_receipts < 1:
        raise PolicyError("max_receipts must be a positive integer")

    tools = policy.get("tools")
    if not isinstance(tools, dict) or set(tools) != {"cargo", "node", "python", "nix", "playwright"}:
        raise PolicyError("tools must define cargo, node, python, nix and playwright exactly")
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


def _trusted_nix_worker_python() -> str:
    executable = str(sys.executable)
    if not Path(executable).is_absolute() or os.path.normpath(executable) != executable:
        raise ManagedBuildError("current Python interpreter path is not canonical and absolute")
    return executable


def _is_nix_prepare_worker(command: Sequence[str]) -> bool:
    if not command or str(command[0]) != _trusted_nix_worker_python():
        return False
    args = [str(item) for item in command[1:]]
    return (
        len(args) == 8
        and Path(args[0]).name == "nixos_production_prepare.py"
        and args[1] == "--managed-worker"
        and args[2] == "--repo"
        and bool(args[3])
        and args[4] == "--output"
        and bool(args[5])
        and args[6] == "--source-authority"
        and args[7] in {"proof-only", "merged-main"}
    )


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
        if explicit_tool == "nix":
            if _is_nix_prepare_worker(command):
                return "nix"
            raise ManagedBuildError("tool nix is reserved for the canonical production prepare worker")
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
        if tool_name == "nix":
            continue
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
    elif tool == "nix":
        observations["python_runtime"] = sys.version
        observations["docker"] = _run_readonly(["docker", "--version"], cwd=repo)
        observations["nix_contract_files"] = _files_digest(
            repo, [
                "flake.lock",
                "nixos/production/contract-v1.json",
                "scripts/nixos_production_install.py",
                "scripts/nixos_production_prepare.py",
            ]
        )["sha256"]
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
    error_count = 0
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
        error_count += result.error_count
    return {"allocated_bytes": total, "error_count": error_count, "entries": entries}


def _validate_store_scan_observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManagedBuildError("managed Nix store scan returned an invalid observation")
    allocated = value.get("allocated_bytes")
    errors = value.get("error_count")
    if type(allocated) is not int or allocated < 0 or type(errors) is not int or errors < 0 or not isinstance(value.get("entries"), list):
        raise ManagedBuildError("managed Nix store scan returned an invalid observation")
    return value


def _bounded_store_scan(store_root: Path, *, timeout_seconds: float) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise StoreScanTimeout("managed Nix store scan deadline elapsed")
    root_text = str(store_root)
    if not store_root.is_absolute() or os.path.normpath(root_text) != root_text:
        raise ManagedBuildError("managed Nix store scan root must be canonical and absolute")
    try:
        result = subprocess.run(
            [_trusted_nix_worker_python(), str(Path(__file__).resolve()), INTERNAL_NIX_STORE_SCAN_OPERATION, root_text],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout_seconds, start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise StoreScanTimeout("managed Nix store scan exceeded its bounded observation window") from exc
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        raise ManagedBuildError("managed Nix store scan helper failed")
    try:
        observation = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManagedBuildError("managed Nix store scan helper returned invalid JSON") from exc
    return _validate_store_scan_observation(observation)


def _internal_nix_store_scan_main(argv: Sequence[str]) -> int:
    if len(argv) != 2 or argv[0] != INTERNAL_NIX_STORE_SCAN_OPERATION:
        return 2
    root = Path(argv[1]); root_text = str(root)
    if not root.is_absolute() or os.path.normpath(root_text) != root_text:
        return 2
    try:
        observation = _validate_store_scan_observation(scan_worktree_payloads(root, ["."]))
    except (ManagedBuildError, OSError):
        return 2
    print(json.dumps({"allocated_bytes": observation["allocated_bytes"], "error_count": observation["error_count"], "entries": []}, sort_keys=True, separators=(",", ":")))
    return 0


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


def _require_nix_prepare_worker_binding(
    command: Sequence[str], root: Path, profile: str
) -> None:
    if profile != "nixos-production-prepare":
        raise ManagedBuildError("managed Nix is restricted to the nixos-production-prepare profile")
    if not command or str(command[0]) != _trusted_nix_worker_python():
        raise ManagedBuildError("managed Nix worker must use the exact current Python interpreter")
    args = [str(item) for item in command[1:]]
    expected_script = root / "scripts" / "nixos_production_prepare.py"
    if (
        len(args) != 8
        or args[1] != "--managed-worker"
        or args[2] != "--repo"
        or args[4] != "--output"
        or args[6] != "--source-authority"
    ):
        raise ManagedBuildError("managed Nix worker requires the exact canonical managed-worker argv")
    script_value = args[0]
    if (
        not Path(script_value).is_absolute()
        or os.path.normpath(script_value) != script_value
        or Path(script_value) != expected_script
    ):
        raise ManagedBuildError("managed Nix worker must use the canonical repository prepare script")
    repo_value = args[3]
    if (
        not Path(repo_value).is_absolute()
        or os.path.normpath(repo_value) != repo_value
        or Path(repo_value) != root
    ):
        raise ManagedBuildError("managed Nix worker repository does not match the managed repository")
    output_value = args[5]
    if not Path(output_value).is_absolute() or os.path.normpath(output_value) != output_value:
        raise ManagedBuildError("managed Nix worker output must be an absolute canonical path")
    if args[7] not in {"proof-only", "merged-main"}:
        raise ManagedBuildError("managed Nix worker source authority is invalid")


def _build_identity_context(
    policy: dict[str, Any],
    *,
    repo: Path,
    command: Sequence[str],
    home: Path,
    explicit_tool: str | None = None,
    explicit_profile: str | None = None,
) -> dict[str, Any]:
    facts = repository_facts(repo)
    root = Path(facts["root"])
    tool = classify_tool(policy, command, explicit_tool=explicit_tool)
    profile = infer_profile(tool, command, explicit_profile)
    if tool == "nix":
        _require_nix_prepare_worker_binding(command, root, profile)
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
    environment = _build_environment(tool, cache_path, spec)
    return {
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
        "environment": environment,
        "command": {
            "executable": _command_basename(command),
            "argv_sha256": _sha256_json(list(command)),
        },
    }


def resolve_environment(
    policy: dict[str, Any],
    *,
    repo: Path,
    command: Sequence[str],
    home: Path,
    explicit_tool: str,
    explicit_profile: str,
) -> dict[str, Any]:
    context = _build_identity_context(
        policy,
        repo=repo,
        command=command,
        home=home,
        explicit_tool=explicit_tool,
        explicit_profile=explicit_profile,
    )
    return {
        "schema_version": 1,
        "kind": "heim_pc.managed_build_environment",
        "generated_at": _utc_now(),
        **context,
        "interactive_shell_behavior": "unchanged",
        "automatic_cleanup_authorized": False,
        "does_not_establish": [
            "execution authority for any child command",
            "permission to delete worktree or cache payloads",
            "build correctness",
            "that the caller will consume the returned environment",
        ],
    }


def prepare_environment(
    policy: dict[str, Any],
    *,
    repo: Path,
    command: Sequence[str],
    home: Path,
    explicit_tool: str,
    explicit_profile: str,
) -> dict[str, Any]:
    resolved = resolve_environment(
        policy,
        repo=repo,
        command=command,
        home=home,
        explicit_tool=explicit_tool,
        explicit_profile=explicit_profile,
    )
    cache_path = Path(resolved["cache_path"])
    _ensure_secure_directory(cache_path, home)
    prepared: list[str] = [str(cache_path)]
    for value in resolved["environment"].values():
        path = Path(value)
        _ensure_secure_directory(path, home)
        prepared.append(str(path))
    result = {
        **resolved,
        "kind": "heim_pc.managed_build_environment_prepared",
        "prepared_paths": sorted(set(prepared)),
        "prepared_paths_sha256": _sha256_json(sorted(set(prepared))),
        "does_not_establish": [
            "execution authority for any child command",
            "permission to delete worktree or cache payloads",
            "build correctness",
            "that the caller will consume the returned environment",
        ],
    }
    if resolved["tool"] == "cargo":
        state_root = Path(resolved["state_root"])
        bindings = state_root / "binding-receipts"
        lock_root = state_root / "cache-locks" / "cargo"
        _ensure_secure_directory(bindings, home)
        _ensure_secure_directory(lock_root, home)
        lifecycle_lock_path = lock_root / f"{resolved['cache_key']}.lock"
        result["lifecycle_lock_path"] = str(lifecycle_lock_path)
        result["prepared_paths"] = sorted(set([*result["prepared_paths"], str(lock_root)]))
        result["prepared_paths_sha256"] = _sha256_json(result["prepared_paths"])
        observed_at = _utc_now()
        binding = {
            "schema_version": 1,
            "kind": "heim_pc.managed_build_binding_receipt",
            "observed_at": observed_at,
            "repository_identity_sha256": resolved["repository_identity_sha256"],
            "tool": "cargo",
            "profile": resolved["profile"],
            "cache_key": resolved["cache_key"],
            "cache_path": resolved["cache_path"],
            "lifecycle_lock_path": str(lifecycle_lock_path),
            "environment_sha256": _sha256_json(resolved["environment"]),
            "automatic_cleanup_authorized": False,
        }
        receipt_name = (
            f"{int(time.time() * 1_000_000)}-"
            f"{resolved['repository_identity_sha256'][:12]}-cargo-"
            f"{resolved['cache_key'][:12]}.json"
        )
        binding_path = bindings / receipt_name
        _atomic_write_json(binding_path, binding)
        _trim_receipts(bindings, int(policy["max_receipts"]))
        result["binding_receipt"] = {
            "path": str(binding_path),
            "sha256": _sha256_file(binding_path),
        }
    return result


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
    context = _build_identity_context(
        policy,
        repo=repo,
        command=command,
        home=home,
        explicit_tool=explicit_tool,
        explicit_profile=explicit_profile,
    )
    root = Path(context["repository_root"])
    tool = str(context["tool"])
    spec = policy["tools"][tool]
    state_root = Path(context["state_root"])
    cache_path = Path(context["cache_path"])

    worktree = scan_worktree_payloads(root, spec["worktree_payloads"])
    worktree_budget = _require_nonnegative_budget(
        policy["managed_worktree_budget_bytes"],
        "managed_worktree_budget_bytes",
    )
    worktree_status = _status(worktree["allocated_bytes"], worktree_budget)
    pin = read_pin(
        state_root,
        str(context["repository_identity_sha256"]),
        tool,
        now_epoch=now_epoch,
    )
    blocked = worktree_status == "hard_limit" and pin is None

    cache_scan = (
        scan_worktree_payloads(cache_path, ["."])
        if cache_path.exists() and cache_path.is_dir() and not cache_path.is_symlink()
        else {"allocated_bytes": 0, "error_count": 0, "entries": []}
    )
    cache_budget = _require_nonnegative_budget(
        policy["per_identity_cache_budget_bytes"],
        "per_identity_cache_budget_bytes",
    )
    nix_guard: dict[str, Any] | None = None
    if tool == "nix":
        source_revision = _git(root, "rev-parse", "HEAD")
        if not re.fullmatch(r"[0-9a-f]{40}", source_revision):
            raise ManagedBuildError("managed Nix source revision must be exact 40-hex")
        store_root_raw = context["environment"].get("HEIM_PC_MANAGED_NIX_STORE_ROOT")
        if not isinstance(store_root_raw, str):
            raise ManagedBuildError("managed Nix store root is missing")
        store_root = Path(store_root_raw)
        store_scan = (
            scan_worktree_payloads(store_root, ["."])
            if store_root.exists() and store_root.is_dir() and not store_root.is_symlink()
            else {"allocated_bytes": 0, "error_count": 0, "entries": []}
        )
        store_budget = _require_nonnegative_budget(
            policy["nix_store_budget_bytes"], "nix_store_budget_bytes"
        )
        runtime_budget = _require_nonnegative_budget(
            policy["nix_runtime_budget_seconds"], "nix_runtime_budget_seconds"
        )
        store_status = _status(store_scan["allocated_bytes"], store_budget)
        if store_scan["error_count"] != 0 or store_scan["allocated_bytes"] >= int(store_budget["warning"]):
            blocked = True
        lock_path = state_root / "cache-locks" / "nix" / f"{context['cache_key']}.lock"
        fence_path = state_root / "cache-locks" / "nix" / f"{context['cache_key']}.active.json"
        nix_guard = {
            "source_revision": source_revision,
            "docker_volume": f"heim-pc-nixos-production-{source_revision[:12]}",
            "source_volume": f"heim-pc-nixos-source-{source_revision[:12]}",
            "store_root": str(store_root),
            "store_allocated_bytes": store_scan["allocated_bytes"],
            "store_scan_error_count": store_scan["error_count"],
            "store_scan_complete": store_scan["error_count"] == 0,
            "store_status": store_status,
            "store_budget_bytes": store_budget,
            "store_stop_threshold_bytes": store_budget["warning"],
            "runtime_budget_seconds": runtime_budget,
            "lifecycle_lock_path": str(lock_path),
            "lifecycle_fence_path": str(fence_path),
            "lock_mode": "flock-exclusive-nonblocking",
        }
    return {
        "schema_version": 1,
        "kind": "heim_pc.managed_build_plan",
        "generated_at": _utc_now(),
        **context,
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
        "nix_guard": nix_guard,
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


def _command_option_value(command: Sequence[str], option: str) -> str:
    values = [str(item) for item in command]
    if values.count(option) != 1:
        raise ManagedBuildError(f"managed command must contain exactly one {option}")
    index = values.index(option)
    if index + 1 >= len(values) or not values[index + 1]:
        raise ManagedBuildError(f"managed command {option} is missing its value")
    return values[index + 1]


def _nix_artifact_receipt(command: Sequence[str], guard: dict[str, Any]) -> dict[str, Any]:
    output = Path(_command_option_value(command, "--output"))
    try:
        info = output.lstat()
    except OSError as exc:
        raise ManagedBuildError("managed Nix worker did not publish its artifact") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ManagedBuildError("managed Nix artifact is not a single-link regular file")
    try:
        artifact = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManagedBuildError("managed Nix artifact is not valid JSON") from exc
    expected_revision = guard["source_revision"]
    expected_volume = guard["docker_volume"]
    system_closure = artifact.get("system_path")
    if (
        artifact.get("source_revision") != expected_revision
        or artifact.get("nix_volume") != expected_volume
        or not isinstance(system_closure, str)
        or re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-nixos-system-heim-pc-[A-Za-z0-9._+-]+", system_closure) is None
        or not isinstance(artifact.get("closure_manifest_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact["closure_manifest_sha256"]) is None
        or type(artifact.get("closure_path_count")) is not int
        or artifact["closure_path_count"] < 1
    ):
        raise ManagedBuildError("managed Nix artifact is not bound to the planned revision/volume/closure")
    return {
        "artifact_path": str(output),
        "artifact_file_sha256": _sha256_file(output),
        "artifact_json_sha256": _sha256_json(artifact),
        "source_revision": expected_revision,
        "docker_volume": expected_volume,
        "system_closure": system_closure,
        "closure_manifest_sha256": artifact["closure_manifest_sha256"],
        "closure_path_count": artifact["closure_path_count"],
    }


def _atomic_create_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        data = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ManagedBuildError("short write while creating managed Nix receipt")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _managed_nix_success_receipt_path(command: Sequence[str]) -> Path:
    return Path(_command_option_value(command, "--output") + NIX_RECEIPT_SUFFIX)


def _nix_container_ids(label: str) -> list[str]:
    if NIX_CONTAINER_LABEL_RE.fullmatch(label) is None:
        raise ManagedBuildError("managed Nix container label is invalid")
    try:
        result = subprocess.run(
            ["docker", "ps", "--no-trunc", "-aq", "--filter", f"label={label}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ManagedBuildError("cannot inspect managed Nix containers") from exc
    if result.returncode != 0:
        raise ManagedBuildError("cannot inspect managed Nix containers")
    try:
        values = [line.strip() for line in result.stdout.decode("ascii", "strict").splitlines() if line.strip()]
    except UnicodeDecodeError as exc:
        raise ManagedBuildError("managed Nix container inventory is not ASCII") from exc
    if any(NIX_CONTAINER_ID_RE.fullmatch(value) is None for value in values):
        raise ManagedBuildError("managed Nix container inventory returned an invalid id")
    return values


def _remove_exact_nix_containers(label: str) -> tuple[int, bool]:
    removed = 0
    for _attempt in range(3):
        ids = _nix_container_ids(label)
        if not ids:
            time.sleep(0.1)
            if not _nix_container_ids(label):
                return removed, True
            continue
        try:
            result = subprocess.run(
                ["docker", "rm", "--force", *ids],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                timeout=VERSION_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            return removed, False
        if result.returncode != 0:
            return removed, False
        removed += len(ids)
        time.sleep(0.1)
    return removed, not _nix_container_ids(label)


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group_exit(
    process: subprocess.Popen[Any], pgid: int, timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        # Reap the group leader as soon as it exits so a zombie leader does not
        # make an otherwise empty process group appear live indefinitely.
        process.poll()
        if not _process_group_exists(pgid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    pgid = process.pid
    leader_returncode = process.poll()
    if not _process_group_exists(pgid):
        # A just-exited leader can race the first probe; re-poll before treating
        # a missing group as inconsistent.
        if leader_returncode is None and process.poll() is None:
            raise ManagedBuildError(
                'managed Nix process group disappeared while its leader remained active'
            )
        return

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if _wait_for_process_group_exit(process, pgid, NIX_CANCEL_GRACE_SECONDS):
        return

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if not _wait_for_process_group_exit(process, pgid, NIX_CANCEL_GRACE_SECONDS):
        raise ManagedBuildError('managed Nix process group cleanup could not be verified')


def _run_nix_worker_guarded(
    command: Sequence[str], *, root: Path, environment: dict[str, str], guard: dict[str, Any]
) -> tuple[subprocess.CompletedProcess[Any], dict[str, Any]]:
    stop_threshold = int(guard["store_stop_threshold_bytes"])
    hard_limit = int(guard["store_budget_bytes"]["hard"])
    timeout_seconds = int(guard["runtime_budget_seconds"]["hard"])
    if not 0 < stop_threshold < hard_limit or timeout_seconds <= 0:
        raise ManagedBuildError("managed Nix runtime guard is invalid")
    plan_digest = hashlib.sha256(_canonical_json({
        "revision": guard["source_revision"], "volume": guard["docker_volume"],
        "store": guard["store_root"], "stop": stop_threshold, "hard": hard_limit,
    })).hexdigest()
    nonce = hashlib.sha256(f"{os.getpid()}:{time.time_ns()}".encode("ascii")).hexdigest()[:12]
    label = f"heim-pc.managed-nix={plan_digest}-{nonce}"
    if NIX_CONTAINER_LABEL_RE.fullmatch(label) is None:
        raise ManagedBuildError("managed Nix container label construction failed")
    child_env = dict(environment)
    child_env["HEIM_PC_MANAGED_NIX_CONTAINER_LABEL"] = label
    store_root = Path(str(guard["store_root"]))
    process = subprocess.Popen(
        list(command), cwd=root, env=child_env, start_new_session=True,
    )
    deadline = time.monotonic() + timeout_seconds
    trigger: str | None = None
    max_observed = 0
    store_scan_error_detected = False
    store_scan_timeout_detected = False
    final_store_scan: dict[str, Any] | None = None
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                trigger = "runtime-timeout"
                break
            try:
                scan = _bounded_store_scan(store_root, timeout_seconds=min(NIX_STORE_FINAL_SCAN_TIMEOUT_SECONDS, remaining))
            except StoreScanTimeout:
                if time.monotonic() >= deadline:
                    trigger = "runtime-timeout"
                else:
                    store_scan_error_detected = True
                    store_scan_timeout_detected = True
                    trigger = "store-scan-timeout"
                break
            if scan["error_count"] != 0:
                store_scan_error_detected = True
                trigger = "store-scan-error"
                break
            observed = scan["allocated_bytes"]
            max_observed = max(max_observed, observed)
            returncode = process.poll()
            if observed >= stop_threshold:
                trigger = "store-budget"
                break
            if returncode is not None:
                break
            if time.monotonic() >= deadline:
                trigger = "runtime-timeout"
                break
            time.sleep(NIX_STORE_MONITOR_INTERVAL_SECONDS)
        # Every terminal monitor path must prove the entire worker process group is gone.
        # A successful group leader can exit while a local descendant remains alive.
        _terminate_process_group(process)
        if process.poll() is None:
            process.wait(timeout=NIX_CANCEL_GRACE_SECONDS)
        orphan_ids = _nix_container_ids(label)
        orphan_detected = bool(orphan_ids)
        removed, cleanup_verified = _remove_exact_nix_containers(label)
        try:
            final_scan = _bounded_store_scan(store_root, timeout_seconds=NIX_STORE_FINAL_SCAN_TIMEOUT_SECONDS)
        except StoreScanTimeout:
            store_scan_error_detected = True
            store_scan_timeout_detected = True
            if trigger is None:
                trigger = "store-scan-timeout"
            final_bytes = max_observed
        else:
            final_store_scan = final_scan
            if final_scan["error_count"] != 0:
                store_scan_error_detected = True
                if trigger is None:
                    trigger = "store-scan-error"
            final_bytes = final_scan["allocated_bytes"]
            max_observed = max(max_observed, final_bytes)
        if not cleanup_verified:
            raise ManagedBuildError("managed Nix container cleanup could not be verified")
    except BaseException as exc:
        process_cleanup_error: BaseException | None = None
        try:
            _terminate_process_group(process)
        except BaseException as cleanup_exc:
            process_cleanup_error = cleanup_exc
        container_cleanup_error: BaseException | None = None
        containers_clean = False
        try:
            _removed, containers_clean = _remove_exact_nix_containers(label)
        except BaseException as cleanup_exc:
            container_cleanup_error = cleanup_exc
        if process_cleanup_error is not None or container_cleanup_error is not None or not containers_clean:
            raise ManagedBuildError(
                "managed Nix exceptional-path cleanup could not be verified; lifecycle fence retained"
            ) from exc
        raise
    if trigger == "runtime-timeout":
        effective = 124
    elif store_scan_error_detected:
        effective = 77
    elif trigger == "store-budget" or final_bytes >= stop_threshold:
        effective = 75
    elif orphan_detected:
        effective = 76
    else:
        effective = int(process.returncode or 0)
    return subprocess.CompletedProcess(list(command), effective), {
        "container_label_sha256": hashlib.sha256(label.encode("ascii")).hexdigest(),
        "container_orphan_detected": orphan_detected,
        "container_count_force_removed": removed,
        "container_cleanup_verified": cleanup_verified,
        "store_stop_threshold_bytes": stop_threshold,
        "store_hard_limit_bytes": hard_limit,
        "store_max_observed_bytes": max_observed,
        "store_budget_stop_triggered": trigger == "store-budget" or final_bytes >= stop_threshold,
        "store_scan_error_detected": store_scan_error_detected,
        "store_scan_timeout_detected": store_scan_timeout_detected,
        "store_final_scan": final_store_scan,
        "runtime_timeout_triggered": trigger == "runtime-timeout",
    }


def _remove_failed_nix_outputs(command: Sequence[str], guard: dict[str, Any]) -> None:
    output = Path(_command_option_value(command, "--output"))
    receipt = _managed_nix_success_receipt_path(command)
    for path in (receipt, output):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ManagedBuildError("refusing unsafe managed Nix failure-output cleanup")
        path.unlink()
        _fsync_directory(path.parent)
    for volume in (str(guard["source_volume"]), str(guard["docker_volume"])):
        inspected = subprocess.run(
            ["docker", "volume", "inspect", volume],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if inspected.returncode == 0:
            removed = subprocess.run(
                ["docker", "volume", "rm", "--force", volume],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            if removed.returncode != 0:
                raise ManagedBuildError("failed to remove rejected managed Nix volume")
        verified = subprocess.run(
            ["docker", "volume", "inspect", volume],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if verified.returncode == 0:
            raise ManagedBuildError("rejected managed Nix volume still exists")


def execute_plan(
    policy: dict[str, Any],
    plan: dict[str, Any],
    command: Sequence[str],
    *,
    home: Path,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> int:
    if plan["guard"]["blocked"]:
        raise ManagedBuildError("managed build blocked: a managed payload is at or above a hard budget")
    root = Path(plan["repository_root"])
    cache_path = Path(plan["cache_path"])
    state_root = Path(plan["state_root"])
    _ensure_secure_directory(cache_path, home)
    _ensure_secure_directory(state_root / "receipts", home)
    for value in plan["environment"].values():
        _ensure_secure_directory(Path(value), home)

    environment = os.environ.copy()
    environment.update(plan["environment"])
    if plan["tool"] == "nix" and plan.get("profile") == "nixos-production-prepare":
        # Establish the worker marker inside the managed executor, after the
        # path-only managed environment has been validated.
        environment["HEIM_PC_NIXOS_PRODUCTION_PREPARE_MANAGED"] = "1"
    nix_guard = plan.get("nix_guard")
    lock_fd: int | None = None
    fence_path: Path | None = None
    fence_created = False
    cleanup_verified = plan["tool"] != "nix"
    before_store = {"allocated_bytes": 0}
    telemetry: dict[str, Any] | None = None
    final_store_scan: dict[str, Any] | None = None
    if plan["tool"] == "nix":
        if not isinstance(nix_guard, dict):
            raise ManagedBuildError("managed Nix plan lacks its Nix guard")
        observed_head = _git(root, "rev-parse", "HEAD")
        if observed_head != nix_guard.get("source_revision") or _git(root, "status", "--porcelain"):
            raise ManagedBuildError("managed Nix source changed after planning")
        store_root = Path(str(nix_guard["store_root"]))
        _ensure_secure_directory(store_root, home)
        before_store = scan_worktree_payloads(store_root, ["."])
        pre_run_store_scan_error = before_store["error_count"] != 0
        stop_store = int(nix_guard["store_stop_threshold_bytes"])
        hard_store = int(nix_guard["store_budget_bytes"]["hard"])
        if not pre_run_store_scan_error and before_store["allocated_bytes"] >= stop_store:
            raise ManagedBuildError("managed Nix store is at or above its active stop threshold")
        if not 0 < stop_store < hard_store:
            raise ManagedBuildError("managed Nix store budget has no fail-closed headroom")
        output = Path(_command_option_value(command, "--output"))
        success_receipt = _managed_nix_success_receipt_path(command)
        if output.exists() or output.is_symlink() or success_receipt.exists() or success_receipt.is_symlink():
            raise ManagedBuildError("managed Nix output or success receipt already exists")
        for volume in (str(nix_guard["source_volume"]), str(nix_guard["docker_volume"])):
            if subprocess.run(["docker", "volume", "inspect", volume], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False).returncode == 0:
                raise ManagedBuildError("managed Nix volume already exists before execution")
        lock_path = Path(str(nix_guard["lifecycle_lock_path"]))
        fence_path = Path(str(nix_guard["lifecycle_fence_path"]))
        _ensure_secure_directory(lock_path.parent, home)
        if fence_path.exists() or fence_path.is_symlink():
            raise ManagedBuildError("managed Nix lifecycle fence requires reconciliation")
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(lock_fd)
            raise ManagedBuildError("managed Nix identity already has an active build lease") from exc
        _atomic_create_json(fence_path, {
            "schema_version": 1, "kind": "heim_pc.managed_nix_active_fence",
            "source_revision": nix_guard["source_revision"],
            "docker_volume": nix_guard["docker_volume"],
        })
        fence_created = True
        if pre_run_store_scan_error:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
                lock_fd = None
            raise ManagedBuildError(
                "managed Nix pre-run store scan is incomplete; lifecycle fence retained"
            )

    started_at = _utc_now()
    effective_returncode = 1
    receipt_path: Path | None = None
    try:
        if plan["tool"] == "nix":
            if runner is subprocess.run:
                result, telemetry = _run_nix_worker_guarded(
                    command, root=root, environment=environment, guard=nix_guard
                )
                observed_final_store_scan = telemetry.get("store_final_scan")
                if observed_final_store_scan is not None:
                    final_store_scan = _validate_store_scan_observation(
                        observed_final_store_scan
                    )
                elif not telemetry.get("store_scan_timeout_detected"):
                    raise ManagedBuildError(
                        "managed Nix final store scan evidence is missing"
                    )
            else:
                # Unit-test injection stays explicit; production always uses the guarded Popen path.
                result = runner(list(command), cwd=root, env=environment, check=False)
                after_injected_scan = scan_worktree_payloads(
                    Path(str(nix_guard["store_root"])), ["."]
                )
                final_store_scan = after_injected_scan
                after_injected = after_injected_scan["allocated_bytes"]
                telemetry = {
                    "container_label_sha256": "0" * 64,
                    "container_orphan_detected": False,
                    "container_count_force_removed": 0,
                    "container_cleanup_verified": True,
                    "store_stop_threshold_bytes": int(nix_guard["store_stop_threshold_bytes"]),
                    "store_hard_limit_bytes": int(nix_guard["store_budget_bytes"]["hard"]),
                    "store_max_observed_bytes": after_injected,
                    "store_budget_stop_triggered": after_injected >= int(nix_guard["store_stop_threshold_bytes"]),
                    "store_scan_error_detected": after_injected_scan["error_count"] != 0,
                    "store_scan_timeout_detected": False,
                    "store_final_scan": after_injected_scan,
                    "runtime_timeout_triggered": False,
                }
                if telemetry["store_scan_error_detected"]:
                    result = subprocess.CompletedProcess(list(command), 77)
                elif telemetry["store_budget_stop_triggered"] and result.returncode == 0:
                    result = subprocess.CompletedProcess(list(command), 75)
            cleanup_verified = bool(telemetry["container_cleanup_verified"])
        else:
            result = runner(list(command), cwd=root, env=environment, check=False)
        finished_at = _utc_now()
        after = scan_worktree_payloads(root, policy["tools"][plan["tool"]]["worktree_payloads"])
        effective_returncode = int(result.returncode)
        nix_receipt: dict[str, Any] | None = None
        if plan["tool"] == "nix":
            store_scan_error_detected = bool(
                (telemetry or {}).get("store_scan_error_detected")
            ) or (
                final_store_scan is not None
                and final_store_scan["error_count"] != 0
            )
            if bool((telemetry or {}).get("runtime_timeout_triggered")):
                effective_returncode = 124
            elif store_scan_error_detected:
                effective_returncode = 77
            elif (
                final_store_scan is not None
                and final_store_scan["allocated_bytes"]
                >= int(nix_guard["store_stop_threshold_bytes"])
                and effective_returncode == 0
            ):
                effective_returncode = 75
            nix_receipt = {
                "source_revision": nix_guard["source_revision"],
                "docker_volume": nix_guard["docker_volume"],
                "source_volume": nix_guard["source_volume"],
                "store_root": nix_guard["store_root"],
                "store_allocated_bytes_before": before_store["allocated_bytes"],
                "store_allocated_bytes_after": (
                    final_store_scan["allocated_bytes"]
                    if final_store_scan is not None
                    else None
                ),
                "store_scan_error_count_after": (
                    final_store_scan["error_count"]
                    if final_store_scan is not None
                    else None
                ),
                "store_scan_error_detected": store_scan_error_detected,
                "store_budget_bytes": nix_guard["store_budget_bytes"],
                "runtime_budget_seconds": nix_guard["runtime_budget_seconds"],
                "lifecycle_lock_path": nix_guard["lifecycle_lock_path"],
                "lock_mode": nix_guard["lock_mode"],
                **(telemetry or {}),
            }
            if effective_returncode == 0:
                nix_receipt.update(_nix_artifact_receipt(command, nix_guard))
            else:
                cleanup_verified = False
                _remove_failed_nix_outputs(command, nix_guard)
                cleanup_verified = True
        receipt = {
            "schema_version": 1, "kind": "heim_pc.managed_build_receipt",
            "started_at": started_at, "finished_at": finished_at,
            "plan_sha256": _sha256_json(plan), "policy_sha256": plan["policy_sha256"],
            "repository_identity_sha256": plan["repository_identity_sha256"],
            "tool": plan["tool"], "profile": plan["profile"], "cache_key": plan["cache_key"],
            "cache_path": plan["cache_path"], "environment": plan["environment"],
            "command": plan["command"], "returncode": effective_returncode,
            "worktree_allocated_bytes_before": plan["guard"]["worktree"]["allocated_bytes"],
            "worktree_allocated_bytes_after": after["allocated_bytes"],
            "nix_build": nix_receipt, "automatic_cleanup_authorized": False,
        }
        receipt_name = f"{int(time.time() * 1_000_000)}-{plan['repository_identity_sha256'][:12]}-{plan['tool']}.json"
        receipt_path = state_root / "receipts" / receipt_name
        _atomic_write_json(receipt_path, receipt)
        _trim_receipts(state_root / "receipts", int(policy["max_receipts"]))
        if plan["tool"] == "nix" and effective_returncode == 0:
            if not cleanup_verified:
                raise ManagedBuildError("managed Nix success requires verified container cleanup")
            if fence_created and fence_path is not None:
                fence_path.unlink()
                _fsync_directory(fence_path.parent)
                fence_created = False
            artifact_path = Path(_command_option_value(command, "--output"))
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            success = {
                "schema_version": 1,
                "kind": "heim_pc.nixos_managed_build_success_receipt",
                "status": "success",
                "returncode": 0,
                "tool": "nix",
                "profile": plan["profile"],
                "managed_plan_sha256": _sha256_json(plan),
                "managed_policy_sha256": plan["policy_sha256"],
                "managed_receipt_sha256": _sha256_file(receipt_path),
                "artifact_file_sha256": _sha256_file(artifact_path),
                "artifact_json_sha256": _sha256_json(artifact),
                "source_revision": nix_guard["source_revision"],
                "docker_volume": nix_guard["docker_volume"],
                "store_root": nix_guard["store_root"],
                "system_closure": nix_receipt["system_closure"],
                "closure_manifest_sha256": nix_receipt["closure_manifest_sha256"],
                "closure_path_count": nix_receipt["closure_path_count"],
                "store_stop_threshold_bytes": telemetry["store_stop_threshold_bytes"],
                "store_hard_limit_bytes": telemetry["store_hard_limit_bytes"],
                "store_max_observed_bytes": telemetry["store_max_observed_bytes"],
                "store_budget_stop_triggered": False,
                "store_scan_error_detected": False,
                "runtime_timeout_triggered": False,
                "container_cleanup_verified": cleanup_verified,
                "lifecycle_fence_cleared": True,
            }
            _atomic_create_json(_managed_nix_success_receipt_path(command), success)
        elif plan["tool"] == "nix":
            if not cleanup_verified:
                raise ManagedBuildError("managed Nix failure cleanup was not verified")
            if not bool((telemetry or {}).get("store_scan_error_detected")) and not (
                isinstance(nix_receipt, dict) and nix_receipt.get("store_scan_error_detected") is True
            ):
                if fence_created and fence_path is not None:
                    fence_path.unlink()
                    _fsync_directory(fence_path.parent)
                    fence_created = False
        return effective_returncode
    finally:
        # Any exceptional Nix path deliberately leaves the durable fence behind.
        # The flock is process-scoped; the retained fence blocks reuse until recovery.
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    plan = subparsers.add_parser("plan", help="emit a read-only managed-build plan")
    plan.add_argument("--repo", type=Path, required=True)
    plan.add_argument("--tool", choices=["cargo", "node", "python", "nix", "playwright"])
    plan.add_argument("--profile")
    plan.add_argument("command", nargs=argparse.REMAINDER)

    resolve = subparsers.add_parser(
        "resolve-environment",
        help="resolve one identity-bound managed environment without executing or scanning payloads",
    )
    resolve.add_argument("--repo", type=Path, required=True)
    resolve.add_argument("--tool", choices=["cargo", "node", "python", "nix", "playwright"], required=True)
    resolve.add_argument("--profile", required=True)
    resolve.add_argument("--executable", required=True)

    prepare = subparsers.add_parser(
        "prepare-environment",
        help="prepare one identity-bound managed environment without executing a build",
    )
    prepare.add_argument("--repo", type=Path, required=True)
    prepare.add_argument("--tool", choices=["cargo", "node", "python", "nix", "playwright"], required=True)
    prepare.add_argument("--profile", required=True)
    prepare.add_argument("--executable", required=True)

    guard = subparsers.add_parser("guard", help="inspect worktree build payloads")
    guard.add_argument("--repo", type=Path, required=True)
    guard.add_argument("--tool", choices=["cargo", "node", "python", "nix", "playwright"])

    run = subparsers.add_parser("run", help="execute through the managed environment")
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--tool", choices=["cargo", "node", "python", "nix", "playwright"])
    run.add_argument("--profile")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER)

    pin = subparsers.add_parser("pin", help="create one explicit expiring hard-budget pin")
    pin.add_argument("--repo", type=Path, required=True)
    pin.add_argument("--tool", choices=["cargo", "node", "python", "nix", "playwright"], required=True)
    pin.add_argument("--reason", required=True)
    pin.add_argument("--ttl-hours", type=int, default=24)
    return parser


def _normalized_command(
    command: Sequence[str],
    *,
    policy: dict[str, Any],
    home: Path,
    explicit_tool: str | None = None,
) -> list[str]:
    result = list(command)
    if result and result[0] == "--":
        result = result[1:]
    if not result:
        raise ManagedBuildError("command is required after '--'")
    if any(not isinstance(item, str) or "\x00" in item for item in result):
        raise ManagedBuildError("command contains an invalid argument")
    if explicit_tool == "nix":
        if result[0] != _trusted_nix_worker_python():
            raise ManagedBuildError("managed Nix worker must request the exact current Python interpreter")
        return result
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
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == INTERNAL_NIX_STORE_SCAN_OPERATION:
        return _internal_nix_store_scan_main(raw_argv)
    args = _parser().parse_args(raw_argv)
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
        if args.operation in {"resolve-environment", "prepare-environment"}:
            command = _normalized_command([args.executable], policy=policy, home=home)
            operation = (
                resolve_environment
                if args.operation == "resolve-environment"
                else prepare_environment
            )
            result = operation(
                policy,
                repo=args.repo,
                command=command,
                home=home,
                explicit_tool=args.tool,
                explicit_profile=args.profile,
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

        command = _normalized_command(
            args.command, policy=policy, home=home, explicit_tool=args.tool
        )
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
