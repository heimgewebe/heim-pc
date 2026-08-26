#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import tempfile
import time
from typing import Any, Iterable

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "package-update-policy.v1.json"
PLAN_KIND = "heim_pc.staged_package_update_plan"
RECEIPT_KIND = "heim_pc.staged_package_update_receipt"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
APT_INST_RE = re.compile(r"^Inst (\S+)(?: \[[^]]*\])? \((\S+).* \[([^]]+)\]\)(?: .*)?$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9.+-]")
APT_SOURCE_PATTERNS = (
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d/*.list",
    "/etc/apt/sources.list.d/*.sources",
    "/etc/apt/trusted.gpg",
    "/etc/apt/trusted.gpg.d/*.gpg",
    "/usr/share/keyrings/*.gpg",
)


class PolicyError(ValueError):
    pass


class PlanError(RuntimeError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(argv: list[str], *, cwd: Path | None = None, check: bool = True) -> dict[str, Any]:
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive"})
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    result = {
        "argv": argv,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if check and completed.returncode != 0:
        raise PlanError(
            f"command failed rc={completed.returncode}: {argv[0]} {argv[-1]}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return result


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    if path.is_symlink():
        raise PlanError(f"JSON path may not be a symlink: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
        raise PlanError(f"JSON path is not a bounded regular file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PlanError("JSON document must be an object")
    return value


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    value = _read_json(path)
    if value.get("schema_version") != 1 or value.get("kind") != "heim_pc.staged_package_update_policy":
        raise PolicyError("package update policy schema or kind mismatch")
    if value.get("automatic_apply") is not False:
        raise PolicyError("automatic_apply must remain false")
    staging = value.get("staging")
    apt = value.get("apt")
    snap = value.get("snap")
    safety = value.get("safety")
    if not all(isinstance(item, dict) for item in (staging, apt, snap, safety)):
        raise PolicyError("staging, apt, snap and safety must be objects")
    if snap.get("allow_dangerous") is not False:
        raise PolicyError("snap.allow_dangerous must remain false")
    required_true = (
        "require_exact_plan_hash",
        "require_fresh_apt_indexes",
        "require_apt_signature_verification",
        "require_dpkg_status_precondition",
        "require_source_config_precondition",
        "require_root_owned_copy_before_apply",
        "require_root_copy_hash_readback",
        "require_broker_read_only_handoff",
        "require_dpkg_recursive_apply",
        "require_no_remove_selection",
        "require_signed_snap_assertion",
        "privileged_broker_network_must_remain_blocked",
    )
    for key in required_true:
        if safety.get(key) is not True:
            raise PolicyError(f"safety.{key} must be true")
    for parent, key in ((staging, "max_plan_age_seconds"), (apt, "max_packages"), (apt, "max_download_bytes"), (snap, "max_snaps")):
        if not isinstance(parent.get(key), int) or parent[key] <= 0:
            raise PolicyError(f"{key} must be a positive integer")
    if apt.get("selection_mode") != "upgrade-with-new-pkgs-no-remove":
        raise PolicyError("unsupported apt selection mode")
    if apt.get("apply_mode") != "dpkg-recursive-root-stage":
        raise PolicyError("unsupported apt apply mode")
    return value


def _expand_runtime_root(policy: dict[str, Any], uid: int) -> Path:
    staging = policy["staging"]
    template = staging["runtime_root"]
    bind_value = staging.get("broker_bind_root")
    if not isinstance(template, str) or not template:
        raise PolicyError("staging.runtime_root must be a non-empty string")
    if not isinstance(bind_value, str) or not bind_value:
        raise PolicyError("staging.broker_bind_root must be a non-empty string")
    path = Path(template.replace("${UID}", str(uid)))
    bind_root = Path(bind_value)
    if not path.is_absolute() or not bind_root.is_absolute():
        raise PolicyError("staging roots must be absolute")
    try:
        relative = path.relative_to(bind_root)
    except ValueError as exc:
        raise PolicyError("runtime staging root must remain below broker_bind_root") from exc
    if not relative.parts:
        raise PolicyError("runtime staging root may not equal broker_bind_root")
    return path


def _effective_broker_read_only_bindings() -> list[Path]:
    result = _run(["/usr/bin/systemctl", "cat", "grabowski-privileged-broker@.service"])
    bindings: list[Path] = []
    for raw_line in result["stdout"].splitlines():
        line = raw_line.strip()
        if not line.startswith("BindReadOnlyPaths="):
            continue
        value = line.split("=", 1)[1].strip()
        if not value:
            bindings = []
            continue
        for token in shlex.split(value):
            spec = token.lstrip("-")
            source = spec.split(":", 1)[0]
            if source:
                bindings.append(Path(source))
    return bindings


def _require_broker_handoff_binding(policy: dict[str, Any]) -> None:
    bind_root = Path(policy["staging"]["broker_bind_root"])
    bindings = _effective_broker_read_only_bindings()
    for candidate in bindings:
        if candidate == bind_root:
            return
    raise PlanError(f"privileged broker does not bind handoff root read-only: {bind_root}")


def _root_stage_root(policy: dict[str, Any]) -> Path:
    value = policy["staging"]["root_root"]
    path = Path(value)
    if not path.is_absolute() or path == Path("/"):
        raise PolicyError("staging.root_root must be an absolute non-root path")
    return path


def _ensure_private_dir(path: Path, uid: int) -> None:
    if path.exists() and path.is_symlink():
        raise PlanError(f"staging path may not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
        raise PlanError(f"staging path is not controlled by uid {uid}: {path}")
    os.chmod(path, 0o700)


def _regular_owned_file(path: Path, uid: int) -> os.stat_result:
    if path.is_symlink():
        raise PlanError(f"artifact may not be a symlink: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1:
        raise PlanError(f"artifact is not a single-link regular file owned by uid {uid}: {path}")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise PlanError(f"artifact is group/world writable: {path}")
    return info


def _expand_patterns(patterns: Iterable[str]) -> list[Path]:
    paths: set[Path] = set()
    for pattern in patterns:
        candidate = Path(pattern)
        if any(char in pattern for char in "*?["):
            parent = candidate.parent
            if not parent.exists():
                continue
            for item in parent.glob(candidate.name):
                paths.add(item)
        elif candidate.exists():
            paths.add(candidate)
    return sorted(paths, key=str)


def _source_config_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in _expand_patterns(APT_SOURCE_PATTERNS):
        if path.is_symlink():
            target = path.resolve(strict=True)
            if not target.is_file():
                raise PlanError(f"APT source/key symlink does not resolve to regular file: {path}")
            path = target
        if not path.is_file():
            continue
        info = path.stat()
        records.append({"path": str(path), "size": info.st_size, "sha256": _sha256_file(path)})
    return records


def _dpkg_status_sha256() -> str:
    return _sha256_file(Path("/var/lib/dpkg/status"))


def _apt_options(stage: Path) -> list[str]:
    apt = stage / "apt"
    return [
        "-o", f"Dir::State::lists={apt / 'lists'}",
        "-o", f"Dir::Cache::archives={apt / 'archives'}",
        "-o", f"Dir::Cache::pkgcache={apt / 'pkgcache.bin'}",
        "-o", f"Dir::Cache::srcpkgcache={apt / 'srcpkgcache.bin'}",
        "-o", "Debug::NoLocking=1",
    ]


def _prepare_apt_dirs(stage: Path, uid: int) -> None:
    for path in (
        stage / "apt",
        stage / "apt" / "lists",
        stage / "apt" / "lists" / "partial",
        stage / "apt" / "archives",
        stage / "apt" / "archives" / "partial",
        stage / "apt" / "debs",
    ):
        _ensure_private_dir(path, uid)


def parse_apt_simulation(text: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    for raw_line in text.splitlines():
        match = APT_INST_RE.match(raw_line.strip())
        if match is None:
            continue
        name, version, arch = match.groups()
        packages.append({"name": name, "version": version, "arch": arch})
    return packages


def _deb_field(path: Path, field: str) -> str:
    result = _run(["/usr/bin/dpkg-deb", "-f", str(path), field])
    return result["stdout"].strip()


def _is_sensitive_package(name: str, policy: dict[str, Any]) -> bool:
    lowered = name.split(":", 1)[0].lower()
    prefixes = policy["apt"].get("sensitive_prefixes", [])
    if not isinstance(prefixes, list) or not all(isinstance(item, str) for item in prefixes):
        raise PolicyError("apt.sensitive_prefixes must be a string list")
    return any(lowered.startswith(prefix.lower()) for prefix in prefixes)


def _stage_apt(stage: Path, policy: dict[str, Any], uid: int) -> dict[str, Any]:
    if policy["apt"].get("enabled") is not True:
        return {"enabled": False, "packages": []}
    _prepare_apt_dirs(stage, uid)
    options = _apt_options(stage)
    update = _run(["/usr/bin/apt-get", *options, "-o", "APT::Update::Error-Mode=any", "update"])
    if re.search(r"^(W:|E:).*signature|NO_PUBKEY|not signed", update["stderr"], flags=re.I | re.M):
        raise PlanError("APT update reported a repository signature problem")
    simulation = _run([
        "/usr/bin/apt-get", "-s", *options, "--no-remove", "upgrade", "--with-new-pkgs"
    ])
    candidates = parse_apt_simulation(simulation["stdout"])
    if len(candidates) > policy["apt"]["max_packages"]:
        raise PlanError(f"APT candidate count {len(candidates)} exceeds policy limit")
    if not candidates:
        return {
            "enabled": True,
            "update_stdout_sha256": _sha256_bytes(update["stdout"].encode()),
            "update_stderr_sha256": _sha256_bytes(update["stderr"].encode()),
            "simulation_sha256": _sha256_bytes(simulation["stdout"].encode()),
            "packages": [],
            "download_bytes": 0,
        }
    deb_dir = stage / "apt" / "debs"
    specs = [f"{item['name']}={item['version']}" for item in candidates]
    _run(["/usr/bin/apt-get", *options, "download", *specs], cwd=deb_dir)
    downloaded = sorted(deb_dir.glob("*.deb"), key=str)
    expected: dict[tuple[str, str, str], dict[str, str]] = {}
    for candidate in candidates:
        base = candidate["name"].split(":", 1)[0]
        key = (base, candidate["version"], candidate["arch"])
        if key in expected:
            raise PlanError(f"duplicate APT candidate identity: {key}")
        expected[key] = candidate
    artifacts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    total_bytes = 0
    for index, path in enumerate(downloaded):
        _regular_owned_file(path, uid)
        package = _deb_field(path, "Package")
        version = _deb_field(path, "Version")
        arch = _deb_field(path, "Architecture")
        key = (package, version, arch)
        candidate = expected.get(key)
        if candidate is None:
            raise PlanError(f"downloaded DEB is not in exact simulated candidate set: {key}")
        if key in seen:
            raise PlanError(f"multiple DEBs satisfy candidate identity: {key}")
        seen.add(key)
        digest = _sha256_file(path)
        safe_package = SAFE_NAME_RE.sub("_", candidate["name"])
        root_name = f"{index:03d}-{safe_package}-{arch}-{digest[:16]}.deb"
        renamed = deb_dir / root_name
        path.replace(renamed)
        os.chmod(renamed, 0o600)
        info = _regular_owned_file(renamed, uid)
        total_bytes += info.st_size
        artifacts.append({
            **candidate,
            "package": package,
            "relative_path": str(renamed.relative_to(stage)),
            "sha256": digest,
            "size": info.st_size,
            "sensitive": _is_sensitive_package(candidate["name"], policy),
        })
    missing = sorted(set(expected) - seen)
    if missing:
        raise PlanError(f"missing exact DEB artifacts for {len(missing)} candidates")
    if total_bytes > policy["apt"]["max_download_bytes"]:
        raise PlanError(f"APT download bytes {total_bytes} exceed policy limit")
    return {
        "enabled": True,
        "update_stdout_sha256": _sha256_bytes(update["stdout"].encode()),
        "update_stderr_sha256": _sha256_bytes(update["stderr"].encode()),
        "simulation_sha256": _sha256_bytes(simulation["stdout"].encode()),
        "packages": artifacts,
        "download_bytes": total_bytes,
    }


def parse_snap_refresh_list(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("name ") or "up to date" in line.lower():
            continue
        parts = line.split()
        if len(parts) < 3 or not parts[2].isdigit():
            continue
        rows.append({"name": parts[0], "version": parts[1], "revision": parts[2]})
    return rows


def _snap_installed_revision(name: str) -> str:
    result = _run(["/usr/bin/snap", "list", name])
    lines = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    if len(lines) < 2:
        raise PlanError(f"cannot read installed snap revision for {name}")
    parts = lines[1].split()
    if len(parts) < 3 or not parts[2].isdigit():
        raise PlanError(f"unexpected snap list output for {name}")
    return parts[2]


def _stage_snap(stage: Path, policy: dict[str, Any], uid: int) -> dict[str, Any]:
    if policy["snap"].get("enabled") is not True:
        return {"enabled": False, "packages": []}
    snap_dir = stage / "snap"
    _ensure_private_dir(snap_dir, uid)
    listed = _run(["/usr/bin/snap", "refresh", "--list"], check=False)
    if listed["returncode"] not in (0,):
        raise PlanError(f"snap refresh --list failed: {listed['stderr'].strip()}")
    pending = parse_snap_refresh_list(listed["stdout"])
    if len(pending) > policy["snap"]["max_snaps"]:
        raise PlanError(f"snap candidate count {len(pending)} exceeds policy limit")
    artifacts: list[dict[str, Any]] = []
    for item in pending:
        baseline_revision = _snap_installed_revision(item["name"])
        basename = f"{SAFE_NAME_RE.sub('_', item['name'])}_{item['revision']}"
        download = _run([
            "/usr/bin/snap", "download", item["name"],
            "--revision", item["revision"],
            "--basename", basename,
            "--target-directory", str(snap_dir),
        ])
        snap_path = snap_dir / f"{basename}.snap"
        assertion_path = snap_dir / f"{basename}.assert"
        snap_info = _regular_owned_file(snap_path, uid)
        assertion_info = _regular_owned_file(assertion_path, uid)
        if assertion_info.st_size == 0:
            raise PlanError(f"snap assertion is empty for {item['name']}")
        os.chmod(snap_path, 0o600)
        os.chmod(assertion_path, 0o600)
        artifacts.append({
            **item,
            "baseline_revision": baseline_revision,
            "snap_relative_path": str(snap_path.relative_to(stage)),
            "snap_sha256": _sha256_file(snap_path),
            "snap_size": snap_info.st_size,
            "assert_relative_path": str(assertion_path.relative_to(stage)),
            "assert_sha256": _sha256_file(assertion_path),
            "assert_size": assertion_info.st_size,
            "download_stdout_sha256": _sha256_bytes(download["stdout"].encode()),
        })
    return {
        "enabled": True,
        "list_sha256": _sha256_bytes(listed["stdout"].encode()),
        "packages": artifacts,
    }


def _apt_apply_systemd_argv(plan_id: str, root_debs: Path) -> list[str]:
    unit_name = f"heim-pc-package-update-{SAFE_NAME_RE.sub('_', plan_id)}.service"
    return [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--collect",
        "--pipe",
        f"--unit={unit_name}",
        "--property=Type=exec",
        "--property=NoNewPrivileges=no",
        "--property=PrivateTmp=yes",
        "--property=MemoryDenyWriteExecute=no",
        "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "--property=IPAddressDeny=any",
        "--",
        "/usr/bin/dpkg",
        "--force-confold",
        "--install",
        "--recursive",
        str(root_debs),
    ]


def _root_commands(plan_id: str, stage: Path, policy: dict[str, Any], apt: dict[str, Any], snap: dict[str, Any]) -> dict[str, Any]:
    root_stage = _root_stage_root(policy) / plan_id
    root_debs = root_stage / "debs"
    root_snaps = root_stage / "snaps"
    prepare = ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", str(root_debs), str(root_snaps)]
    apt_sources = [str(stage / item["relative_path"]) for item in apt.get("packages", [])]
    apt_destinations = [str(root_debs / Path(item["relative_path"]).name) for item in apt.get("packages", [])]
    snap_sources: list[str] = []
    snap_destinations: list[str] = []
    for item in snap.get("packages", []):
        for key in ("assert_relative_path", "snap_relative_path"):
            source = stage / item[key]
            snap_sources.append(str(source))
            snap_destinations.append(str(root_snaps / source.name))
    copy_apt = ["/usr/bin/install", "-o", "root", "-g", "root", "-m", "0600", *apt_sources, str(root_debs)] if apt_sources else None
    copy_snap = ["/usr/bin/install", "-o", "root", "-g", "root", "-m", "0600", *snap_sources, str(root_snaps)] if snap_sources else None
    hash_apt = ["/usr/bin/sha256sum", *apt_destinations] if apt_destinations else None
    hash_snap = ["/usr/bin/sha256sum", *snap_destinations] if snap_destinations else None
    apt_apply_preflight = None
    apt_apply = None
    if apt_destinations:
        apt_apply_preflight = [
            "/usr/bin/dpkg", "--simulate", "--force-confold",
            "--install", "--recursive", str(root_debs),
        ]
        apt_apply = _apt_apply_systemd_argv(plan_id, root_debs)
    snap_apply: list[list[str]] = []
    for item in snap.get("packages", []):
        assertion = str(root_snaps / Path(item["assert_relative_path"]).name)
        snap_file = str(root_snaps / Path(item["snap_relative_path"]).name)
        snap_apply.append(["/usr/bin/snap", "ack", assertion])
        snap_apply.append(["/usr/bin/snap", "install", snap_file])
    return {
        "root_stage": str(root_stage),
        "prepare_argv": prepare,
        "copy_apt_argv": copy_apt,
        "copy_snap_argv": copy_snap,
        "hash_apt_argv": hash_apt,
        "hash_snap_argv": hash_snap,
        "apt_apply_preflight_argv": apt_apply_preflight,
        "apt_apply_argv": apt_apply,
        "snap_apply_argvs": snap_apply,
        "cleanup_argv": ["/usr/bin/rm", "-rf", "--", str(root_stage)],
    }


def _artifact_expectations(plan: dict[str, Any]) -> dict[str, str]:
    root_stage = Path(plan["root_commands"]["root_stage"])
    expected: dict[str, str] = {}
    for item in plan["apt"].get("packages", []):
        expected[str(root_stage / "debs" / Path(item["relative_path"]).name)] = item["sha256"]
    for item in plan["snap"].get("packages", []):
        expected[str(root_stage / "snaps" / Path(item["assert_relative_path"]).name)] = item["assert_sha256"]
        expected[str(root_stage / "snaps" / Path(item["snap_relative_path"]).name)] = item["snap_sha256"]
    return expected


def _plan_digest(plan: dict[str, Any]) -> str:
    unsigned = dict(plan)
    unsigned.pop("plan_sha256", None)
    return _sha256_json(unsigned)


def create_plan(policy_path: Path) -> dict[str, Any]:
    if os.geteuid() == 0:
        raise PlanError("plan generation must run unprivileged")
    policy = load_policy(policy_path)
    uid = os.geteuid()
    runtime_root = _expand_runtime_root(policy, uid)
    _require_broker_handoff_binding(policy)
    _ensure_private_dir(runtime_root, uid)
    plan_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(6)}"
    stage = runtime_root / plan_id
    _ensure_private_dir(stage, uid)
    baseline = {
        "uid": uid,
        "dpkg_status_sha256": _dpkg_status_sha256(),
        "apt_source_config": _source_config_records(),
        "created_at_unix": int(time.time()),
    }
    apt = _stage_apt(stage, policy, uid)
    snap = _stage_snap(stage, policy, uid)
    commands = _root_commands(plan_id, stage, policy, apt, snap)
    plan: dict[str, Any] = {
        "schema_version": 1,
        "kind": PLAN_KIND,
        "plan_id": plan_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_at_unix": int(time.time()),
        "policy_path": str(policy_path.resolve()),
        "policy_sha256": _sha256_file(policy_path),
        "stage_path": str(stage),
        "baseline": baseline,
        "apt": apt,
        "snap": snap,
        "root_commands": commands,
        "root_artifact_sha256": {},
        "safety": {
            "automatic_apply": False,
            "root_executes_user_code": False,
            "apt_selection_no_remove": True,
            "apt_apply_network_capable": False,
            "apt_apply_engine": "dpkg-recursive-root-stage",
            "apt_apply_execution": "network-denied-systemd-system-task",
            "snap_dangerous": False,
            "privileged_network_required": False,
        },
        "does_not_establish": [
            "privileged apply authority",
            "root-copy integrity before root hash readback",
            "absence of package-manager activity after plan creation",
            "reboot safety",
        ],
    }
    plan["root_artifact_sha256"] = _artifact_expectations(plan)
    plan["plan_sha256"] = _plan_digest(plan)
    plan_path = stage / "plan.json"
    _atomic_json(plan_path, plan)
    return {
        "plan_path": str(plan_path),
        "plan_sha256": plan["plan_sha256"],
        "apt_packages": len(apt.get("packages", [])),
        "apt_download_bytes": apt.get("download_bytes", 0),
        "sensitive_apt_packages": [item["name"] for item in apt.get("packages", []) if item.get("sensitive")],
        "snap_packages": len(snap.get("packages", [])),
        "snap_names": [item["name"] for item in snap.get("packages", [])],
        "root_stage": commands["root_stage"],
    }


def _validate_confirmation(plan: dict[str, Any], confirmation: str) -> None:
    digest = plan.get("plan_sha256")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise PlanError("plan_sha256 is invalid")
    if _plan_digest(plan) != digest:
        raise PlanError("plan content hash mismatch")
    if confirmation != digest:
        raise PlanError("confirmation does not match exact plan hash")


def _validate_source_config(expected: list[dict[str, Any]]) -> None:
    if _source_config_records() != expected:
        raise PlanError("APT source/key configuration changed after planning")


def _validate_stage_artifacts(plan: dict[str, Any], uid: int, policy: dict[str, Any]) -> None:
    stage = Path(plan["stage_path"])
    runtime_root = _expand_runtime_root(policy, uid)
    try:
        relative = stage.relative_to(runtime_root)
    except ValueError as exc:
        raise PlanError("plan stage is outside the broker-visible handoff root") from exc
    if not relative.parts:
        raise PlanError("plan stage may not equal the handoff root")
    if stage.is_symlink() or stage.stat().st_uid != uid:
        raise PlanError("plan stage is not owned private handoff state")
    for item in plan["apt"].get("packages", []):
        path = stage / item["relative_path"]
        info = _regular_owned_file(path, uid)
        if info.st_size != item["size"] or _sha256_file(path) != item["sha256"]:
            raise PlanError(f"APT artifact changed: {path}")
    for item in plan["snap"].get("packages", []):
        for rel_key, hash_key, size_key in (
            ("assert_relative_path", "assert_sha256", "assert_size"),
            ("snap_relative_path", "snap_sha256", "snap_size"),
        ):
            path = stage / item[rel_key]
            info = _regular_owned_file(path, uid)
            if info.st_size != item[size_key] or _sha256_file(path) != item[hash_key]:
                raise PlanError(f"snap artifact changed: {path}")


def verify_plan(plan_path: Path, confirmation: str) -> dict[str, Any]:
    plan = _read_json(plan_path)
    if plan.get("schema_version") != 1 or plan.get("kind") != PLAN_KIND:
        raise PlanError("plan schema or kind mismatch")
    _validate_confirmation(plan, confirmation)
    policy_path = Path(plan["policy_path"])
    policy = load_policy(policy_path)
    if _sha256_file(policy_path) != plan.get("policy_sha256"):
        raise PlanError("policy changed after planning")
    age = int(time.time()) - int(plan["created_at_unix"])
    if age < 0 or age > policy["staging"]["max_plan_age_seconds"]:
        raise PlanError(f"plan age {age}s exceeds policy limit")
    if _dpkg_status_sha256() != plan["baseline"]["dpkg_status_sha256"]:
        raise PlanError("dpkg status changed after planning")
    _validate_source_config(plan["baseline"]["apt_source_config"])
    uid = os.geteuid()
    if uid != plan["baseline"]["uid"]:
        raise PlanError("verification uid differs from plan uid")
    _require_broker_handoff_binding(policy)
    _validate_stage_artifacts(plan, uid, policy)
    for item in plan["snap"].get("packages", []):
        if _snap_installed_revision(item["name"]) != item["baseline_revision"]:
            raise PlanError(f"installed snap revision changed after planning: {item['name']}")
    expected = plan["root_artifact_sha256"]
    if expected != _artifact_expectations(plan):
        raise PlanError("root artifact expectation map is inconsistent")
    commands = plan["root_commands"]
    expected_commands = _root_commands(
        plan["plan_id"], Path(plan["stage_path"]), policy, plan["apt"], plan["snap"]
    )
    if commands != expected_commands:
        raise PlanError("root command set is inconsistent with the current policy and exact plan artifacts")
    apt_preflight = commands.get("apt_apply_preflight_argv") or []
    apt_apply = commands.get("apt_apply_argv") or []
    if apt_apply:
        expected_root_debs = str(Path(commands["root_stage"]) / "debs")
        if apt_preflight != [
            "/usr/bin/dpkg", "--simulate", "--force-confold",
            "--install", "--recursive", expected_root_debs,
        ]:
            raise PlanError("APT root preflight is not an exact local dpkg simulation")
        if apt_apply != _apt_apply_systemd_argv(plan["plan_id"], Path(expected_root_debs)):
            raise PlanError("APT root apply is not the exact network-denied systemd dpkg task")
    for argv in commands.get("snap_apply_argvs", []):
        if "--dangerous" in argv:
            raise PlanError("dangerous snap installation is forbidden")
    return {
        "status": "verified",
        "plan_path": str(plan_path),
        "plan_sha256": plan["plan_sha256"],
        "age_seconds": age,
        "root_artifact_sha256": expected,
        "root_commands": commands,
        "sensitive_apt_packages": [item["name"] for item in plan["apt"].get("packages", []) if item.get("sensitive")],
        "does_not_establish": [
            "root artifact copy integrity before root hash readback",
            "privileged apply completion",
            "postflight service health",
        ],
    }


def _dpkg_version(name: str, arch: str | None = None) -> str | None:
    query_name = name if ":" in name or not arch else f"{name}:{arch}"
    result = _run(["/usr/bin/dpkg-query", "-W", "-f=${Version}\n", query_name], check=False)
    if result["returncode"] != 0:
        return None
    versions = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    if len(versions) != 1:
        return None
    return versions[0]


def _service_state(unit: str, *, user: bool) -> str:
    argv = ["/usr/bin/systemctl"]
    if user:
        argv.append("--user")
    argv.extend(["is-active", unit])
    result = _run(argv, check=False)
    return result["stdout"].strip() or f"rc={result['returncode']}"


def postflight(plan_path: Path, confirmation: str) -> dict[str, Any]:
    plan = _read_json(plan_path)
    if plan.get("schema_version") != 1 or plan.get("kind") != PLAN_KIND:
        raise PlanError("plan schema or kind mismatch")
    _validate_confirmation(plan, confirmation)
    policy = load_policy(Path(plan["policy_path"]))
    apt_results: list[dict[str, Any]] = []
    for item in plan["apt"].get("packages", []):
        installed = _dpkg_version(item["name"], item.get("arch"))
        apt_results.append({
            "name": item["name"],
            "arch": item.get("arch"),
            "expected_version": item["version"],
            "installed_version": installed,
            "matched": installed == item["version"],
        })
    snap_results: list[dict[str, Any]] = []
    for item in plan["snap"].get("packages", []):
        try:
            installed_revision = _snap_installed_revision(item["name"])
        except PlanError:
            installed_revision = None
        snap_results.append({
            "name": item["name"],
            "expected_revision": item["revision"],
            "installed_revision": installed_revision,
            "matched": installed_revision == item["revision"],
        })
    system_services = {
        unit: _service_state(unit, user=False)
        for unit in policy.get("postflight", {}).get("system_services", [])
    }
    user_services = {
        unit: _service_state(unit, user=True)
        for unit in policy.get("postflight", {}).get("user_services", [])
    }
    nvidia = _run([
        "/usr/bin/nvidia-smi", "--query-gpu=name,driver_version,temperature.gpu,memory.used,memory.total", "--format=csv,noheader"
    ], check=False)
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": RECEIPT_KIND,
        "plan_id": plan["plan_id"],
        "plan_sha256": plan["plan_sha256"],
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "apt": apt_results,
        "snap": snap_results,
        "all_apt_matched": all(item["matched"] for item in apt_results),
        "all_snap_matched": all(item["matched"] for item in snap_results),
        "reboot_required": Path("/var/run/reboot-required").exists(),
        "system_services": system_services,
        "user_services": user_services,
        "nvidia_smi": nvidia["stdout"].strip() if nvidia["returncode"] == 0 else None,
        "does_not_establish": [
            "future package repository freshness",
            "future service health",
            "reboot completion when reboot_required is true",
        ],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    receipt_path = Path(plan["stage_path"]) / "postflight.json"
    _atomic_json(receipt_path, receipt)
    return {**receipt, "receipt_path": str(receipt_path)}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stage and verify hash-bound Heim-PC package updates.")
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="Refresh and download artifacts unprivileged; create a non-authorizing plan.")
    verify = sub.add_parser("verify", help="Verify exact plan, live preconditions and staged artifacts.")
    verify.add_argument("--plan", type=Path, required=True)
    verify.add_argument("--confirmation", required=True)
    post = sub.add_parser("postflight", help="Verify installed versions, snap revisions and service health.")
    post.add_argument("--plan", type=Path, required=True)
    post.add_argument("--confirmation", required=True)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    try:
        if args.command == "plan":
            result = create_plan(args.policy)
        elif args.command == "verify":
            result = verify_plan(args.plan, args.confirmation)
        elif args.command == "postflight":
            result = postflight(args.plan, args.confirmation)
        else:
            raise PlanError("unsupported command")
    except (PolicyError, PlanError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
