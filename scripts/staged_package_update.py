#!/usr/bin/python3 -I
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
import sys
import tempfile
import time
import urllib.parse
from typing import Any, Iterable

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "package-update-policy.v1.json"
PLAN_KIND = "heim_pc.staged_package_update_plan"
RECEIPT_KIND = "heim_pc.staged_package_update_receipt"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLAN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
APT_INST_RE = re.compile(r"^Inst (\S+)(?: \[[^]]*\])? \((\S+).* \[([^]]+)\]\)(?: .*)?$")
APT_SUMMARY_RE = re.compile(r"^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9.+-]")
BROKER_OUTPUT_EVIDENCE_ROOT = Path("/run/grabowski/privileged-broker-evidence")
BROKER_OUTPUT_EVIDENCE_KIND = "grabowski_privileged_output_evidence"
BROKER_POWER_ACTION = "operator_power_argv"
BROKER_PEER_UNIT = "grabowski-operator.service"
APT_SOURCE_FILE_PATTERNS = (
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d/*.list",
    "/etc/apt/sources.list.d/*.sources",
)
APT_KEYRING_PATTERNS = (
    "/etc/apt/trusted.gpg",
    "/etc/apt/trusted.gpg.d/*.gpg",
    "/etc/apt/trusted.gpg.d/*.asc",
    "/etc/apt/keyrings/*.gpg",
    "/etc/apt/keyrings/*.asc",
    "/usr/share/keyrings/*.gpg",
    "/usr/share/keyrings/*.asc",
)
APT_SOURCE_PATTERNS = APT_SOURCE_FILE_PATTERNS + APT_KEYRING_PATTERNS


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


def _base_command_env() -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "DEBIAN_FRONTEND": "noninteractive",
        "HOME": "/",
        "TMPDIR": "/tmp",
    }


def _run(
    argv: list[str], *, cwd: Path | None = None, check: bool = True,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    command_env = _base_command_env() if env is None else dict(env)
    for key in list(command_env):
        if key == "APT_CONFIG" or key.startswith(("DPKG_", "LD_", "SNAPD_", "SYSTEMD_", "DBUS_", "PYTHON")):
            command_env.pop(key, None)
    command_env.update({"LC_ALL": "C", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive"})
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=command_env,
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


def _host_readback_env(*, user: bool = False) -> dict[str, str]:
    value = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive", "HOME": "/"}
    if user:
        value["XDG_RUNTIME_DIR"] = f"/run/user/{os.geteuid()}"
    return value


def _host_dpkg_env() -> dict[str, str]:
    return _host_readback_env()


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


def _validate_broker_output_evidence(
    evidence_path: Path,
    *,
    expected_argv: list[str],
    stdout_text: str,
    expected_peer_uid: int,
    not_before_unix: int,
    max_age_seconds: int,
    expected_owner_uid: int = 0,
) -> dict[str, Any]:
    if evidence_path.parent != BROKER_OUTPUT_EVIDENCE_ROOT:
        raise PlanError("privileged broker output evidence path is outside the canonical evidence root")
    root_info = BROKER_OUTPUT_EVIDENCE_ROOT.lstat()
    if (
        BROKER_OUTPUT_EVIDENCE_ROOT.is_symlink()
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != expected_owner_uid
        or stat.S_IMODE(root_info.st_mode) & 0o022
    ):
        raise PlanError("privileged broker output evidence root is not trusted")
    info = evidence_path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_owner_uid
        or stat.S_IMODE(info.st_mode) != 0o640
        or info.st_nlink != 1
    ):
        raise PlanError("privileged broker output evidence file is not trusted")
    value = _read_json(evidence_path, max_bytes=64 * 1024)
    request_id = value.get("request_id")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != BROKER_OUTPUT_EVIDENCE_KIND
        or value.get("action") != BROKER_POWER_ACTION
        or value.get("mode") != "argv-json"
        or value.get("peer_uid") != expected_peer_uid
        or value.get("peer_unit") != BROKER_PEER_UNIT
        or value.get("returncode") != 0
        or value.get("timed_out") is not False
        or value.get("stdout_truncated") is not False
        or not isinstance(request_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", request_id) is None
        or evidence_path.name != f"{request_id}.json"
    ):
        raise PlanError("privileged broker output evidence identity or execution status is invalid")
    for key in ("reference_sha256", "argv_sha256", "cwd_sha256", "stdout_sha256", "evidence_sha256"):
        if not isinstance(value.get(key), str) or SHA256_RE.fullmatch(value[key]) is None:
            raise PlanError(f"privileged broker output evidence {key} is invalid")
    if value["argv_sha256"] != _sha256_json(expected_argv):
        raise PlanError("privileged broker output evidence is bound to different argv")
    raw_stdout = stdout_text.encode("utf-8")
    if value.get("stdout_bytes") != len(raw_stdout) or value["stdout_sha256"] != _sha256_bytes(raw_stdout):
        raise PlanError("privileged broker output evidence does not authenticate the supplied stdout")
    timestamp = value.get("timestamp_unix")
    now = int(time.time())
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or timestamp < not_before_unix
        or timestamp > now + 5
        or now - timestamp > max_age_seconds
    ):
        raise PlanError("privileged broker output evidence is stale or outside the plan lifetime")
    digest = value["evidence_sha256"]
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if _sha256_json(unsigned) != digest:
        raise PlanError("privileged broker output evidence content hash mismatch")
    return {
        "path": str(evidence_path),
        "request_id": request_id,
        "evidence_sha256": digest,
        "argv_sha256": value["argv_sha256"],
        "stdout_sha256": value["stdout_sha256"],
        "stdout_bytes": value["stdout_bytes"],
        "timestamp_unix": timestamp,
    }


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
    if snap.get("download_quota_mode") != "userns-pid-tmpfs-bwrap-ro-root":
        raise PolicyError("snap.download_quota_mode must be userns-pid-tmpfs-bwrap-ro-root")
    required_true = (
        "require_exact_plan_hash",
        "require_fresh_apt_indexes",
        "require_apt_signature_verification",
        "require_signed_apt_artifact_provenance",
        "require_pre_download_byte_cap",
        "require_root_staging_capacity",
        "require_reboot_capture",
        "require_dpkg_status_precondition",
        "require_source_config_precondition",
        "require_root_owned_copy_before_apply",
        "require_root_copy_hash_readback",
        "require_broker_read_only_handoff",
        "require_dpkg_explicit_apply",
        "require_no_remove_selection",
        "require_signed_snap_assertion",
        "require_snap_store_artifact_revalidation",
        "require_apt_apply_private_runtime_namespace",
        "require_apt_apply_kernel_device_isolation",
        "require_apply_readback_authorization",
        "require_snap_download_byte_cap",
        "require_snap_download_hard_quota",
        "require_authenticated_apt_preflight_completion",
        "require_authenticated_apply_completion_evidence",
        "require_postflight_plan_identity",
        "privileged_broker_network_must_remain_blocked",
        "require_privileged_broker_output_evidence",
        "require_target_downgrade_refusal",
        "require_explicit_activation_semantics",
    )
    for key in required_true:
        if safety.get(key) is not True:
            raise PolicyError(f"safety.{key} must be true")
    for parent, key in (
        (staging, "max_plan_age_seconds"), (staging, "privileged_readback_max_age_seconds"),
        (staging, "root_stage_safety_margin_bytes"),
        (apt, "max_packages"), (apt, "max_download_bytes"),
        (snap, "max_snaps"), (snap, "max_download_bytes"), (snap, "max_assertion_bytes"),
    ):
        if not isinstance(parent.get(key), int) or parent[key] <= 0:
            raise PolicyError(f"{key} must be a positive integer")
    if apt.get("selection_mode") != "upgrade-with-new-pkgs-no-remove":
        raise PolicyError("unsupported apt selection mode")
    if apt.get("apply_mode") != "dpkg-explicit-root-stage":
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


def _canonical_policy_path() -> Path:
    return POLICY_PATH.resolve(strict=True)


def _validate_plan_id(value: Any) -> str:
    if not isinstance(value, str) or PLAN_ID_RE.fullmatch(value) is None:
        raise PlanError("plan_id is not a canonical generated package-update id")
    return value


def _require_canonical_policy_path(policy_path: Path) -> Path:
    try:
        resolved = policy_path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PlanError(f"package update policy does not exist: {policy_path}") from exc
    if resolved != _canonical_policy_path():
        raise PlanError("privileged package plans must use the canonical repository policy")
    return resolved


def _root_stage_root(policy: dict[str, Any]) -> Path:
    value = policy["staging"]["root_root"]
    path = Path(value)
    if not path.is_absolute() or path == Path("/"):
        raise PolicyError("staging.root_root must be an absolute non-root path")
    return path


def _runtime_capture_root(policy: dict[str, Any]) -> Path:
    value = policy["staging"]["runtime_capture_root"]
    path = Path(value)
    if not path.is_absolute() or path == Path("/"):
        raise PolicyError("staging.runtime_capture_root must be an absolute non-root path")
    try:
        relative = path.relative_to(Path("/run"))
    except ValueError as exc:
        raise PolicyError("staging.runtime_capture_root must be below /run") from exc
    if not relative.parts:
        raise PolicyError("staging.runtime_capture_root may not equal /run")
    return path


def _root_capacity_prepare_argv(policy: dict[str, Any]) -> list[str]:
    root_root = _root_stage_root(policy)
    return [
        "/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0711",
        str(root_root),
    ]


def _root_capacity_argv(policy: dict[str, Any]) -> list[str]:
    return ["/usr/bin/stat", "-f", "-c", "%a:%S", str(_root_stage_root(policy))]


def parse_root_capacity_readback(text: str, required_bytes: int) -> dict[str, int | bool]:
    match = re.fullmatch(r"([0-9]+):([0-9]+)", text.strip())
    if match is None:
        raise PlanError("unexpected root staging filesystem capacity readback")
    available_blocks = int(match.group(1))
    block_size = int(match.group(2))
    if block_size <= 0:
        raise PlanError("root staging filesystem reported an invalid block size")
    available_bytes = available_blocks * block_size
    if required_bytes < 0:
        raise PlanError("root staging required bytes may not be negative")
    if available_bytes < required_bytes:
        raise PlanError(
            f"root staging requires {required_bytes} bytes but destination filesystem has only {available_bytes} available"
        )
    return {"required_bytes": required_bytes, "available_bytes": available_bytes, "sufficient": True}


def _root_copy_required_bytes(apt: dict[str, Any], snap: dict[str, Any]) -> int:
    total = 0
    for item in apt.get("packages", []):
        size = item.get("size")
        if not isinstance(size, int) or size < 0:
            raise PlanError("APT artifact size is missing or invalid for root staging")
        total += size
    for item in snap.get("packages", []):
        for key in ("assert_size", "snap_size"):
            size = item.get(key)
            if not isinstance(size, int) or size < 0:
                raise PlanError("Snap artifact size is missing or invalid for root staging")
            total += size
    return total


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


def _apt_source_text(path: Path) -> str:
    target = path.resolve(strict=True) if path.is_symlink() else path
    if not target.is_file():
        raise PlanError(f"APT source path is not a regular file: {path}")
    try:
        return target.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PlanError(f"APT source file is not UTF-8 text: {path}") from exc


def _signed_by_paths_from_source(path: Path) -> set[Path]:
    text = _apt_source_text(path)
    signed_by: set[Path] = set()
    if path.name == "sources.list" or path.suffix == ".list":
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or re.match(r"^deb(?:-src)?\s", line, flags=re.I) is None:
                continue
            option_match = re.match(r"^deb(?:-src)?\s+\[([^]]+)\]", line, flags=re.I)
            if option_match is None:
                continue
            options = option_match.group(1)
            if re.search(r"(?:^|\s)trusted\s*=\s*(?:yes|true|1)(?=\s|$)", options, flags=re.I):
                raise PlanError(f"active APT source bypasses authentication with trusted=yes: {path}")
            for match in re.finditer(r"(?:^|\s)signed-by\s*=\s*([^\s]+)", options, flags=re.I):
                for token in match.group(1).split(","):
                    if token.startswith("/"):
                        signed_by.add(Path(token))
        return signed_by

    if path.suffix != ".sources":
        return signed_by
    for paragraph in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        current: str | None = None
        for raw_line in paragraph.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            if raw_line[:1].isspace() and current is not None:
                fields[current] += "\n" + raw_line.strip()
                continue
            match = re.match(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$", raw_line)
            if match is None:
                current = None
                continue
            current = match.group(1).lower()
            fields[current] = match.group(2).strip()
        if fields.get("enabled", "yes").strip().lower() in {"no", "false", "0"}:
            continue
        types = {token.lower() for token in fields.get("types", "").split()}
        if not types.intersection({"deb", "deb-src"}):
            continue
        if fields.get("trusted", "").strip().lower() in {"yes", "true", "1"}:
            raise PlanError(f"active APT source bypasses authentication with Trusted: yes: {path}")
        signed_value = fields.get("signed-by", "")
        signed_value = signed_value.split("-----BEGIN PGP PUBLIC KEY BLOCK-----", 1)[0]
        for token in re.split(r"[,\s]+", signed_value):
            if token.startswith("/"):
                signed_by.add(Path(token))
    return signed_by


def _active_signed_by_keyrings() -> list[Path]:
    keyrings: set[Path] = set()
    for source in _expand_patterns(APT_SOURCE_FILE_PATTERNS):
        keyrings.update(_signed_by_paths_from_source(source))
    resolved: set[Path] = set()
    for keyring in keyrings:
        target = keyring.resolve(strict=True) if keyring.is_symlink() else keyring
        if not target.is_file():
            raise PlanError(f"active APT Signed-By keyring is missing or not regular: {keyring}")
        resolved.add(target)
    return sorted(resolved, key=str)


def _source_config_records() -> list[dict[str, Any]]:
    candidates = set(_expand_patterns(APT_SOURCE_PATTERNS))
    candidates.update(_active_signed_by_keyrings())
    resolved: set[Path] = set()
    for path in candidates:
        if path.is_symlink():
            target = path.resolve(strict=True)
            if not target.is_file():
                raise PlanError(f"APT source/key symlink does not resolve to regular file: {path}")
            path = target
        if path.is_file():
            resolved.add(path)
    records: list[dict[str, Any]] = []
    for path in sorted(resolved, key=str):
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
        "-o", "Dir::Etc::sourcelist=/etc/apt/sources.list",
        "-o", "Dir::Etc::sourceparts=/etc/apt/sources.list.d",
        "-o", "Dir::Etc::trusted=/etc/apt/trusted.gpg",
        "-o", "Dir::Etc::trustedparts=/etc/apt/trusted.gpg.d",
        "-o", "APT::Get::AllowUnauthenticated=false",
        "-o", "Acquire::AllowInsecureRepositories=false",
        "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
        "-o", "Acquire::AllowWeakRepositories=false",
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
    summary_total: int | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        summary = APT_SUMMARY_RE.match(line)
        if summary is not None:
            if summary_total is not None:
                raise PlanError("APT simulation contains multiple summary rows")
            upgraded, newly_installed, removed, _not_upgraded = (int(value) for value in summary.groups())
            if removed != 0:
                raise PlanError("APT simulation unexpectedly proposes removals")
            summary_total = upgraded + newly_installed
            continue
        match = APT_INST_RE.match(line)
        if match is None:
            if "Inst " in line:
                raise PlanError(f"unexpected apt simulation Inst row: {line}")
            continue
        name, version, arch = match.groups()
        packages.append({"name": name, "version": version, "arch": arch})
    if summary_total is None:
        raise PlanError("APT simulation summary row is missing or changed format")
    if len(packages) != summary_total:
        raise PlanError(f"APT simulation parsed {len(packages)} install rows but summary declares {summary_total}")
    return packages


def parse_apt_print_uris(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = shlex.split(line)
        if len(parts) != 4 or not parts[2].isdigit():
            raise PlanError(f"unexpected apt --print-uris output: {line}")
        hash_kind, separator, digest = parts[3].partition(":")
        algorithm = hash_kind.upper()
        digest_lengths = {"SHA256": 64, "SHA512": 128}
        expected_length = digest_lengths.get(algorithm)
        if (
            separator != ":"
            or expected_length is None
            or re.fullmatch(rf"[0-9a-fA-F]{{{expected_length}}}", digest) is None
        ):
            raise PlanError("APT repository metadata did not provide a supported strong SHA256/SHA512 artifact hash")
        uri_path = urllib.parse.unquote(urllib.parse.urlsplit(parts[0]).path)
        uri_basename = Path(uri_path).name
        if not uri_basename:
            raise PlanError("APT repository URI did not provide an artifact basename")
        records.append({
            "repository_uri_sha256": _sha256_bytes(parts[0].encode("utf-8")),
            "repository_uri_basename": uri_basename,
            "repository_filename": parts[1],
            "repository_size": int(parts[2]),
            "repository_hash_algorithm": algorithm,
            "repository_hash": digest.lower(),
        })
    return records


def parse_apt_cache_show_sha256(
    text: str, candidate: dict[str, str], *, repository_uri_basename: str,
    repository_size: int,
) -> str:
    expected_package = str(candidate["name"]).split(":", 1)[0]
    expected_version = str(candidate["version"])
    expected_arch = str(candidate["arch"])
    if (
        not repository_uri_basename
        or isinstance(repository_size, bool)
        or not isinstance(repository_size, int)
        or repository_size < 0
    ):
        raise PlanError("APT repository artifact identity is invalid")
    digests: set[str] = set()
    for paragraph in re.split(r"\n\s*\n", text.strip()):
        if not paragraph.strip():
            continue
        fields: dict[str, str] = {}
        current: str | None = None
        for raw_line in paragraph.splitlines():
            if raw_line[:1].isspace() and current is not None:
                continue
            match = re.match(r"^([A-Za-z0-9-]+):\s*(.*)$", raw_line)
            if match is None:
                current = None
                continue
            current = match.group(1).lower()
            fields[current] = match.group(2).strip()
        if (
            fields.get("package") != expected_package
            or fields.get("version") != expected_version
            or fields.get("architecture") != expected_arch
            or fields.get("size") != str(repository_size)
            or Path(fields.get("filename", "")).name != repository_uri_basename
        ):
            continue
        digest = fields.get("sha256", "").lower()
        if SHA256_RE.fullmatch(digest) is None:
            continue
        digests.add(digest)
    if len(digests) != 1:
        raise PlanError(
            f"APT signed package metadata did not resolve exactly one SHA-256 for "
            f"{expected_package}:{expected_arch}={expected_version}"
        )
    return next(iter(digests))


def _strong_hash_file(path: Path, algorithm: str) -> str:
    constructors = {"SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
    constructor = constructors.get(algorithm)
    if constructor is None:
        raise PlanError(f"unsupported strong APT artifact hash algorithm: {algorithm}")
    digest = constructor()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _candidate_identity(item: dict[str, Any]) -> tuple[str, str, str]:
    return (str(item["name"]), str(item["version"]), str(item["arch"]))


def _apt_repository_record(options: list[str], candidate: dict[str, str]) -> dict[str, Any]:
    spec = f"{candidate['name']}={candidate['version']}"
    result = _run(["/usr/bin/apt-get", *options, "--print-uris", "download", spec])
    records = parse_apt_print_uris(result["stdout"])
    if len(records) != 1:
        raise PlanError(f"APT repository metadata did not resolve exactly one artifact for {spec}")
    repository = records[0]
    base_name = str(candidate["name"]).split(":", 1)[0]
    metadata_spec = f"{base_name}:{candidate['arch']}={candidate['version']}"
    metadata = _run(["/usr/bin/apt-cache", *options, "show", metadata_spec])
    repository_sha256 = parse_apt_cache_show_sha256(
        metadata["stdout"], candidate,
        repository_uri_basename=str(repository["repository_uri_basename"]),
        repository_size=int(repository["repository_size"]),
    )
    return {
        **repository,
        "repository_sha256": repository_sha256,
        "repository_manifest_sha256": _sha256_bytes(result["stdout"].encode()),
    }


def _available_bytes(path: Path) -> int:
    info = os.statvfs(path)
    return int(info.f_bavail) * int(info.f_frsize)


def _stage_artifact_path(stage: Path, relative_value: Any, expected_parent: Path) -> Path:
    if not isinstance(relative_value, str) or not relative_value:
        raise PlanError("stage artifact relative path must be a non-empty string")
    relative = Path(relative_value)
    if relative.is_absolute() or ".." in relative.parts:
        raise PlanError(f"stage artifact path escapes its bounded directory: {relative_value}")
    path = stage / relative
    try:
        child = path.relative_to(expected_parent)
    except ValueError as exc:
        raise PlanError(f"stage artifact path escapes its bounded directory: {relative_value}") from exc
    if not child.parts:
        raise PlanError("stage artifact path may not name the artifact directory itself")
    return path


def _apt_update_and_candidates(stage: Path, policy: dict[str, Any], uid: int) -> tuple[list[str], dict[str, Any], dict[str, Any], list[dict[str, str]]]:
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
    return options, update, simulation, candidates


def _deb_field(path: Path, field: str) -> str:
    result = _run(["/usr/bin/dpkg-deb", "-f", str(path), field])
    return result["stdout"].strip()


def _deb_reboot_marker_capable(path: Path, uid: int) -> bool:
    with tempfile.TemporaryDirectory(prefix=".control-", dir=path.parent) as control_raw:
        control = Path(control_raw)
        _run(["/usr/bin/dpkg-deb", "--control", str(path), str(control)])
        total_bytes = 0
        needles = (b"reboot-required", b"notify-reboot-required")
        for candidate in sorted(control.rglob("*"), key=str):
            if candidate.is_symlink():
                raise PlanError(f"DEB control archive contains a symlink: {candidate}")
            if not candidate.is_file():
                continue
            info = candidate.stat()
            if info.st_uid != uid or info.st_nlink != 1:
                raise PlanError(f"DEB control file has unsafe ownership/link count: {candidate}")
            total_bytes += info.st_size
            if total_bytes > 8 * 1024 * 1024:
                raise PlanError("DEB control archive exceeds bounded reboot-marker inspection size")
            data = candidate.read_bytes()
            if any(needle in data for needle in needles):
                return True
    return False


def _is_sensitive_package(name: str, policy: dict[str, Any]) -> bool:
    lowered = name.split(":", 1)[0].lower()
    prefixes = policy["apt"].get("sensitive_prefixes", [])
    if not isinstance(prefixes, list) or not all(isinstance(item, str) for item in prefixes):
        raise PolicyError("apt.sensitive_prefixes must be a string list")
    return any(lowered.startswith(prefix.lower()) for prefix in prefixes)


def _stage_apt(stage: Path, policy: dict[str, Any], uid: int) -> dict[str, Any]:
    if policy["apt"].get("enabled") is not True:
        return {"enabled": False, "packages": []}
    options, update, simulation, candidates = _apt_update_and_candidates(stage, policy, uid)
    if not candidates:
        return {
            "enabled": True,
            "update_stdout_sha256": _sha256_bytes(update["stdout"].encode()),
            "update_stderr_sha256": _sha256_bytes(update["stderr"].encode()),
            "simulation_sha256": _sha256_bytes(simulation["stdout"].encode()),
            "packages": [],
            "download_bytes": 0,
            "authenticated_download_bytes": 0,
        }
    deb_dir = stage / "apt" / "debs"
    authenticated: dict[tuple[str, str, str], dict[str, Any]] = {}
    authenticated_bytes = 0
    for candidate in candidates:
        key = _candidate_identity(candidate)
        if key in authenticated:
            raise PlanError(f"duplicate APT candidate identity: {key}")
        record = _apt_repository_record(options, candidate)
        authenticated[key] = record
        authenticated_bytes += int(record["repository_size"])
    if authenticated_bytes > policy["apt"]["max_download_bytes"]:
        raise PlanError(f"APT authenticated download bytes {authenticated_bytes} exceed policy limit before download")
    available = _available_bytes(deb_dir)
    if authenticated_bytes > available:
        raise PlanError(f"APT authenticated download bytes {authenticated_bytes} exceed available staging bytes {available}")
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
        info_before = _regular_owned_file(path, uid)
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
        auth_key = _candidate_identity(candidate)
        repository = authenticated[auth_key]
        digest = _sha256_file(path)
        if (
            info_before.st_size != repository["repository_size"]
            or digest != repository["repository_sha256"]
            or _strong_hash_file(path, repository["repository_hash_algorithm"]) != repository["repository_hash"]
        ):
            raise PlanError(f"downloaded DEB does not match authenticated repository metadata: {key}")
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
            **repository,
            "sensitive": _is_sensitive_package(candidate["name"], policy),
            "reboot_marker_capable": _deb_reboot_marker_capable(renamed, uid),
        })
    missing = sorted(set(expected) - seen)
    if missing:
        raise PlanError(f"missing exact DEB artifacts for {len(missing)} candidates")
    if total_bytes != authenticated_bytes:
        raise PlanError("downloaded APT bytes differ from authenticated pre-download manifest")
    return {
        "enabled": True,
        "update_stdout_sha256": _sha256_bytes(update["stdout"].encode()),
        "update_stderr_sha256": _sha256_bytes(update["stderr"].encode()),
        "simulation_sha256": _sha256_bytes(simulation["stdout"].encode()),
        "packages": artifacts,
        "download_bytes": total_bytes,
        "authenticated_download_bytes": authenticated_bytes,
    }


def _snap_size_upper_bound_bytes(value: str) -> int:
    match = re.fullmatch(r"([0-9]+)(?:\.([0-9]+))?([KMGTPE]?B)", value.strip(), flags=re.I)
    if match is None:
        raise PlanError(f"unexpected snap size: {value}")
    whole = match.group(1)
    fraction = match.group(2) or ""
    digits = int(whole + fraction)
    scale = 10 ** len(fraction)
    # One displayed quantum is added deliberately so rounded human output is a safe upper bound.
    upper_digits = digits + 1
    unit = match.group(3).upper()
    powers = {"B": 0, "KB": 1, "MB": 2, "GB": 3, "TB": 4, "PB": 5, "EB": 6}
    multiplier = 1024 ** powers[unit]
    return (upper_digits * multiplier + scale - 1) // scale


def parse_snap_refresh_list(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("name ") or "up to date" in line.lower():
            continue
        parts = line.split()
        if len(parts) < 4 or not parts[2].isdigit():
            raise PlanError(f"unexpected snap refresh --list row: {line}")
        rows.append({
            "name": parts[0],
            "version": parts[1],
            "revision": parts[2],
            "size_upper_bound_bytes": _snap_size_upper_bound_bytes(parts[3]),
        })
    return rows


def _snap_installed_revision(name: str) -> str:
    result = _run(["/usr/bin/snap", "list", name], env=_host_readback_env())
    lines = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    if len(lines) < 2:
        raise PlanError(f"cannot read installed snap revision for {name}")
    parts = lines[1].split()
    if len(parts) < 3 or not parts[2].isdigit():
        raise PlanError(f"unexpected snap list output for {name}")
    return parts[2]


def _snap_quota_worker(args: list[str]) -> int:
    if len(args) != 7:
        raise PlanError("Snap quota worker argument count is invalid")
    mountpoint = Path(args[0]); output_dir = Path(args[1]); name, revision, basename = args[2], args[3], args[4]
    if (not mountpoint.is_absolute() or not output_dir.is_absolute() or not name or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name) is None or re.fullmatch(r"[0-9]+", revision) is None or re.fullmatch(r"[A-Za-z0-9.+-]{1,200}", basename) is None):
        raise PlanError("Snap quota worker identity is invalid")
    try:
        snap_cap = int(args[5]); assertion_cap = int(args[6])
    except ValueError as exc:
        raise PlanError("Snap quota worker byte limits are invalid") from exc
    if snap_cap <= 0 or assertion_cap <= 0:
        raise PlanError("Snap quota worker byte limits must be positive")
    quota_bytes = snap_cap + assertion_cap
    for directory, label in ((mountpoint, "mountpoint"), (output_dir, "output directory")):
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or (stat.S_IMODE(info.st_mode) & 0o022):
            raise PlanError(f"Snap quota {label} is unsafe")
    if any(mountpoint.iterdir()):
        raise PlanError("Snap quota mountpoint must start empty")
    expected_names = {f"{basename}.snap", f"{basename}.assert"}; copied: list[Path] = []; mounted = False
    try:
        safe_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
        mount = subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", f"size={quota_bytes},mode=0700,nosuid,nodev,noexec", "tmpfs", str(mountpoint)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=safe_env)
        if mount.returncode != 0:
            raise PlanError(f"Snap quota tmpfs mount failed: {mount.stderr.strip()}")
        mounted = True
        snap_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(mountpoint), "TMPDIR": str(mountpoint), "XDG_CACHE_HOME": str(mountpoint), "XDG_CONFIG_HOME": str(mountpoint)}
        download = subprocess.run(["/usr/bin/bwrap", "--ro-bind", "/", "/", "--bind", str(mountpoint), str(mountpoint), "--die-with-parent", "/usr/bin/snap", "download", name, "--revision", revision, "--basename", basename, "--target-directory", str(mountpoint)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=snap_env)
        if download.returncode != 0:
            raise PlanError(f"snap download failed inside hard quota rc={download.returncode}: {download.stderr.strip() or download.stdout.strip()}")
        if {entry.name for entry in mountpoint.iterdir()} != expected_names:
            raise PlanError("Snap quota download produced an unexpected artifact inventory")
        for source, destination, limit, label in ((mountpoint / f"{basename}.snap", output_dir / f"{basename}.snap", snap_cap, "snap"), (mountpoint / f"{basename}.assert", output_dir / f"{basename}.assert", assertion_cap, "assertion")):
            source_info = source.lstat()
            if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != os.geteuid() or source_info.st_nlink != 1 or source_info.st_size <= 0 or source_info.st_size > limit:
                raise PlanError(f"Snap quota {label} artifact is unsafe or over limit")
            source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
            try:
                destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600); copied.append(destination)
                try:
                    remaining = source_info.st_size
                    while remaining:
                        chunk = os.read(source_fd, min(1024 * 1024, remaining))
                        if not chunk: raise PlanError(f"Snap quota {label} artifact ended early")
                        view = memoryview(chunk)
                        while view:
                            written = os.write(destination_fd, view)
                            if written <= 0: raise OSError("Snap quota artifact copy was incomplete")
                            view = view[written:]
                        remaining -= len(chunk)
                    if os.read(source_fd, 1): raise PlanError(f"Snap quota {label} artifact grew during copy")
                    os.fsync(destination_fd)
                finally: os.close(destination_fd)
            finally: os.close(source_fd)
        _fsync_directory(output_dir)
        unmount = subprocess.run(["/usr/bin/umount", str(mountpoint)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=safe_env)
        if unmount.returncode != 0:
            raise PlanError(f"Snap quota tmpfs teardown failed: {unmount.stderr.strip()}")
        mounted = False
        if download.stdout: sys.stdout.write(download.stdout)
        return 0
    except BaseException:
        for destination in reversed(copied): destination.unlink(missing_ok=True)
        raise
    finally:
        if mounted: subprocess.run(["/usr/bin/umount", str(mountpoint)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})


def _snap_quota_argv(output_dir: Path, mountpoint: Path, *, name: str, revision: str, basename: str, snap_cap: int, assertion_cap: int) -> list[str]:
    return ["/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--pid", "--fork", "--kill-child=KILL", "--mount-proc", "/usr/bin/python3", "-I", str(Path(__file__).resolve()), "__snap-quota-worker", str(mountpoint), str(output_dir), name, revision, basename, str(snap_cap), str(assertion_cap)]


def _snap_quota_download(output_dir: Path, *, name: str, revision: str, basename: str, snap_cap: int, assertion_cap: int, uid: int) -> dict[str, Any]:
    _ensure_private_dir(output_dir, uid); mountpoint = output_dir / f".quota-{basename}-{secrets.token_hex(6)}"; mountpoint.mkdir(mode=0o700)
    try:
        result = _run(_snap_quota_argv(output_dir, mountpoint, name=name, revision=revision, basename=basename, snap_cap=snap_cap, assertion_cap=assertion_cap))
        if any(mountpoint.iterdir()): raise PlanError("Snap quota mountpoint retained unexpected files after namespace exit")
        return result
    finally:
        try: mountpoint.rmdir()
        except FileNotFoundError: pass


def _stage_snap(stage: Path, policy: dict[str, Any], uid: int) -> dict[str, Any]:
    if policy["snap"].get("enabled") is not True:
        return {"enabled": False, "packages": [], "download_bytes": 0, "declared_upper_bound_bytes": 0}
    snap_dir = stage / "snap"
    _ensure_private_dir(snap_dir, uid)
    listed = _run(["/usr/bin/snap", "refresh", "--list"], check=False)
    if listed["returncode"] != 0:
        raise PlanError(f"snap refresh --list failed: {listed['stderr'].strip()}")
    pending = parse_snap_refresh_list(listed["stdout"])
    if len(pending) > policy["snap"]["max_snaps"]:
        raise PlanError(f"snap candidate count {len(pending)} exceeds policy limit")
    assertion_budget = policy["snap"]["max_assertion_bytes"] * len(pending)
    declared_upper_bound = sum(int(item["size_upper_bound_bytes"]) for item in pending) + assertion_budget
    if declared_upper_bound > policy["snap"]["max_download_bytes"]:
        raise PlanError(f"Snap declared download upper bound {declared_upper_bound} exceeds policy limit before download")
    available = _available_bytes(snap_dir)
    if declared_upper_bound > available:
        raise PlanError(f"Snap declared download upper bound {declared_upper_bound} exceeds available staging bytes {available}")
    artifacts: list[dict[str, Any]] = []
    total_bytes = 0
    for item in pending:
        baseline_revision = _snap_installed_revision(str(item["name"]))
        basename = f"{SAFE_NAME_RE.sub('_', str(item['name']))}_{item['revision']}"
        download = _snap_quota_download(
            snap_dir, name=str(item["name"]), revision=str(item["revision"]),
            basename=basename, snap_cap=int(item["size_upper_bound_bytes"]),
            assertion_cap=policy["snap"]["max_assertion_bytes"], uid=uid,
        )
        snap_path = snap_dir / f"{basename}.snap"
        assertion_path = snap_dir / f"{basename}.assert"
        snap_info = _regular_owned_file(snap_path, uid)
        assertion_info = _regular_owned_file(assertion_path, uid)
        if assertion_info.st_size == 0 or assertion_info.st_size > policy["snap"]["max_assertion_bytes"]:
            raise PlanError(f"snap assertion size is invalid for {item['name']}")
        if snap_info.st_size > int(item["size_upper_bound_bytes"]):
            raise PlanError(f"downloaded snap exceeds the Store-list size upper bound: {item['name']}")
        total_bytes += snap_info.st_size + assertion_info.st_size
        if total_bytes > policy["snap"]["max_download_bytes"]:
            raise PlanError("actual Snap download bytes exceed policy limit")
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
        "download_bytes": total_bytes,
        "declared_upper_bound_bytes": declared_upper_bound,
    }


def _revalidate_apt_provenance(stage: Path, plan: dict[str, Any], policy: dict[str, Any], uid: int) -> None:
    apt = plan.get("apt")
    if not isinstance(apt, dict) or apt.get("enabled") is not (policy["apt"].get("enabled") is True):
        raise PlanError("APT plan enabled state is inconsistent with policy")
    if apt.get("enabled") is not True:
        if apt.get("packages"):
            raise PlanError("disabled APT plan may not contain packages")
        return
    options, _update, _simulation, candidates = _apt_update_and_candidates(stage, policy, uid)
    planned_packages = apt.get("packages", [])
    if not isinstance(planned_packages, list):
        raise PlanError("APT plan packages must be a list")
    current_identities = sorted(_candidate_identity(item) for item in candidates)
    planned_identities = sorted(_candidate_identity(item) for item in planned_packages)
    if current_identities != planned_identities:
        raise PlanError("APT signed upgrade candidate set changed or plan was not derived from the current signed candidate set")
    authenticated_total = 0
    for item in planned_packages:
        repository = _apt_repository_record(options, item)
        repository_sha256 = repository.get("repository_sha256")
        if not isinstance(repository_sha256, str) or SHA256_RE.fullmatch(repository_sha256) is None:
            raise PlanError(f"APT signed repository SHA-256 is missing or invalid for {item['name']}")
        for key in (
            "repository_size", "repository_hash_algorithm", "repository_hash",
            "repository_sha256", "repository_manifest_sha256", "repository_uri_sha256",
        ):
            if item.get(key) != repository.get(key):
                raise PlanError(f"APT authenticated repository provenance changed for {item['name']}")
        if item.get("sha256") != repository_sha256:
            raise PlanError(
                f"APT plan SHA-256 differs from signed repository SHA-256 for {item['name']}"
            )
        authenticated_total += int(repository["repository_size"])
        if authenticated_total > policy["apt"]["max_download_bytes"]:
            raise PlanError(f"APT authenticated download bytes {authenticated_total} exceed policy limit during verification")
        sensitive = _is_sensitive_package(str(item["name"]), policy)
        if item.get("sensitive") is not sensitive:
            raise PlanError(f"APT sensitive-package classification changed for {item['name']}")
        path = _stage_artifact_path(stage, item.get("relative_path"), stage / "apt" / "debs")
        info = _regular_owned_file(path, uid)
        package = _deb_field(path, "Package")
        version = _deb_field(path, "Version")
        arch = _deb_field(path, "Architecture")
        expected_package = str(item["name"]).split(":", 1)[0]
        if (package, version, arch) != (expected_package, item["version"], item["arch"]):
            raise PlanError(f"APT artifact package identity does not match signed plan candidate: {path}")
        if (
            info.st_size != repository["repository_size"]
            or _sha256_file(path) != repository_sha256
            or _strong_hash_file(path, repository["repository_hash_algorithm"]) != repository["repository_hash"]
        ):
            raise PlanError(f"APT artifact bytes do not match freshly authenticated repository metadata: {path}")
        reboot_marker_capable = _deb_reboot_marker_capable(path, uid)
        if item.get("reboot_marker_capable") is not reboot_marker_capable:
            raise PlanError(f"APT reboot-marker capability changed for {item['name']}")
    if apt.get("authenticated_download_bytes") != authenticated_total or apt.get("download_bytes") != authenticated_total:
        raise PlanError("APT planned download byte totals differ from freshly authenticated repository sizes")


def _revalidate_snap_store_artifact(
    stage: Path, item: dict[str, Any], uid: int, policy: dict[str, Any]
) -> None:
    snap_dir = stage / "snap"
    _ensure_private_dir(snap_dir, uid)
    staged_snap = _stage_artifact_path(stage, item.get("snap_relative_path"), snap_dir)
    staged_assert = _stage_artifact_path(stage, item.get("assert_relative_path"), snap_dir)
    staged_snap_info = _regular_owned_file(staged_snap, uid)
    staged_assert_info = _regular_owned_file(staged_assert, uid)
    if staged_snap_info.st_size > int(item["size_upper_bound_bytes"]):
        raise PlanError(f"staged snap exceeds declared Store-list upper bound: {item['name']}")
    if staged_assert_info.st_size > policy["snap"]["max_assertion_bytes"]:
        raise PlanError(f"staged snap assertion exceeds policy limit: {item['name']}")
    verify_upper_bound = int(item["size_upper_bound_bytes"]) + policy["snap"]["max_assertion_bytes"]
    if verify_upper_bound > policy["snap"]["max_download_bytes"]:
        raise PlanError(f"Snap verification download upper bound exceeds policy limit: {item['name']}")
    available = _available_bytes(snap_dir)
    if verify_upper_bound > available:
        raise PlanError(f"Snap verification download upper bound exceeds available staging bytes: {item['name']}")
    with tempfile.TemporaryDirectory(prefix=".verify-store-", dir=snap_dir) as verify_dir_raw:
        verify_dir = Path(verify_dir_raw)
        basename = f"verify-{SAFE_NAME_RE.sub('_', str(item['name']))}_{item['revision']}-{secrets.token_hex(4)}"
        _snap_quota_download(
            verify_dir, name=str(item["name"]), revision=str(item["revision"]),
            basename=basename, snap_cap=int(item["size_upper_bound_bytes"]),
            assertion_cap=policy["snap"]["max_assertion_bytes"], uid=uid,
        )
        store_snap = verify_dir / f"{basename}.snap"
        store_assert = verify_dir / f"{basename}.assert"
        store_snap_info = _regular_owned_file(store_snap, uid)
        store_assert_info = _regular_owned_file(store_assert, uid)
        if store_assert_info.st_size == 0 or store_assert_info.st_size > policy["snap"]["max_assertion_bytes"]:
            raise PlanError(f"fresh Store assertion size is invalid for {item['name']}")
        if store_snap_info.st_size > int(item["size_upper_bound_bytes"]):
            raise PlanError(f"fresh Store snap exceeds declared size upper bound: {item['name']}")
        if (
            staged_snap_info.st_size != store_snap_info.st_size
            or _sha256_file(staged_snap) != _sha256_file(store_snap)
            or staged_assert_info.st_size != store_assert_info.st_size
            or _sha256_file(staged_assert) != _sha256_file(store_assert)
        ):
            raise PlanError(f"Snap staged assertion/artifact does not match freshly downloaded Store artifact: {item['name']}")


def _revalidate_snap_provenance(stage: Path, plan: dict[str, Any], policy: dict[str, Any], uid: int) -> None:
    snap = plan.get("snap")
    if not isinstance(snap, dict) or snap.get("enabled") is not (policy["snap"].get("enabled") is True):
        raise PlanError("Snap plan enabled state is inconsistent with policy")
    if snap.get("enabled") is not True:
        if snap.get("packages"):
            raise PlanError("disabled Snap plan may not contain packages")
        return
    listed = _run(["/usr/bin/snap", "refresh", "--list"], check=False)
    if listed["returncode"] != 0:
        raise PlanError(f"snap refresh --list failed during verification: {listed['stderr'].strip()}")
    pending = parse_snap_refresh_list(listed["stdout"])
    if len(pending) > policy["snap"]["max_snaps"]:
        raise PlanError(f"snap candidate count {len(pending)} exceeds policy limit during verification")
    planned_packages = snap.get("packages", [])
    if not isinstance(planned_packages, list):
        raise PlanError("Snap plan packages must be a list")
    current = sorted(
        (item["name"], item["version"], item["revision"], item["size_upper_bound_bytes"]) for item in pending
    )
    planned = sorted(
        (item["name"], item["version"], item["revision"], item["size_upper_bound_bytes"]) for item in planned_packages
    )
    if current != planned:
        raise PlanError("Snap pending refresh set changed or plan was not derived from the current Store refresh set")
    declared_upper_bound = (
        sum(int(item["size_upper_bound_bytes"]) for item in planned_packages)
        + policy["snap"]["max_assertion_bytes"] * len(planned_packages)
    )
    if declared_upper_bound > policy["snap"]["max_download_bytes"]:
        raise PlanError("Snap declared verification bytes exceed policy limit")
    if snap.get("declared_upper_bound_bytes") != declared_upper_bound:
        raise PlanError("Snap declared upper-bound byte total changed")
    actual_total = sum(int(item["snap_size"]) + int(item["assert_size"]) for item in planned_packages)
    if snap.get("download_bytes") != actual_total or actual_total > policy["snap"]["max_download_bytes"]:
        raise PlanError("Snap planned download byte total is inconsistent or over policy")
    for item in planned_packages:
        _revalidate_snap_store_artifact(stage, item, uid, policy)


def _root_apt_deb_paths(plan: dict[str, Any]) -> list[Path]:
    root_debs = Path(plan["root_commands"]["root_stage"]) / "debs"
    paths: list[Path] = []
    for item in plan["apt"].get("packages", []):
        relative = item.get("relative_path")
        if not isinstance(relative, str) or not relative:
            raise PlanError("APT package relative_path is missing")
        paths.append(root_debs / Path(relative).name)
    return paths


def _apt_apply_systemd_argv(
    plan_id: str, root_deb_paths: list[Path], runtime_capture: Path
) -> list[str]:
    if not root_deb_paths:
        raise PlanError("APT apply requires at least one explicit root-owned DEB path")
    unit_name = f"heim-pc-package-update-{SAFE_NAME_RE.sub('_', plan_id)}.service"
    argv = [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--collect",
        "--pipe",
        f"--unit={unit_name}",
        "--property=Type=exec",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateMounts=yes",
        "--property=PrivateNetwork=yes",
        f"--property=BindPaths={runtime_capture}:/run",
        "--property=ProtectProc=invisible",
        "--property=ProcSubset=pid",
        "--property=BindReadOnlyPaths=/dev/null:/run/systemd/private /dev/null:/run/dbus/system_bus_socket",
        "--property=ProtectKernelTunables=yes",
        # Kernel DEBs legitimately create /usr/lib/modules/<version> during unpack.
        # Making that tree read-only converts a valid offline kernel upgrade into
        # a partial dpkg transaction before the package can reach postinst.
        "--property=ProtectControlGroups=yes",
        "--property=PrivateDevices=yes",
        "--property=RestrictNamespaces=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectClock=yes",
        "--property=LockPersonality=yes",
        "--property=CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_SYS_BOOT CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_TIME CAP_SYS_TTY_CONFIG",
        "--property=MemoryDenyWriteExecute=no",
        "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "--property=IPAddressDeny=any",
        "--",
        "/usr/bin/dpkg",
        "--refuse-downgrade",
        "--force-confold",
        "--install",
        *[str(path) for path in root_deb_paths],
    ]
    if len(argv) > 128:
        raise PlanError("APT apply argv exceeds privileged broker item limit")
    return argv


def _root_commands(
    plan_id: str, stage: Path, policy: dict[str, Any], apt: dict[str, Any], snap: dict[str, Any]
) -> dict[str, Any]:
    plan_id = _validate_plan_id(plan_id)
    copy_bytes = _root_copy_required_bytes(apt, snap)
    safety_margin_bytes = policy["staging"]["root_stage_safety_margin_bytes"] if copy_bytes else 0
    required_bytes = copy_bytes + safety_margin_bytes
    root_stage = _root_stage_root(policy) / plan_id
    runtime_capture = _runtime_capture_root(policy) / plan_id
    return {
        "root_stage": str(root_stage),
        "runtime_capture_path": str(runtime_capture),
        "root_copy_required_bytes": copy_bytes,
        "root_stage_safety_margin_bytes": safety_margin_bytes,
        "root_capacity_required_bytes": required_bytes,
        "root_capacity_prepare_argv": _root_capacity_prepare_argv(policy) if copy_bytes else None,
        "root_capacity_argv": _root_capacity_argv(policy) if copy_bytes else None,
        "capacity_readback_required": bool(copy_bytes),
        "apply_readback_required": bool(copy_bytes),
        "cleanup_argv": ["/usr/bin/rm", "-rf", "--", str(root_stage)],
        "cleanup_runtime_capture_argv": ["/usr/bin/rm", "-rf", "--", str(runtime_capture)],
    }


def _copy_commands(plan: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    commands = plan["root_commands"]
    stage = Path(plan["stage_path"])
    root_stage = Path(commands["root_stage"])
    root_debs = root_stage / "debs"
    root_snaps = root_stage / "snaps"
    runtime_capture = Path(commands["runtime_capture_path"])
    apt_sources = [str(_stage_artifact_path(stage, item.get("relative_path"), stage / "apt" / "debs")) for item in plan["apt"].get("packages", [])]
    apt_destinations = [str(root_debs / Path(item["relative_path"]).name) for item in plan["apt"].get("packages", [])]
    snap_sources: list[str] = []
    snap_destinations: list[str] = []
    for item in plan["snap"].get("packages", []):
        for key in ("assert_relative_path", "snap_relative_path"):
            source = _stage_artifact_path(stage, item.get(key), stage / "snap")
            snap_sources.append(str(source)); snap_destinations.append(str(root_snaps / source.name))
    hash_destinations = [*apt_destinations, *snap_destinations]
    return {
        "prepare_argv": ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0711", str(root_stage), str(root_debs), str(root_snaps), str(runtime_capture)],
        "copy_apt_argv": ["/usr/bin/install", "-o", "root", "-g", "root", "-m", "0600", *apt_sources, str(root_debs)] if apt_sources else None,
        "copy_snap_argv": ["/usr/bin/install", "-o", "root", "-g", "root", "-m", "0600", *snap_sources, str(root_snaps)] if snap_sources else None,
        "hash_argv": ["/usr/bin/sha256sum", *hash_destinations] if hash_destinations else None,
    }


def _apt_apply_preflight_argv(plan: dict[str, Any]) -> list[str] | None:
    root_deb_paths = _root_apt_deb_paths(plan)
    if not root_deb_paths:
        return None
    argv = [
        "/usr/bin/dpkg", "--simulate", "--refuse-downgrade", "--force-confold",
        "--install", *[str(path) for path in root_deb_paths],
    ]
    if len(argv) > 128:
        raise PlanError("APT preflight argv exceeds privileged broker item limit")
    return argv


def _apply_commands(plan: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    commands = plan["root_commands"]
    root_stage = Path(commands["root_stage"])
    root_snaps = root_stage / "snaps"
    root_deb_paths = _root_apt_deb_paths(plan)
    apt_apply = None
    if root_deb_paths:
        apt_apply = _apt_apply_systemd_argv(
            plan["plan_id"], root_deb_paths, Path(commands["runtime_capture_path"])
        )
    snap_apply: list[list[str]] = []
    for item in plan["snap"].get("packages", []):
        assertion = str(root_snaps / Path(item["assert_relative_path"]).name)
        snap_file = str(root_snaps / Path(item["snap_relative_path"]).name)
        snap_apply.append(["/usr/bin/snap", "ack", assertion])
        snap_apply.append(["/usr/bin/snap", "install", snap_file])
    for argv in snap_apply:
        if "--dangerous" in argv:
            raise PlanError("dangerous snap installation is forbidden")
    return {
        "apt_apply_argv": apt_apply,
        "snap_apply_argvs": snap_apply,
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
    policy_path = _require_canonical_policy_path(policy_path)
    policy = load_policy(policy_path)
    uid = os.geteuid()
    runtime_root = _expand_runtime_root(policy, uid)
    _require_broker_handoff_binding(policy)
    _ensure_private_dir(runtime_root, uid)
    plan_id = _validate_plan_id(f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(6)}")
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
            "apt_apply_host_ipc_capable": False,
            "apt_apply_runtime_namespace": "persistent-private-run-capture-private-network",
            "apt_apply_reboot_capture": True,
            "apt_apply_kernel_device_isolation": True,
            "copy_commands_embedded_in_plan": False,
            "copy_requires_root_capacity_readback": True,
            "apply_commands_embedded_in_plan": False,
            "apply_requires_root_hash_readback": True,
            "apt_apply_engine": "dpkg-explicit-root-stage",
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
        "root_capacity_prepare_argv": commands["root_capacity_prepare_argv"],
        "root_capacity_argv": commands["root_capacity_argv"],
        "root_capacity_required_bytes": commands["root_capacity_required_bytes"],
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
        path = _stage_artifact_path(stage, item.get("relative_path"), stage / "apt" / "debs")
        info = _regular_owned_file(path, uid)
        if info.st_size != item["size"] or _sha256_file(path) != item["sha256"]:
            raise PlanError(f"APT artifact changed: {path}")
    for item in plan["snap"].get("packages", []):
        for rel_key, hash_key, size_key in (
            ("assert_relative_path", "assert_sha256", "assert_size"),
            ("snap_relative_path", "snap_sha256", "snap_size"),
        ):
            path = _stage_artifact_path(stage, item.get(rel_key), stage / "snap")
            info = _regular_owned_file(path, uid)
            if info.st_size != item[size_key] or _sha256_file(path) != item[hash_key]:
                raise PlanError(f"snap artifact changed: {path}")


def _validate_plan_identity(
    plan_path: Path, confirmation: str
) -> tuple[dict[str, Any], dict[str, Any], Path, int]:
    if os.geteuid() == 0:
        raise PlanError("package plan verification/postflight must run unprivileged")
    plan = _read_json(plan_path)
    if plan.get("schema_version") != 1 or plan.get("kind") != PLAN_KIND:
        raise PlanError("plan schema or kind mismatch")
    _validate_confirmation(plan, confirmation)
    plan_id = _validate_plan_id(plan.get("plan_id"))
    policy_path = _require_canonical_policy_path(Path(plan["policy_path"]))
    expected_policy_sha256 = plan.get("policy_sha256")
    if not isinstance(expected_policy_sha256, str) or SHA256_RE.fullmatch(expected_policy_sha256) is None:
        raise PlanError("plan policy digest is missing or invalid")
    policy_sha256_before = _sha256_file(policy_path)
    if policy_sha256_before != expected_policy_sha256:
        raise PlanError("package update policy changed after planning")
    policy = load_policy(policy_path)
    if _sha256_file(policy_path) != policy_sha256_before:
        raise PlanError("package update policy changed while loading plan identity")
    uid = os.geteuid()
    runtime_root = _expand_runtime_root(policy, uid)
    expected_stage = runtime_root / plan_id
    stage = Path(plan.get("stage_path", ""))
    if stage != expected_stage:
        raise PlanError("plan stage does not match canonical runtime_root/plan_id")
    if plan_path != stage / "plan.json" or plan_path.is_symlink():
        raise PlanError("plan must use its canonical non-symlink stage plan.json path")
    _regular_owned_file(plan_path, uid)
    baseline = plan.get("baseline")
    if not isinstance(baseline, dict) or baseline.get("uid") != uid:
        raise PlanError("plan baseline uid differs from current uid")
    _require_broker_handoff_binding(policy)
    expected_artifacts = plan.get("root_artifact_sha256")
    if expected_artifacts != _artifact_expectations(plan):
        raise PlanError("root artifact expectation map is inconsistent")
    commands = plan.get("root_commands")
    if not isinstance(commands, dict):
        raise PlanError("root_commands must be an object")
    expected_commands = _root_commands(plan_id, stage, policy, plan["apt"], plan["snap"])
    if commands != expected_commands:
        raise PlanError("root command set is inconsistent with the current policy and exact plan artifacts")
    forbidden_embedded = {
        "prepare_argv", "copy_apt_argv", "copy_snap_argv",
        "hash_apt_argv", "hash_snap_argv", "hash_argv", "apt_apply_preflight_argv",
        "apt_apply_argv", "snap_apply_argvs",
    }
    embedded = sorted(forbidden_embedded.intersection(commands))
    if embedded:
        raise PlanError(f"copy/apply commands must not be embedded in a package plan: {embedded}")
    return plan, policy, stage, uid


def _verify_plan_loaded(
    plan_path: Path, confirmation: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    plan, policy, stage, uid = _validate_plan_identity(plan_path, confirmation)
    age = int(time.time()) - int(plan["created_at_unix"])
    if age < 0 or age > policy["staging"]["max_plan_age_seconds"]:
        raise PlanError(f"plan age {age}s exceeds policy limit")
    if _dpkg_status_sha256() != plan["baseline"]["dpkg_status_sha256"]:
        raise PlanError("dpkg status changed after planning")
    _validate_source_config(plan["baseline"]["apt_source_config"])
    if uid != plan["baseline"]["uid"]:
        raise PlanError("verification uid differs from plan uid")
    _require_broker_handoff_binding(policy)
    _validate_stage_artifacts(plan, uid, policy)
    _revalidate_apt_provenance(stage, plan, policy, uid)
    _revalidate_snap_provenance(stage, plan, policy, uid)
    for item in plan["snap"].get("packages", []):
        if _snap_installed_revision(item["name"]) != item["baseline_revision"]:
            raise PlanError(f"installed snap revision changed after planning: {item['name']}")
    commands = plan["root_commands"]
    result = {
        "status": "verified",
        "plan_path": str(plan_path),
        "plan_sha256": plan["plan_sha256"],
        "age_seconds": age,
        "root_artifact_sha256": plan["root_artifact_sha256"],
        "root_capacity": {
            "required": bool(commands.get("capacity_readback_required")),
            "prepare_argv": commands.get("root_capacity_prepare_argv"),
            "argv": commands.get("root_capacity_argv"),
            "copy_bytes": commands.get("root_copy_required_bytes", 0),
            "safety_margin_bytes": commands.get("root_stage_safety_margin_bytes", 0),
            "required_bytes": commands.get("root_capacity_required_bytes", 0),
        },
        "sensitive_apt_packages": [
            item["name"] for item in plan["apt"].get("packages", []) if item.get("sensitive")
        ],
        "does_not_establish": [
            "root copy authorization before root capacity readback",
            "root artifact copy integrity before root hash readback",
            "privileged apply completion",
            "postflight service health",
        ],
    }
    return result, plan, policy


def verify_plan(plan_path: Path, confirmation: str) -> dict[str, Any]:
    result, _plan, _policy = _verify_plan_loaded(plan_path, confirmation)
    return result


def root_capacity_authorize(
    plan_path: Path, confirmation: str, root_capacity_output: str, broker_evidence_path: Path
) -> dict[str, Any]:
    verified, plan, policy = _verify_plan_loaded(plan_path, confirmation)
    commands = plan["root_commands"]
    if not commands.get("capacity_readback_required"):
        raise PlanError("root capacity authorization is unnecessary when no package artifacts are planned")
    required_bytes = commands.get("root_capacity_required_bytes")
    copy_bytes = commands.get("root_copy_required_bytes")
    safety_margin_bytes = commands.get("root_stage_safety_margin_bytes")
    if not all(isinstance(value, int) and value >= 0 for value in (required_bytes, copy_bytes, safety_margin_bytes)):
        raise PlanError("root capacity byte bindings are missing or invalid")
    if required_bytes != copy_bytes + safety_margin_bytes:
        raise PlanError("root capacity requirement does not equal artifact bytes plus safety margin")
    evidence = _validate_broker_output_evidence(
        broker_evidence_path,
        expected_argv=commands["root_capacity_argv"],
        stdout_text=root_capacity_output,
        expected_peer_uid=int(plan["baseline"]["uid"]),
        not_before_unix=int(plan["created_at_unix"]),
        max_age_seconds=policy["staging"]["privileged_readback_max_age_seconds"],
    )
    capacity = parse_root_capacity_readback(root_capacity_output, required_bytes)
    copy_commands = _copy_commands(plan, policy)
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": "heim_pc.staged_package_update_root_capacity",
        "plan_id": plan["plan_id"],
        "plan_sha256": plan["plan_sha256"],
        "root_capacity_prepare_argv": commands.get("root_capacity_prepare_argv"),
        "root_capacity_argv": commands.get("root_capacity_argv"),
        "root_copy_bytes": copy_bytes,
        "safety_margin_bytes": safety_margin_bytes,
        "required_bytes": required_bytes,
        "available_bytes": capacity["available_bytes"],
        "root_capacity_output": root_capacity_output,
        "broker_output_evidence": evidence,
        "copy_commands": copy_commands,
        "status": "root-capacity-authorized",
        "does_not_establish": [
            "future root-filesystem capacity",
            "root artifact copy completion",
            "root artifact hash correctness",
            "privileged apply completion",
        ],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    receipt_path = Path(plan["stage_path"]) / "root-capacity.json"
    _atomic_json(receipt_path, receipt)
    return {**receipt, "receipt_path": str(receipt_path), "verify_age_seconds": verified["age_seconds"]}


def _validate_root_capacity_receipt(
    plan: dict[str, Any], policy: dict[str, Any], uid: int
) -> dict[str, Any]:
    commands = plan["root_commands"]
    if not commands.get("capacity_readback_required"):
        return {"status": "not-required", "copy_commands": _copy_commands(plan, policy)}
    receipt_path = Path(plan["stage_path"]) / "root-capacity.json"
    receipt = _read_json(receipt_path)
    _regular_owned_file(receipt_path, uid)
    if receipt.get("schema_version") != 1 or receipt.get("kind") != "heim_pc.staged_package_update_root_capacity":
        raise PlanError("root capacity receipt schema or kind mismatch")
    if receipt.get("status") != "root-capacity-authorized":
        raise PlanError("root capacity receipt is not authorized")
    if receipt.get("plan_id") != plan["plan_id"] or receipt.get("plan_sha256") != plan["plan_sha256"]:
        raise PlanError("root capacity receipt is bound to a different plan")
    expected = {
        "root_capacity_prepare_argv": commands.get("root_capacity_prepare_argv"),
        "root_capacity_argv": commands.get("root_capacity_argv"),
        "root_copy_bytes": commands.get("root_copy_required_bytes"),
        "safety_margin_bytes": commands.get("root_stage_safety_margin_bytes"),
        "required_bytes": commands.get("root_capacity_required_bytes"),
        "copy_commands": _copy_commands(plan, policy),
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise PlanError(f"root capacity receipt binding changed: {key}")
    root_capacity_output = receipt.get("root_capacity_output")
    broker_output_evidence = receipt.get("broker_output_evidence")
    if not isinstance(root_capacity_output, str) or not isinstance(broker_output_evidence, dict):
        raise PlanError("root capacity receipt lacks authenticated broker output evidence")
    evidence = _validate_broker_output_evidence(
        Path(str(broker_output_evidence.get("path", ""))),
        expected_argv=commands["root_capacity_argv"],
        stdout_text=root_capacity_output,
        expected_peer_uid=int(plan["baseline"]["uid"]),
        not_before_unix=int(plan["created_at_unix"]),
        max_age_seconds=policy["staging"]["privileged_readback_max_age_seconds"],
    )
    if evidence != broker_output_evidence:
        raise PlanError("root capacity receipt broker evidence binding changed")
    parse_root_capacity_readback(root_capacity_output, int(receipt["required_bytes"]))
    if not isinstance(receipt.get("available_bytes"), int) or receipt["available_bytes"] < receipt["required_bytes"]:
        raise PlanError("root capacity receipt no longer proves sufficient destination space")
    digest = receipt.get("receipt_sha256")
    unsigned = dict(receipt); unsigned.pop("receipt_sha256", None)
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None or _sha256_json(unsigned) != digest:
        raise PlanError("root capacity receipt content hash mismatch")
    return receipt


def _parse_sha256sum_output(text: str) -> dict[str, str]:
    observed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or SHA256_RE.fullmatch(parts[0]) is None:
            raise PlanError(f"unexpected sha256sum readback line: {line}")
        path = parts[1].lstrip("*").strip()
        if not path.startswith("/") or path in observed:
            raise PlanError(f"unsafe or duplicate root hash readback path: {path}")
        observed[path] = parts[0]
    return observed


def root_readback_authorize(
    plan_path: Path, confirmation: str, sha256sum_output: str, broker_evidence_path: Path
) -> dict[str, Any]:
    verified, plan, policy = _verify_plan_loaded(plan_path, confirmation)
    capacity_receipt = _validate_root_capacity_receipt(plan, policy, os.geteuid())
    hash_argv = _copy_commands(plan, policy).get("hash_argv")
    if not isinstance(hash_argv, list) or not hash_argv:
        raise PlanError("root hash authorization is unnecessary when no package artifacts are planned")
    evidence = _validate_broker_output_evidence(
        broker_evidence_path,
        expected_argv=hash_argv,
        stdout_text=sha256sum_output,
        expected_peer_uid=int(plan["baseline"]["uid"]),
        not_before_unix=int(plan["created_at_unix"]),
        max_age_seconds=policy["staging"]["privileged_readback_max_age_seconds"],
    )
    observed = _parse_sha256sum_output(sha256sum_output)
    expected = plan["root_artifact_sha256"]
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        mismatched = sorted(path for path in set(expected).intersection(observed) if expected[path] != observed[path])
        raise PlanError(
            f"root artifact hash readback mismatch missing={missing} extra={extra} mismatched={mismatched}"
        )
    apply_commands = _apply_commands(plan, policy)
    authorization: dict[str, Any] = {
        "schema_version": 1,
        "kind": "heim_pc.staged_package_update_root_readback",
        "plan_id": plan["plan_id"],
        "plan_sha256": plan["plan_sha256"],
        "root_artifact_sha256": observed,
        "root_readback_sha256": _sha256_json({
            "plan_sha256": plan["plan_sha256"], "root_artifact_sha256": observed
        }),
        "broker_output_evidence": evidence,
        "capacity_receipt_sha256": capacity_receipt.get("receipt_sha256"),
        "root_hash_output": sha256sum_output,
        "authorized_at_unix": int(time.time()),
        "apt_apply_preflight_argv": _apt_apply_preflight_argv(plan),
        "apply_commands": apply_commands,
        "status": "root-readback-authorized",
        "does_not_establish": ["privileged apply completion", "postflight service health"],
    }
    authorization["receipt_sha256"] = _sha256_json(authorization)
    receipt_path = Path(plan["stage_path"]) / "root-readback.json"
    _atomic_json(receipt_path, authorization)
    return {**authorization, "receipt_path": str(receipt_path), "verify_age_seconds": verified["age_seconds"]}


def _validate_root_readback_receipt(plan: dict[str, Any], policy: dict[str, Any], uid: int) -> dict[str, Any]:
    receipt_path = Path(plan["stage_path"]) / "root-readback.json"
    receipt = _read_json(receipt_path)
    _regular_owned_file(receipt_path, uid)
    if (receipt.get("schema_version") != 1 or receipt.get("kind") != "heim_pc.staged_package_update_root_readback" or receipt.get("status") != "root-readback-authorized" or receipt.get("plan_id") != plan["plan_id"] or receipt.get("plan_sha256") != plan["plan_sha256"] or receipt.get("root_artifact_sha256") != plan["root_artifact_sha256"] or receipt.get("apt_apply_preflight_argv") != _apt_apply_preflight_argv(plan) or receipt.get("apply_commands") != _apply_commands(plan, policy)):
        raise PlanError("root readback receipt binding is invalid")
    authorized_at = receipt.get("authorized_at_unix"); now = int(time.time())
    if isinstance(authorized_at, bool) or not isinstance(authorized_at, int) or authorized_at < int(plan["created_at_unix"]) or authorized_at > now + 5 or now - authorized_at > policy["staging"]["max_plan_age_seconds"]:
        raise PlanError("root readback receipt is stale or outside the plan lifetime")
    root_hash_output = receipt.get("root_hash_output"); broker_output_evidence = receipt.get("broker_output_evidence"); hash_argv = _copy_commands(plan, policy).get("hash_argv")
    if not isinstance(root_hash_output, str) or not isinstance(broker_output_evidence, dict) or not isinstance(hash_argv, list):
        raise PlanError("root readback receipt lacks authenticated hash evidence")
    evidence = _validate_broker_output_evidence(Path(str(broker_output_evidence.get("path", ""))), expected_argv=hash_argv, stdout_text=root_hash_output, expected_peer_uid=int(plan["baseline"]["uid"]), not_before_unix=int(plan["created_at_unix"]), max_age_seconds=policy["staging"]["max_plan_age_seconds"])
    if evidence != broker_output_evidence or _parse_sha256sum_output(root_hash_output) != plan["root_artifact_sha256"]:
        raise PlanError("root readback receipt authenticated hash binding changed")
    digest = receipt.get("receipt_sha256"); unsigned = dict(receipt); unsigned.pop("receipt_sha256", None)
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None or _sha256_json(unsigned) != digest:
        raise PlanError("root readback receipt content hash mismatch")
    return receipt


def _expected_apply_stage_paths(plan: dict[str, Any], argv: list[str]) -> list[str]:
    root_stage = str(Path(plan["root_commands"]["root_stage"])) + "/"
    paths = [value for value in argv if isinstance(value, str) and value.startswith(root_stage)]
    if not paths:
        raise PlanError("apply argv has no exact package-stage artifact path")
    return paths


def _read_broker_package_completion_evidence(
    evidence_path: Path, *, expected_owner_uid: int
) -> tuple[dict[str, Any], str]:
    if evidence_path.parent != BROKER_OUTPUT_EVIDENCE_ROOT:
        raise PlanError("package completion evidence path is outside the canonical evidence root")
    root_info = BROKER_OUTPUT_EVIDENCE_ROOT.lstat()
    info = evidence_path.lstat()
    if (
        BROKER_OUTPUT_EVIDENCE_ROOT.is_symlink()
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != expected_owner_uid
        or stat.S_IMODE(root_info.st_mode) & 0o022
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_owner_uid
        or stat.S_IMODE(info.st_mode) != 0o640
        or info.st_nlink != 1
    ):
        raise PlanError("package completion evidence path is not trusted")
    value = _read_json(evidence_path, max_bytes=64 * 1024)
    request_id = value.get("request_id")
    if (
        not isinstance(request_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", request_id) is None
        or evidence_path.name != f"{request_id}.json"
    ):
        raise PlanError("package completion evidence request identity is invalid")
    return value, request_id


def _validate_broker_preflight_evidence(
    evidence_path: Path, *, expected_argv: list[str], plan: dict[str, Any],
    guard_evidence_sha256: str, not_before_unix: int, max_age_seconds: int,
    expected_owner_uid: int = 0,
) -> dict[str, Any]:
    value, request_id = _read_broker_package_completion_evidence(
        evidence_path, expected_owner_uid=expected_owner_uid
    )
    expected_paths = _expected_apply_stage_paths(plan, expected_argv)
    if (
        value.get("schema_version") != 1
        or value.get("kind") != BROKER_OUTPUT_EVIDENCE_KIND
        or value.get("action") != BROKER_POWER_ACTION
        or value.get("mode") != "argv-json"
        or value.get("peer_uid") != int(plan["baseline"]["uid"])
        or value.get("peer_unit") != BROKER_PEER_UNIT
        or value.get("returncode") != 0
        or value.get("timed_out") is not False
        or value.get("stdout_truncated") is not False
        or value.get("stderr_truncated") is not False
        or value.get("package_preflight_completed") is not True
        or value.get("package_operation") != "apt_preflight"
        or value.get("package_exact_evidence") is not True
        or value.get("package_plan_id") != plan["plan_id"]
        or value.get("package_paths") != expected_paths
        or value.get("package_preflight_guard_evidence_sha256") != guard_evidence_sha256
    ):
        raise PlanError("APT preflight evidence identity, plan binding or execution status is invalid")
    for key in ("reference_sha256", "argv_sha256", "cwd_sha256", "stdout_sha256", "evidence_sha256"):
        if not isinstance(value.get(key), str) or SHA256_RE.fullmatch(value[key]) is None:
            raise PlanError(f"APT preflight evidence {key} is invalid")
    if value["argv_sha256"] != _sha256_json(expected_argv):
        raise PlanError("APT preflight evidence is bound to different argv")
    timestamp = value.get("timestamp_unix")
    now = int(time.time())
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or timestamp < not_before_unix
        or timestamp > now + 5
        or now - timestamp > max_age_seconds
    ):
        raise PlanError("APT preflight evidence is stale or predates root authorization")
    digest = value["evidence_sha256"]
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if _sha256_json(unsigned) != digest:
        raise PlanError("APT preflight evidence content hash mismatch")
    return {
        "path": str(evidence_path),
        "request_id": request_id,
        "evidence_sha256": digest,
        "argv_sha256": value["argv_sha256"],
        "timestamp_unix": timestamp,
    }


def _validate_broker_apply_evidence(
    evidence_path: Path, *, expected_argv: list[str], expected_operation: str,
    plan: dict[str, Any], guard_evidence_sha256: str, not_before_unix: int,
    max_age_seconds: int, expected_preflight_evidence_sha256: str | None = None,
    preflight_timestamp_unix: int | None = None, expected_owner_uid: int = 0,
) -> dict[str, Any]:
    value, request_id = _read_broker_package_completion_evidence(
        evidence_path, expected_owner_uid=expected_owner_uid
    )
    expected_paths = _expected_apply_stage_paths(plan, expected_argv)
    if (
        value.get("schema_version") != 1
        or value.get("kind") != BROKER_OUTPUT_EVIDENCE_KIND
        or value.get("action") != BROKER_POWER_ACTION
        or value.get("mode") != "argv-json"
        or value.get("peer_uid") != int(plan["baseline"]["uid"])
        or value.get("peer_unit") != BROKER_PEER_UNIT
        or value.get("returncode") != 0
        or value.get("timed_out") is not False
        or value.get("stdout_truncated") is not False
        or value.get("stderr_truncated") is not False
        or value.get("package_apply_completed") is not True
        or value.get("package_operation") != expected_operation
        or value.get("package_exact_evidence") is not True
        or value.get("package_plan_id") != plan["plan_id"]
        or value.get("package_paths") != expected_paths
        or value.get("package_apply_guard_evidence_sha256") != guard_evidence_sha256
    ):
        raise PlanError("package apply evidence identity, plan binding or execution status is invalid")
    if expected_operation == "apt_apply":
        if (
            not isinstance(expected_preflight_evidence_sha256, str)
            or SHA256_RE.fullmatch(expected_preflight_evidence_sha256) is None
            or value.get("package_apply_preflight_evidence_sha256")
            != expected_preflight_evidence_sha256
            or isinstance(preflight_timestamp_unix, bool)
            or not isinstance(preflight_timestamp_unix, int)
        ):
            raise PlanError("APT apply evidence lacks the authenticated preflight binding")
    for key in ("reference_sha256", "argv_sha256", "cwd_sha256", "stdout_sha256", "evidence_sha256"):
        if not isinstance(value.get(key), str) or SHA256_RE.fullmatch(value[key]) is None:
            raise PlanError(f"package apply evidence {key} is invalid")
    if value["argv_sha256"] != _sha256_json(expected_argv):
        raise PlanError("package apply evidence is bound to different argv")
    timestamp = value.get("timestamp_unix")
    now = int(time.time())
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or timestamp < not_before_unix
        or timestamp > now + 5
        or now - timestamp > max_age_seconds
        or (
            expected_operation == "apt_apply"
            and isinstance(preflight_timestamp_unix, int)
            and timestamp < preflight_timestamp_unix
        )
    ):
        raise PlanError("package apply evidence is stale or predates required authorization")
    digest = value["evidence_sha256"]
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if _sha256_json(unsigned) != digest:
        raise PlanError("package apply evidence content hash mismatch")
    return {
        "path": str(evidence_path),
        "request_id": request_id,
        "evidence_sha256": digest,
        "argv_sha256": value["argv_sha256"],
        "timestamp_unix": timestamp,
        "package_operation": expected_operation,
    }


def _validate_postflight_authorization(
    plan: dict[str, Any], policy: dict[str, Any], uid: int,
    apply_evidence_paths: list[Path], apt_preflight_evidence_path: Path | None = None,
) -> dict[str, Any]:
    age = int(time.time()) - int(plan["created_at_unix"])
    apply_commands = _apply_commands(plan, policy)
    apt_apply_argv = apply_commands.get("apt_apply_argv")
    snap_apply_argvs = list(apply_commands.get("snap_apply_argvs", []))
    expected_specs: list[tuple[list[str], str]] = []
    if isinstance(apt_apply_argv, list):
        expected_specs.append((apt_apply_argv, "apt_apply"))
    for argv in snap_apply_argvs:
        if argv[:2] == ["/usr/bin/snap", "ack"]:
            operation = "snap_ack"
        elif argv[:2] == ["/usr/bin/snap", "install"]:
            operation = "snap_install"
        else:
            raise PlanError("unexpected Snap apply argv in verified plan")
        expected_specs.append((argv, operation))
    if age < 0 or age > policy["staging"]["max_plan_age_seconds"]:
        raise PlanError(f"postflight plan age {age}s exceeds policy limit")
    if not expected_specs:
        if apply_evidence_paths or apt_preflight_evidence_path is not None:
            raise PlanError("postflight received completion evidence for a plan with no package apply")
        return {"status": "not-required", "apt_preflight_evidence": None, "apply_evidence": []}
    root_readback = _validate_root_readback_receipt(plan, policy, uid)
    guard_sha = root_readback["broker_output_evidence"]["evidence_sha256"]
    preflight_summary: dict[str, Any] | None = None
    if isinstance(apt_apply_argv, list):
        preflight_argv = root_readback.get("apt_apply_preflight_argv")
        if not isinstance(preflight_argv, list) or apt_preflight_evidence_path is None:
            raise PlanError("postflight requires authenticated successful APT preflight evidence")
        preflight_summary = _validate_broker_preflight_evidence(
            apt_preflight_evidence_path,
            expected_argv=preflight_argv,
            plan=plan,
            guard_evidence_sha256=guard_sha,
            not_before_unix=int(root_readback["authorized_at_unix"]),
            max_age_seconds=policy["staging"]["max_plan_age_seconds"],
        )
    elif apt_preflight_evidence_path is not None:
        raise PlanError("postflight received APT preflight evidence for a plan without APT apply")
    if len(apply_evidence_paths) != len(expected_specs):
        raise PlanError("postflight requires one authenticated completion evidence file per apply argv")
    summaries: list[dict[str, Any]] = []
    for path, (argv, operation) in zip(apply_evidence_paths, expected_specs, strict=True):
        summaries.append(_validate_broker_apply_evidence(
            path,
            expected_argv=argv,
            expected_operation=operation,
            plan=plan,
            guard_evidence_sha256=guard_sha,
            not_before_unix=int(root_readback["authorized_at_unix"]),
            max_age_seconds=policy["staging"]["max_plan_age_seconds"],
            expected_preflight_evidence_sha256=(
                preflight_summary["evidence_sha256"]
                if operation == "apt_apply" and preflight_summary is not None
                else None
            ),
            preflight_timestamp_unix=(
                int(preflight_summary["timestamp_unix"])
                if operation == "apt_apply" and preflight_summary is not None
                else None
            ),
        ))
    return {
        "status": "authenticated-apply-complete",
        "root_readback_receipt_sha256": root_readback["receipt_sha256"],
        "apt_preflight_evidence": preflight_summary,
        "apply_evidence": summaries,
    }


def _dpkg_state(name: str, arch: str | None = None) -> dict[str, str] | None:
    query_name = name if ":" in name or not arch else f"{name}:{arch}"
    result = _run(
        ["/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "-W", "-f=${Version}\t${Status}\n", query_name],
        check=False, env=_host_dpkg_env(),
    )
    if result["returncode"] != 0:
        return None
    rows = [line.rstrip("\n") for line in result["stdout"].splitlines() if line.strip()]
    if len(rows) != 1 or "\t" not in rows[0]:
        return None
    version, status = rows[0].split("\t", 1)
    if not version or not status:
        return None
    return {"version": version, "status": status}


def _dpkg_version(name: str, arch: str | None = None) -> str | None:
    state = _dpkg_state(name, arch)
    return state["version"] if state is not None else None


def _service_state(unit: str, *, user: bool) -> str:
    argv = ["/usr/bin/systemctl"]
    if user:
        argv.append("--user")
    argv.extend(["is-active", unit])
    result = _run(argv, check=False, env=_host_readback_env(user=user))
    return result["stdout"].strip() or f"rc={result['returncode']}"


def postflight(
    plan_path: Path, confirmation: str, apply_evidence_paths: list[Path] | None = None,
    apt_preflight_evidence_path: Path | None = None,
) -> dict[str, Any]:
    plan, policy, _stage, _uid = _validate_plan_identity(plan_path, confirmation)
    apply_authorization = _validate_postflight_authorization(
        plan, policy, _uid, apply_evidence_paths or [], apt_preflight_evidence_path
    )
    apt_results: list[dict[str, Any]] = []
    for item in plan["apt"].get("packages", []):
        installed = _dpkg_state(item["name"], item.get("arch"))
        installed_version = installed.get("version") if installed is not None else None
        installed_status = installed.get("status") if installed is not None else None
        apt_results.append({
            "name": item["name"],
            "arch": item.get("arch"),
            "expected_version": item["version"],
            "installed_version": installed_version,
            "installed_status": installed_status,
            "matched": (
                installed_version == item["version"]
                and installed_status == "install ok installed"
            ),
        })
    dpkg_audit = _run(["/usr/bin/dpkg", "--admindir=/var/lib/dpkg", "--audit"], check=False, env=_host_dpkg_env())
    dpkg_audit_ok = (
        dpkg_audit["returncode"] == 0
        and not dpkg_audit["stdout"].strip()
        and not dpkg_audit["stderr"].strip()
    )
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
    ], check=False, env=_host_readback_env())
    all_system_services_active = all(state == "active" for state in system_services.values())
    all_user_services_active = all(state == "active" for state in user_services.values())
    nvidia_smi_ok = nvidia["returncode"] == 0 and bool(nvidia["stdout"].strip())
    host_reboot_required = Path("/var/run/reboot-required").exists()
    isolated_reboot_required = False
    runtime_capture_path: Path | None = None
    if plan["apt"].get("packages"):
        raw_capture = plan.get("root_commands", {}).get("runtime_capture_path")
        if not isinstance(raw_capture, str) or not raw_capture:
            raise PlanError("APT postflight is missing the private runtime capture path")
        runtime_capture_path = Path(raw_capture)
        info = runtime_capture_path.lstat() if runtime_capture_path.exists() else None
        if info is None or not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise PlanError("APT private runtime capture is missing or unsafe; reboot evidence is incomplete")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise PlanError("APT private runtime capture is writable by non-owner principals")
        isolated_reboot_required = (runtime_capture_path / "reboot-required").exists()
    reboot_marker_capable_packages = [
        item["name"] for item in plan["apt"].get("packages", [])
        if item.get("reboot_marker_capable") is True
    ]
    conservative_reboot_required = bool(reboot_marker_capable_packages) and not isolated_reboot_required
    reboot_required_sources: list[str] = []
    if host_reboot_required:
        reboot_required_sources.append("host-marker")
    if isolated_reboot_required:
        reboot_required_sources.append("isolated-apt-runtime-marker")
    if conservative_reboot_required:
        reboot_required_sources.append("planned-reboot-marker-capable-package")
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
        "dpkg_audit_ok": dpkg_audit_ok,
        "dpkg_audit_stdout_sha256": _sha256_bytes(dpkg_audit["stdout"].encode()),
        "dpkg_audit_stderr_sha256": _sha256_bytes(dpkg_audit["stderr"].encode()),
        "apply_authorization": apply_authorization,
        "all_system_services_active": all_system_services_active,
        "all_user_services_active": all_user_services_active,
        "service_liveness_established": all_system_services_active and all_user_services_active,
        "service_restart_established": not bool(apt_results or snap_results),
        "new_code_activation_established": not bool(apt_results or snap_results),
        "activation_observation": "not-applicable" if not (apt_results or snap_results) else "not-established-by-isolated-package-apply",
        "nvidia_smi_ok": nvidia_smi_ok,
        "reboot_required": bool(reboot_required_sources),
        "reboot_required_sources": reboot_required_sources,
        "reboot_marker_capable_packages": reboot_marker_capable_packages,
        "runtime_capture_path": str(runtime_capture_path) if runtime_capture_path is not None else None,
        "system_services": system_services,
        "user_services": user_services,
        "nvidia_smi": nvidia["stdout"].strip() if nvidia_smi_ok else None,
        "does_not_establish": [
            "future package repository freshness",
            "future service health",
            "reboot completion when reboot_required is true",
            "service restart or new-code activation for planned package updates",
        ],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    receipt_path = Path(plan["stage_path"]) / "postflight.json"
    _atomic_json(receipt_path, receipt)
    if not receipt["all_apt_matched"] or not receipt["all_snap_matched"]:
        raise PlanError(f"postflight target mismatch; receipt={receipt_path}")
    if not receipt["dpkg_audit_ok"]:
        raise PlanError(f"postflight dpkg audit mismatch; receipt={receipt_path}")
    if not receipt["all_system_services_active"] or not receipt["all_user_services_active"]:
        raise PlanError(f"postflight service health mismatch; receipt={receipt_path}")
    if not receipt["nvidia_smi_ok"]:
        raise PlanError(f"postflight NVIDIA health mismatch; receipt={receipt_path}")
    return {**receipt, "receipt_path": str(receipt_path)}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stage and verify hash-bound Heim-PC package updates.")
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="Refresh and download artifacts unprivileged; create a non-authorizing plan.")
    verify = sub.add_parser("verify", help="Verify exact plan, live preconditions and staged artifacts.")
    verify.add_argument("--plan", type=Path, required=True)
    verify.add_argument("--confirmation", required=True)
    capacity = sub.add_parser("capacity", help="Release root copy argv only after destination-filesystem capacity readback.")
    capacity.add_argument("--plan", type=Path, required=True)
    capacity.add_argument("--confirmation", required=True)
    capacity.add_argument("--root-capacity-output", required=True)
    capacity.add_argument("--broker-evidence", type=Path, required=True)
    readback = sub.add_parser("readback", help="Authorize apply argv only after exact root-owned sha256sum readback.")
    readback.add_argument("--plan", type=Path, required=True)
    readback.add_argument("--confirmation", required=True)
    readback.add_argument("--sha256sum-output", required=True)
    readback.add_argument("--broker-evidence", type=Path, required=True)
    post = sub.add_parser("postflight", help="Verify authenticated apply completion, installed state and service health.")
    post.add_argument("--plan", type=Path, required=True)
    post.add_argument("--confirmation", required=True)
    post.add_argument(
        "--apt-preflight-evidence", type=Path,
        help="Root-owned Grabowski evidence for the exact successful dpkg --simulate preflight.",
    )
    post.add_argument("--apply-evidence", type=Path, action="append", default=[])
    return parser


def main() -> int:
    if not sys.flags.isolated:
        print(json.dumps({"status": "blocked", "error": "staged package update CLI requires isolated Python (-I)"}, sort_keys=True))
        return 2
    if len(sys.argv) > 1 and sys.argv[1] == "__snap-quota-worker":
        try: return _snap_quota_worker(sys.argv[2:])
        except (PlanError, OSError) as exc:
            print(str(exc), file=sys.stderr); return 2
    args = _build_parser().parse_args()
    try:
        if args.command == "plan":
            result = create_plan(args.policy)
        elif args.command == "verify":
            result = verify_plan(args.plan, args.confirmation)
        elif args.command == "capacity":
            result = root_capacity_authorize(args.plan, args.confirmation, args.root_capacity_output, args.broker_evidence)
        elif args.command == "readback":
            result = root_readback_authorize(
                args.plan, args.confirmation, args.sha256sum_output, args.broker_evidence
            )
        elif args.command == "postflight":
            result = postflight(
                args.plan, args.confirmation, args.apply_evidence, args.apt_preflight_evidence
            )
        else:
            raise PlanError("unsupported command")
    except (PolicyError, PlanError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
