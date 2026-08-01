#!/usr/bin/env python3
"""Plan or transactionally install persistent Heim-PC host-health files."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET_ROOT = Path("/")
LOCK_RELATIVE = "var/lib/heim-pc/host-health/install.lock"
BACKUP_ROOT_RELATIVE = "var/lib/heim-pc/host-health/install-backups"
RECEIPT_RELATIVE = "var/lib/heim-pc/host-health/install-receipt.v3.json"
STRICT_PROFILE = "/usr/local/libexec/heim-pc/ensure-performance-profile"
FLUIDSYNTH_USER = "alex"
FLUIDSYNTH_EXEC_START = "/usr/bin/fluidsynth -is $OTHER_OPTS $SOUND_FONT"
FLUIDSYNTH_SERVICE_TYPE = "notify"
FLUIDSYNTH_NOTIFY_ACCESS = "main"
FLUIDSYNTH_LOG_RATE_LIMIT_INTERVAL = "30s"
FLUIDSYNTH_LOG_RATE_LIMIT_BURST = "200"
COMMIT_POINT = (
    "all_target_operations_fsynced_exactly_read_back_and_"
    "effective_systemd_composition_verified"
)
RESIDUE_TOKEN = re.compile(r"^[0-9a-f]{16}$")

FILES = (
    ("config/host-health-remediation.v1.json", "etc/heim-pc/host-health-remediation.v1.json", 0o644),
    ("scripts/ensure_performance_profile.py", "usr/local/libexec/heim-pc/ensure-performance-profile", 0o755),
    ("scripts/host_health_diagnostics.py", "usr/local/sbin/heim-pc-host-health", 0o755),
    ("systemd/system/cpu-governor.service", "etc/systemd/system/cpu-governor.service", 0o644),
    (
        "systemd/system/cpu-governor.service.d/zz-heim-pc-strict-profile.conf",
        "etc/systemd/system/cpu-governor.service.d/zz-heim-pc-strict-profile.conf",
        0o644,
    ),
    (
        "systemd/system/heim-pc-mce-edac-monitor.service",
        "etc/systemd/system/heim-pc-mce-edac-monitor.service",
        0o644,
    ),
    (
        "systemd/system/heim-pc-mce-edac-monitor.timer",
        "etc/systemd/system/heim-pc-mce-edac-monitor.timer",
        0o644,
    ),
    (
        "systemd/journald.conf.d/zz-heim-pc-retention.conf",
        "etc/systemd/journald.conf.d/zz-heim-pc-retention.conf",
        0o644,
    ),
    (
        "systemd/user/fluidsynth.service.d/zz-heim-pc-interactive-user.conf",
        "etc/systemd/user/fluidsynth.service.d/zz-heim-pc-interactive-user.conf",
        0o644,
    ),
)

REMOVALS = (
    "etc/systemd/journald.conf.d/50-heim-pc-retention.conf",
    "etc/systemd/journald.conf.d/99-heim-pc-retention.conf",
    "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf",
    "usr/local/sbin/heim-pc-set-performance-profile",
    "etc/systemd/user/fluidsynth.service.d/10-interactive-user.conf",
    "etc/systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf",
    "etc/systemd/user/fluidsynth.service.d/zz-heim-pc-gdm-guard.conf",
)

KNOWN_LEGACY_PROFILE_SCRIPT = b"""#!/usr/bin/python3
import subprocess
import sys

setter = subprocess.run(
    ["/usr/bin/system76-power", "profile", "performance"],
    text=True,
    capture_output=True,
    check=False,
)
probe = subprocess.run(
    ["/usr/bin/system76-power", "profile"],
    text=True,
    capture_output=True,
    check=False,
)
if probe.returncode == 0 and probe.stdout.strip() == "Power Profile: Performance":
    if setter.returncode != 0:
        detail = " ".join((setter.stderr or setter.stdout).split())
        print(
            f"system76-power setter returned {setter.returncode}, but verified final profile is Performance: {detail}",
            file=sys.stderr,
        )
    raise SystemExit(0)

for label, result in (("setter", setter), ("probe", probe)):
    detail = " ".join((result.stderr or result.stdout).split())
    print(f"{label} rc={result.returncode}: {detail}", file=sys.stderr)
raise SystemExit(setter.returncode or probe.returncode or 1)
"""
KNOWN_JOURNALD_512M = b"""# Persist enough bounded journal history for cross-boot host-health diagnosis.
[Journal]
Storage=persistent
SystemMaxUse=512M
MaxRetentionSec=14day
"""
KNOWN_JOURNALD_2G = b"""# Persist enough bounded journal history for cross-boot host-health diagnosis.
[Journal]
Storage=persistent
SystemMaxUse=2G
SystemKeepFree=20G
MaxRetentionSec=14day
"""
KNOWN_OBSOLETE_ASSETS: dict[str, dict[str, Any]] = {
    "etc/systemd/journald.conf.d/50-heim-pc-retention.conf": {
        "contents": (KNOWN_JOURNALD_512M, KNOWN_JOURNALD_2G),
        "mode": 0o644,
    },
    "etc/systemd/journald.conf.d/99-heim-pc-retention.conf": {
        "contents": (KNOWN_JOURNALD_512M, KNOWN_JOURNALD_2G),
        "mode": 0o644,
    },
    "etc/systemd/system/cpu-governor.service.d/10-verified-profile.conf": {
        "contents": (
            b"[Service]\nExecStart=\n"
            b"ExecStart=/usr/local/sbin/heim-pc-set-performance-profile\n",
        ),
        "mode": 0o644,
    },
    "usr/local/sbin/heim-pc-set-performance-profile": {
        "contents": (KNOWN_LEGACY_PROFILE_SCRIPT,),
        "mode": 0o755,
        "live_owner": ("root", "root"),
    },
    "etc/systemd/user/fluidsynth.service.d/10-interactive-user.conf": {
        "contents": (b"[Unit]\nConditionUser=alex\n",),
        "mode": 0o644,
    },
    "etc/systemd/user/fluidsynth.service.d/50-heim-pc-gdm-guard.conf": {
        "contents": (
            b"# The distribution unit remains enabled. "
            b"This condition skips only GDM's user manager.\n"
            b"[Unit]\nConditionUser=!gdm\n",
        ),
        "mode": 0o644,
    },
    "etc/systemd/user/fluidsynth.service.d/zz-heim-pc-gdm-guard.conf": {
        "contents": (
            b"# Reset legacy user pinning. The distribution unit remains enabled "
            b"for every user except GDM.\n"
            b"[Unit]\nConditionUser=\nConditionUser=!gdm\n",
        ),
        "mode": 0o644,
    },
}

SYSTEM_UNIT_DIRS = (
    "etc/systemd/system",
    "run/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
)
USER_UNIT_DIRS = (
    "etc/systemd/user",
    "run/systemd/user",
    "usr/local/lib/systemd/user",
    "usr/lib/systemd/user",
    "lib/systemd/user",
)

# Tests may replace this hook. Production leaves it as None.
TRANSACTION_FAULT_HOOK: Callable[[int, str], None] | None = None


class InstallError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def re_full_commit(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)


def _git(
    root: Path,
    argv: list[str],
    *,
    text: bool,
) -> subprocess.CompletedProcess[Any]:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        ["git", *argv],
        cwd=root,
        text=text,
        capture_output=True,
        check=False,
        env=environment,
    )


def repository_identity(root: Path) -> tuple[str, bool]:
    head = _git(root, ["rev-parse", "--verify", "HEAD^{commit}"], text=True)
    status_result = _git(
        root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        text=True,
    )
    if head.returncode != 0 or status_result.returncode != 0:
        raise InstallError("cannot determine repository identity")
    commit = head.stdout.strip()
    if not re_full_commit(commit):
        raise InstallError("repository HEAD is invalid")
    return commit, bool(status_result.stdout.strip())


def _committed_sources(
    root: Path,
    commit: str,
) -> tuple[dict[str, bytes], dict[str, str], str]:
    verified = _git(root, ["rev-parse", "--verify", f"{commit}^{{commit}}"], text=True)
    if verified.returncode != 0 or verified.stdout.strip() != commit:
        raise InstallError("expected Git commit object is unavailable")
    object_format_result = _git(
        root,
        ["rev-parse", "--show-object-format"],
        text=True,
    )
    object_format = object_format_result.stdout.strip()
    if object_format_result.returncode != 0 or object_format not in {"sha1", "sha256"}:
        raise InstallError("cannot determine Git object format")
    result: dict[str, bytes] = {}
    object_ids: dict[str, str] = {}
    for source_relative, _target_relative, _mode in FILES:
        tree = _git(root, ["ls-tree", "-z", commit, "--", source_relative], text=False)
        if tree.returncode != 0 or not tree.stdout:
            raise InstallError(f"committed source is missing: {source_relative}")
        metadata, separator, tree_path = tree.stdout.partition(b"\t")
        fields = metadata.split()
        if (
            separator != b"\t"
            or tree_path.rstrip(b"\0").decode("utf-8", "strict") != source_relative
            or tree.stdout.count(b"\0") != 1
            or not tree.stdout.endswith(b"\0")
            or len(fields) != 3
            or fields[1] != b"blob"
            or fields[0] not in {b"100644", b"100755"}
        ):
            raise InstallError(f"committed source is not a regular blob: {source_relative}")
        object_id = fields[2].decode("ascii", "strict")
        expected_object_id_length = 40 if object_format == "sha1" else 64
        if (
            len(object_id) != expected_object_id_length
            or any(character not in "0123456789abcdef" for character in object_id)
        ):
            raise InstallError(f"committed source blob identity is invalid: {source_relative}")
        blob = _git(root, ["cat-file", "blob", object_id], text=False)
        if blob.returncode != 0:
            raise InstallError(f"cannot read committed source blob: {source_relative}")
        digest = hashlib.new(object_format)
        digest.update(f"blob {len(blob.stdout)}\0".encode("ascii"))
        digest.update(blob.stdout)
        if digest.hexdigest() != object_id:
            raise InstallError(
                f"committed source blob identity mismatch: {source_relative}"
            )
        result[source_relative] = blob.stdout
        object_ids[source_relative] = object_id
    _validate_committed_contract(result)
    return result, object_ids, object_format


def _validate_committed_contract(source_data: dict[str, bytes]) -> None:
    try:
        config = json.loads(
            source_data["config/host-health-remediation.v1.json"].decode("utf-8")
        )
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("committed deployment contract is invalid") from exc
    deployment = config.get("deployment")
    mce = config.get("mce_edac")
    expected_deployment = {
        "source_binding": "expected_git_commit_tree_verified_blob_objects",
        "exclusive_lock": f"/{LOCK_RELATIVE}",
        "receipt": f"/{RECEIPT_RELATIVE}",
        "target_regular_file_owner": "root:root",
        "target_operations": "descriptor_relative_nofollow",
        "transaction": "preflight_stage_fsync_commit_verify_commit_point",
        "commit_point": COMMIT_POINT,
        "post_commit_cleanup": "bounded_best_effort_receipted_and_recoverable",
        "receipt_publication": "post_commit_atomic_replace_fsync_exact_readback",
        "plan_mode": "commit_bound_read_only_unprivileged_no_apply_state",
        "legacy_removal_policy": "exact_known_preimages_only",
        "fluidsynth_condition_user": FLUIDSYNTH_USER,
        "activation_performed": False,
        "fluidsynth_exec_start": FLUIDSYNTH_EXEC_START,
        "fluidsynth_service_type": FLUIDSYNTH_SERVICE_TYPE,
        "fluidsynth_notify_access": FLUIDSYNTH_NOTIFY_ACCESS,
        "fluidsynth_log_rate_limit_interval": FLUIDSYNTH_LOG_RATE_LIMIT_INTERVAL,
        "fluidsynth_log_rate_limit_burst": FLUIDSYNTH_LOG_RATE_LIMIT_BURST,
    }
    if not isinstance(deployment, dict) or any(
        deployment.get(key) != value
        for key, value in expected_deployment.items()
    ):
        raise InstallError("committed deployment contract differs from installer constants")
    if set(deployment.get("legacy_removals", [])) != {
        f"/{relative}" for relative in REMOVALS
    }:
        raise InstallError("committed legacy removal contract differs from installer targets")
    legacy_script = deployment.get("known_legacy_profile_script")
    if legacy_script != {
        "path": "/usr/local/sbin/heim-pc-set-performance-profile",
        "sha256": _sha256(KNOWN_LEGACY_PROFILE_SCRIPT),
        "mode": "0755",
        "owner": "root:root",
    }:
        raise InstallError("committed legacy script identity differs from installer")
    if (
        not isinstance(mce, dict)
        or mce.get("state_schema_version") != 2
        or mce.get("deduplication")
        != "bounded_constituent_overlap_and_boundary_span"
        or mce.get("constituent_evidence_limit")
        != mce.get("max_journal_entries")
    ):
        raise InstallError("committed MCE evidence contract is inconsistent")


def _relative_parts(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts or "." in path.parts:
        raise InstallError(f"unsafe target relative path: {relative}")
    return path.parts


def _nofollow_flags(flags: int) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise InstallError("platform lacks O_NOFOLLOW")
    return flags | nofollow | getattr(os, "O_CLOEXEC", 0)


def _open_root(target_root: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(target_root)))
    try:
        descriptor = os.open(
            absolute,
            _nofollow_flags(os.O_RDONLY | os.O_DIRECTORY),
        )
    except OSError as exc:
        raise InstallError(f"cannot safely open target root {absolute}: {exc}") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise InstallError(f"target root is not a directory: {absolute}")
    return descriptor


def _open_directory(
    root_fd: int,
    relative_parts: tuple[str, ...],
    *,
    create: bool,
    created: list[str] | None = None,
    final_mode: int = 0o755,
) -> int | None:
    descriptor = os.dup(root_fd)
    walked: list[str] = []
    try:
        for index, part in enumerate(relative_parts):
            walked.append(part)
            try:
                child = os.open(
                    part,
                    _nofollow_flags(os.O_RDONLY | os.O_DIRECTORY),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    os.close(descriptor)
                    return None
                mode = final_mode if index == len(relative_parts) - 1 else 0o755
                try:
                    os.mkdir(part, mode, dir_fd=descriptor)
                except FileExistsError:
                    pass
                else:
                    os.fsync(descriptor)
                    if created is not None:
                        created.append("/".join(walked))
                child = os.open(
                    part,
                    _nofollow_flags(os.O_RDONLY | os.O_DIRECTORY),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise InstallError(
                    f"unsafe or unreadable target directory: {'/'.join(walked)}: {exc}"
                ) from exc
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise InstallError(f"target parent is not a directory: {'/'.join(walked)}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_parent(
    root_fd: int,
    relative: str,
    *,
    create: bool,
    created: list[str] | None = None,
    parent_mode: int = 0o755,
) -> tuple[int | None, str]:
    parts = _relative_parts(relative)
    parent = _open_directory(
        root_fd,
        parts[:-1],
        create=create,
        created=created,
        final_mode=parent_mode,
    )
    return parent, parts[-1]


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _snapshot_at(parent_fd: int | None, name: str) -> dict[str, Any]:
    if parent_fd is None:
        return {"exists": False}
    try:
        descriptor = os.open(name, _nofollow_flags(os.O_RDONLY), dir_fd=parent_fd)
    except FileNotFoundError:
        return {"exists": False}
    except OSError as exc:
        raise InstallError(f"cannot safely open target {name}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallError(f"target must be a regular file: {name}")
        data = _read_descriptor(descriptor)
        return {
            "exists": True,
            "data": data,
            "sha256": _sha256(data),
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
    finally:
        os.close(descriptor)


def _snapshot(root_fd: int, relative: str) -> dict[str, Any]:
    parent_fd, name = _open_parent(root_fd, relative, create=False)
    try:
        return _snapshot_at(parent_fd, name)
    finally:
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _same_snapshot(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("exists") != right.get("exists"):
        return False
    if not left.get("exists"):
        return True
    return all(
        left.get(key) == right.get(key)
        for key in ("data", "mode", "uid", "gid", "device", "inode")
    )


def _target_display(target_root: Path, relative: str) -> str:
    return str(Path(os.path.abspath(os.fspath(target_root))) / relative)


def _backup_relative(target_relative: str, before: bytes) -> str:
    safe_name = "__".join(_relative_parts(target_relative))
    return f"{BACKUP_ROOT_RELATIVE}/{safe_name}.{_sha256(before)}.bak"


def _expected_owner(target_root: Path) -> tuple[int, int]:
    if Path(os.path.abspath(os.fspath(target_root))) == DEFAULT_TARGET_ROOT:
        return 0, 0
    return os.geteuid(), os.getegid()


def _validate_obsolete_preimage(
    target_relative: str,
    before: dict[str, Any],
    *,
    target_root: Path,
) -> dict[str, Any] | None:
    if not before["exists"]:
        return None
    contract = KNOWN_OBSOLETE_ASSETS[target_relative]
    mismatch: list[str] = []
    if before["data"] not in contract["contents"]:
        mismatch.append("content")
    if before["mode"] != contract["mode"]:
        mismatch.append("mode")
    expected_live_owner: tuple[int, int] | None = None
    if (
        Path(os.path.abspath(os.fspath(target_root))) == DEFAULT_TARGET_ROOT
        and "live_owner" in contract
    ):
        owner_name, group_name = contract["live_owner"]
        try:
            expected_live_owner = (
                pwd.getpwnam(owner_name).pw_uid,
                grp.getgrnam(group_name).gr_gid,
            )
        except KeyError as exc:
            raise InstallError(
                f"cannot resolve known obsolete owner for {target_relative}"
            ) from exc
        if (before["uid"], before["gid"]) != expected_live_owner:
            mismatch.append("owner")
    if mismatch:
        raise InstallError(
            f"obsolete target is not the exact known managed preimage: "
            f"{target_relative} ({', '.join(mismatch)} mismatch; "
            f"sha256={before['sha256']}, mode={oct(before['mode'])}, "
            f"uid={before['uid']}, gid={before['gid']})"
        )
    return {
        "verified": True,
        "accepted_sha256": before["sha256"],
        "accepted_mode": oct(before["mode"]),
        "accepted_uid": before["uid"],
        "accepted_gid": before["gid"],
        "live_owner_required": expected_live_owner is not None,
    }


def _overlay_bytes(
    root_fd: int,
    relative: str,
    overlay: dict[str, bytes | None],
) -> bytes | None:
    if relative in overlay:
        return overlay[relative]
    snapshot = _snapshot(root_fd, relative)
    return snapshot["data"] if snapshot["exists"] else None


def _virtual_names(
    root_fd: int,
    directory: str,
    overlay: dict[str, bytes | None],
) -> set[str]:
    names: set[str] = set()
    directory_fd = _open_directory(
        root_fd,
        _relative_parts(directory),
        create=False,
    )
    if directory_fd is not None:
        try:
            names.update(os.listdir(directory_fd))
        finally:
            os.close(directory_fd)
    prefix = f"{directory}/"
    for relative, value in overlay.items():
        if relative.startswith(prefix) and "/" not in relative[len(prefix) :]:
            name = relative[len(prefix) :]
            if value is None:
                names.discard(name)
            else:
                names.add(name)
    return names


def _is_merged_usr_lib_alias(root_fd: int, directory: str) -> bool:
    if not directory.startswith("lib/systemd/"):
        return False
    try:
        target = os.readlink("lib", dir_fd=root_fd)
    except OSError:
        return False
    return target in {"usr/lib", "/usr/lib"}


def _assignments(data: bytes, section_name: str, key_name: str) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("systemd composition contains non-UTF-8 configuration") from exc
    section: str | None = None
    values: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == section_name and "=" in line:
            key, value = line.split("=", 1)
            if key.strip() == key_name:
                values.append(value.strip())
    return values


def _effective_list_directive(
    root_fd: int,
    *,
    unit_dirs: tuple[str, ...],
    unit_name: str,
    section: str,
    key: str,
    overlay: dict[str, bytes | None],
) -> tuple[list[str], list[str], list[str]]:
    values: list[str] = []
    sources: list[str] = []
    directive_sources: list[str] = []
    for directory in unit_dirs:
        if _is_merged_usr_lib_alias(root_fd, directory):
            continue
        relative = f"{directory}/{unit_name}"
        data = _overlay_bytes(root_fd, relative, overlay)
        if data is not None:
            assignments = _assignments(data, section, key)
            for value in assignments:
                values = [] if value == "" else [*values, value]
            sources.append(relative)
            if assignments:
                directive_sources.append(relative)
            break

    stem, separator, suffix = unit_name.rpartition(".")
    drop_in_names = [f"{unit_name}.d"]
    if separator and "-" in stem:
        components = stem.split("-")
        for count in range(len(components) - 1, 0, -1):
            drop_in_names.append(
                f"{'-'.join(components[:count])}-.{suffix}.d"
            )
    if separator:
        drop_in_names.append(f"{suffix}.d")

    selected_drop_ins: dict[str, str] = {}
    for directory in unit_dirs:
        if _is_merged_usr_lib_alias(root_fd, directory):
            continue
        for drop_in_name in drop_in_names:
            drop_in_dir = f"{directory}/{drop_in_name}"
            for name in _virtual_names(root_fd, drop_in_dir, overlay):
                if name.endswith(".conf") and name not in selected_drop_ins:
                    selected_drop_ins[name] = f"{drop_in_dir}/{name}"
    for name in sorted(selected_drop_ins):
        relative = selected_drop_ins[name]
        data = _overlay_bytes(root_fd, relative, overlay)
        if data is None:
            continue
        assignments = _assignments(data, section, key)
        for value in assignments:
            values = [] if value == "" else [*values, value]
        sources.append(relative)
        if assignments:
            directive_sources.append(relative)
    return values, sources, directive_sources


def _verify_effective_composition(
    root_fd: int,
    overlay: dict[str, bytes | None] | None = None,
) -> dict[str, Any]:
    effective_overlay = {} if overlay is None else overlay
    exec_start, cpu_sources, cpu_directive_sources = _effective_list_directive(
        root_fd,
        unit_dirs=SYSTEM_UNIT_DIRS,
        unit_name="cpu-governor.service",
        section="Service",
        key="ExecStart",
        overlay=effective_overlay,
    )
    condition_user, fluid_sources, fluid_directive_sources = _effective_list_directive(
        root_fd,
        unit_dirs=USER_UNIT_DIRS,
        unit_name="fluidsynth.service",
        section="Unit",
        key="ConditionUser",
        overlay=effective_overlay,
    )
    fluid_exec_start, fluid_exec_sources, fluid_exec_directive_sources = (
        _effective_list_directive(
            root_fd,
            unit_dirs=USER_UNIT_DIRS,
            unit_name="fluidsynth.service",
            section="Service",
            key="ExecStart",
            overlay=effective_overlay,
        )
    )
    fluid_type_values, fluid_type_sources, fluid_type_directive_sources = (
        _effective_list_directive(
            root_fd,
            unit_dirs=USER_UNIT_DIRS,
            unit_name="fluidsynth.service",
            section="Service",
            key="Type",
            overlay=effective_overlay,
        )
    )
    fluid_notify_values, fluid_notify_sources, fluid_notify_directive_sources = (
        _effective_list_directive(
            root_fd,
            unit_dirs=USER_UNIT_DIRS,
            unit_name="fluidsynth.service",
            section="Service",
            key="NotifyAccess",
            overlay=effective_overlay,
        )
    )
    fluid_rate_interval_values, fluid_rate_interval_sources, _ = (
        _effective_list_directive(
            root_fd,
            unit_dirs=USER_UNIT_DIRS,
            unit_name="fluidsynth.service",
            section="Service",
            key="LogRateLimitIntervalSec",
            overlay=effective_overlay,
        )
    )
    fluid_rate_burst_values, fluid_rate_burst_sources, _ = (
        _effective_list_directive(
            root_fd,
            unit_dirs=USER_UNIT_DIRS,
            unit_name="fluidsynth.service",
            section="Service",
            key="LogRateLimitBurst",
            overlay=effective_overlay,
        )
    )
    fluid_type = fluid_type_values[-1] if fluid_type_values else None
    fluid_notify_access = fluid_notify_values[-1] if fluid_notify_values else None
    fluid_rate_interval = (
        fluid_rate_interval_values[-1] if fluid_rate_interval_values else None
    )
    fluid_rate_burst = (
        fluid_rate_burst_values[-1] if fluid_rate_burst_values else None
    )
    expected_fluid_main_units = {
        f"{directory}/fluidsynth.service"
        for directory in USER_UNIT_DIRS
        if not _is_merged_usr_lib_alias(root_fd, directory)
    }
    fluid_main_unit_sources = [
        source for source in fluid_sources if source in expected_fluid_main_units
    ]
    if not fluid_main_unit_sources:
        raise InstallError(
            "loadable fluidsynth.service main unit is missing; a managed drop-in "
            "cannot establish the service by itself"
        )
    if exec_start != [STRICT_PROFILE]:
        raise InstallError(
            "effective cpu-governor.service ExecStart is not the strict committed wrapper"
        )
    unexpected_cpu_drop_ins = [
        source
        for source in cpu_directive_sources
        if ".d/" in source
        and source
        != "etc/systemd/system/cpu-governor.service.d/"
        "zz-heim-pc-strict-profile.conf"
    ]
    if unexpected_cpu_drop_ins:
        raise InstallError(
            "unmanaged cpu-governor.service ExecStart drop-in(s) are present: "
            + ", ".join(unexpected_cpu_drop_ins)
        )
    if condition_user != [FLUIDSYNTH_USER]:
        raise InstallError(
            f"effective fluidsynth.service ConditionUser must contain only "
            f"{FLUIDSYNTH_USER}"
        )
    if fluid_exec_start != [FLUIDSYNTH_EXEC_START]:
        raise InstallError(
            "effective fluidsynth.service ExecStart must be the bounded "
            "no-shell server command"
        )
    if fluid_type != FLUIDSYNTH_SERVICE_TYPE:
        raise InstallError(
            "effective fluidsynth.service Type must restore the distribution "
            "notify contract"
        )
    if fluid_notify_access != FLUIDSYNTH_NOTIFY_ACCESS:
        raise InstallError(
            "effective fluidsynth.service NotifyAccess must be main"
        )
    if fluid_rate_interval != FLUIDSYNTH_LOG_RATE_LIMIT_INTERVAL:
        raise InstallError(
            "effective fluidsynth.service LogRateLimitIntervalSec must be bounded"
        )
    if fluid_rate_burst != FLUIDSYNTH_LOG_RATE_LIMIT_BURST:
        raise InstallError(
            "effective fluidsynth.service LogRateLimitBurst must be bounded"
        )
    unexpected_fluid_drop_ins = [
        source
        for source in fluid_directive_sources
        if ".d/" in source
        and source
        != "etc/systemd/user/fluidsynth.service.d/"
        "zz-heim-pc-interactive-user.conf"
    ]
    if unexpected_fluid_drop_ins:
        raise InstallError(
            "unmanaged fluidsynth.service ConditionUser drop-in(s) are present: "
            + ", ".join(unexpected_fluid_drop_ins)
        )
    return {
        "cpu_governor": {
            "exec_start": exec_start,
            "sources": cpu_sources,
            "directive_sources": cpu_directive_sources,
            "verified": True,
        },
        "fluidsynth": {
            "condition_user": condition_user,
            "exec_start": fluid_exec_start,
            "type": fluid_type,
            "notify_access": fluid_notify_access,
            "log_rate_limit_interval": fluid_rate_interval,
            "log_rate_limit_burst": fluid_rate_burst,
            "sources": fluid_sources,
            "directive_sources": fluid_directive_sources,
            "exec_start_sources": fluid_exec_sources,
            "exec_start_directive_sources": fluid_exec_directive_sources,
            "type_sources": fluid_type_sources,
            "type_directive_sources": fluid_type_directive_sources,
            "notify_access_sources": fluid_notify_sources,
            "notify_access_directive_sources": fluid_notify_directive_sources,
            "rate_interval_sources": fluid_rate_interval_sources,
            "rate_burst_sources": fluid_rate_burst_sources,
            "main_unit_sources": fluid_main_unit_sources,
            "verified": True,
        },
    }


def verify_effective_composition(target_root: Path) -> dict[str, Any]:
    root_fd = _open_root(target_root)
    try:
        return _verify_effective_composition(root_fd)
    finally:
        try:
            os.close(root_fd)
        except OSError:
            pass


def _build_plan(
    *,
    root_fd: int,
    source_data: dict[str, bytes],
    target_root: Path,
    uid: int,
    gid: int,
    inspect_apply_state: bool,
) -> tuple[list[dict[str, Any]], dict[str, bytes | None], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    overlay: dict[str, bytes | None] = {}

    for target_relative in REMOVALS:
        before = _snapshot(root_fd, target_relative)
        managed_preimage = _validate_obsolete_preimage(
            target_relative,
            before,
            target_root=target_root,
        )
        backup_relative = (
            _backup_relative(target_relative, before["data"]) if before["exists"] else None
        )
        if backup_relative is not None:
            if inspect_apply_state:
                backup_before = _snapshot(root_fd, backup_relative)
                if backup_before["exists"] and (
                    backup_before["data"] != before["data"]
                    or backup_before["mode"] != 0o600
                    or backup_before["uid"] != uid
                    or backup_before["gid"] != gid
                ):
                    raise InstallError(f"backup collision: {backup_relative}")
                backup_metadata = {
                    "available": True,
                    "exists": backup_before["exists"],
                }
            else:
                backup_metadata = {
                    "available": False,
                    "reason": "apply_only_privileged_metadata_not_read_in_plan_mode",
                }
        else:
            backup_metadata = {"available": True, "exists": False}
        entries.append(
            {
                "operation": "remove_obsolete",
                "source": None,
                "target_relative": target_relative,
                "target": _target_display(target_root, target_relative),
                "mode": None,
                "before": before,
                "action": "planned_removal" if before["exists"] else "absent",
                "sha256": before.get("sha256"),
                "managed_preimage": managed_preimage,
                "backup_relative": backup_relative,
                "backup": (
                    _target_display(target_root, backup_relative)
                    if backup_relative is not None
                    else None
                ),
                "backup_metadata": backup_metadata,
            }
        )
        overlay[target_relative] = None

    for source_relative, target_relative, mode in FILES:
        data = source_data[source_relative]
        before = _snapshot(root_fd, target_relative)
        changed = (
            not before["exists"]
            or before["data"] != data
            or before["mode"] != mode
            or before["uid"] != uid
            or before["gid"] != gid
        )
        backup_relative = None
        backup_metadata = {"available": True, "exists": False}
        if before["exists"] and before["data"] != data:
            backup_relative = _backup_relative(target_relative, before["data"])
            if inspect_apply_state:
                backup_before = _snapshot(root_fd, backup_relative)
                if backup_before["exists"] and (
                    backup_before["data"] != before["data"]
                    or backup_before["mode"] != 0o600
                    or backup_before["uid"] != uid
                    or backup_before["gid"] != gid
                ):
                    raise InstallError(f"backup collision: {backup_relative}")
                backup_metadata = {
                    "available": True,
                    "exists": backup_before["exists"],
                }
            else:
                backup_metadata = {
                    "available": False,
                    "reason": "apply_only_privileged_metadata_not_read_in_plan_mode",
                }
        entries.append(
            {
                "operation": "install",
                "source": source_relative,
                "source_sha256": _sha256(data),
                "target_relative": target_relative,
                "target": _target_display(target_root, target_relative),
                "mode": oct(mode),
                "mode_int": mode,
                "uid": uid,
                "gid": gid,
                "data": data,
                "before": before,
                "action": "planned" if changed else "unchanged",
                "sha256": _sha256(data),
                "backup_relative": backup_relative,
                "backup": (
                    _target_display(target_root, backup_relative)
                    if backup_relative is not None
                    else None
                ),
                "backup_metadata": backup_metadata,
            }
        )
        overlay[target_relative] = data

    composition = _verify_effective_composition(root_fd, overlay)
    return entries, overlay, composition


def _public_entry(item: dict[str, Any], *, applied: bool) -> dict[str, Any]:
    action = item["action"]
    before = item["before"]
    if applied:
        if action == "planned":
            action = "installed"
        elif action == "planned_removal":
            action = "removed"
    return {
        "operation": item["operation"],
        "source": item.get("source"),
        "source_sha256": item.get("source_sha256"),
        "target": item["target"],
        "mode": item.get("mode"),
        "uid": item.get("uid"),
        "gid": item.get("gid"),
        "action": action,
        "sha256": item.get("sha256"),
        "managed_preimage": item.get("managed_preimage"),
        "backup": item.get("backup"),
        "backup_metadata": item.get("backup_metadata"),
        "before": (
            {
                "sha256": before["sha256"],
                "mode": oct(before["mode"]),
                "uid": before["uid"],
                "gid": before["gid"],
            }
            if before["exists"]
            else None
        ),
    }


def _write_temp(
    parent_fd: int,
    target_name: str,
    data: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    role: str,
) -> str:
    for _attempt in range(32):
        name = f".{target_name}.{role}.{secrets.token_hex(8)}"
        try:
            descriptor = os.open(
                name,
                _nofollow_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                mode,
                dir_fd=parent_fd,
            )
            break
        except FileExistsError:
            continue
    else:
        raise InstallError(f"cannot allocate staged file for {target_name}")
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise InstallError(f"short staged write for {target_name}")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise InstallError(f"staged file metadata verification failed for {target_name}")
    except Exception:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    return name


def _remove_created_directories(root_fd: int, created: list[str]) -> list[str]:
    errors: list[str] = []
    for relative in reversed(created):
        parts = _relative_parts(relative)
        parent = _open_directory(root_fd, parts[:-1], create=False)
        if parent is None:
            continue
        try:
            try:
                os.rmdir(parts[-1], dir_fd=parent)
            except OSError as exc:
                if exc.errno not in {errno.ENOTEMPTY, errno.ENOENT}:
                    errors.append(f"{relative}: {exc}")
            try:
                os.fsync(parent)
            except OSError as exc:
                errors.append(f"{relative}: parent fsync failed: {exc}")
        finally:
            os.close(parent)
    return errors


def _preimage_matches(parent_fd: int, name: str, expected: dict[str, Any]) -> bool:
    return _same_snapshot(_snapshot_at(parent_fd, name), expected)


def _stage_operation(
    root_fd: int,
    operation: dict[str, Any],
    *,
    created: list[str],
) -> dict[str, Any]:
    parent_fd, name = _open_parent(
        root_fd,
        operation["relative"],
        create=True,
        created=created,
        parent_mode=operation.get("parent_mode", 0o755),
    )
    assert parent_fd is not None
    staged_name = None
    rollback_name = None
    try:
        if not _preimage_matches(parent_fd, name, operation["before"]):
            raise InstallError(f"target preimage changed before staging: {operation['relative']}")
        if operation["kind"] == "install":
            staged_name = _write_temp(
                parent_fd,
                name,
                operation["data"],
                mode=operation["mode"],
                uid=operation["uid"],
                gid=operation["gid"],
                role="stage",
            )
        if operation["before"]["exists"]:
            rollback_name = _write_temp(
                parent_fd,
                name,
                operation["before"]["data"],
                mode=operation["before"]["mode"],
                uid=operation["before"]["uid"],
                gid=operation["before"]["gid"],
                role="rollback",
            )
        staged_snapshot = (
            _snapshot_at(parent_fd, staged_name) if staged_name is not None else None
        )
        rollback_snapshot = (
            _snapshot_at(parent_fd, rollback_name) if rollback_name is not None else None
        )
        os.fsync(parent_fd)
        return {
            **operation,
            "parent_fd": parent_fd,
            "name": name,
            "staged_name": staged_name,
            "rollback_name": rollback_name,
            "staged_snapshot": staged_snapshot,
            "rollback_snapshot": rollback_snapshot,
        }
    except Exception:
        for temporary_name in (staged_name, rollback_name):
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        os.close(parent_fd)
        raise


def _residue_entry(
    target_root: Path,
    operation: dict[str, Any],
    key: str,
) -> dict[str, Any]:
    role = "stage" if key == "staged_name" else "rollback"
    snapshot_key = "staged_snapshot" if key == "staged_name" else "rollback_snapshot"
    snapshot = operation.get(snapshot_key)
    parent = str(PurePosixPath(operation["relative"]).parent)
    relative = (
        operation[key]
        if parent == "."
        else f"{parent}/{operation[key]}"
    )
    result = {
        "relative": relative,
        "path": _target_display(target_root, relative),
        "role": role,
    }
    if snapshot is not None:
        result["snapshot"] = {
            "sha256": snapshot["sha256"],
            "mode": oct(snapshot["mode"]),
            "uid": snapshot["uid"],
            "gid": snapshot["gid"],
            "device": snapshot["device"],
            "inode": snapshot["inode"],
        }
    return result


def _cleanup_staged(
    staged: list[dict[str, Any]],
    *,
    target_root: Path,
) -> dict[str, Any]:
    warnings: list[str] = []
    attempted = 0
    for operation in staged:
        parent_fd = operation["parent_fd"]
        for key in ("staged_name", "rollback_name"):
            name = operation.get(key)
            if name is not None:
                if key == "rollback_name" and operation.get("rollback_failed"):
                    continue
                attempted += 1
                try:
                    os.unlink(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    operation[key] = None
                except OSError as exc:
                    residue = _residue_entry(target_root, operation, key)
                    warnings.append(f"{residue['path']}: cleanup failed: {exc}")
                else:
                    operation[key] = None
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            warnings.append(
                f"{_target_display(target_root, str(PurePosixPath(operation['relative']).parent))}: "
                f"cleanup fsync failed: {exc}"
            )
        try:
            os.close(parent_fd)
        except OSError as exc:
            warnings.append(
                f"{_target_display(target_root, operation['relative'])}: "
                f"cleanup descriptor close failed: {exc}"
            )
    residue = [
        _residue_entry(target_root, operation, key)
        for operation in staged
        for key in ("staged_name", "rollback_name")
        if operation.get(key) is not None
    ]
    return {
        "complete": not warnings and not residue,
        "bounded": True,
        "maximum_attempts": len(staged) * 2,
        "attempted": attempted,
        "residue": residue,
        "warnings": warnings,
    }


def _rollback(committed: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for operation in reversed(committed):
        parent_fd = operation["parent_fd"]
        try:
            current = _snapshot_at(parent_fd, operation["name"])
            if operation["kind"] == "install":
                expected_current = {
                    "exists": True,
                    "data": operation["data"],
                    "mode": operation["mode"],
                    "uid": operation["uid"],
                    "gid": operation["gid"],
                }
                if not all(
                    current.get(key) == expected_current.get(key)
                    for key in ("exists", "data", "mode", "uid", "gid")
                ):
                    raise InstallError("installed target changed before rollback")
            elif current["exists"]:
                raise InstallError("removed target was replaced before rollback")

            if operation["before"]["exists"]:
                rollback_name = operation["rollback_name"]
                if rollback_name is None:
                    raise InstallError("rollback image is missing")
                if not _same_snapshot(
                    _snapshot_at(parent_fd, rollback_name),
                    operation["rollback_snapshot"],
                ):
                    raise InstallError("rollback image changed before restoration")
                os.replace(
                    rollback_name,
                    operation["name"],
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                operation["rollback_name"] = None
            elif current["exists"]:
                os.unlink(operation["name"], dir_fd=parent_fd)
            os.fsync(parent_fd)
        except Exception as exc:  # rollback must attempt every committed target
            operation["rollback_failed"] = True
            errors.append(f"{operation['relative']}: {exc}")
    return errors


def _verify_operation(root_fd: int, operation: dict[str, Any]) -> dict[str, Any]:
    final = _snapshot(root_fd, operation["relative"])
    if operation["kind"] == "remove":
        if final["exists"]:
            raise InstallError(f"obsolete target removal readback failed: {operation['relative']}")
        return {
            "relative": operation["relative"],
            "exists": False,
        }
    if (
        not final["exists"]
        or final["data"] != operation["data"]
        or final["mode"] != operation["mode"]
        or final["uid"] != operation["uid"]
        or final["gid"] != operation["gid"]
    ):
        raise InstallError(f"installed target readback failed: {operation['relative']}")
    return {
        "relative": operation["relative"],
        "exists": True,
        "sha256": final["sha256"],
        "mode": oct(final["mode"]),
        "uid": final["uid"],
        "gid": final["gid"],
    }


def _verify_entries(
    root_fd: int,
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    readback: list[dict[str, Any]] = []
    for item in entries:
        final = _snapshot(root_fd, item["target_relative"])
        if item["operation"] == "remove_obsolete":
            if final["exists"]:
                raise InstallError(
                    f"obsolete target removal readback failed: {item['target_relative']}"
                )
            readback.append(
                {
                    "target": item["target"],
                    "target_relative": item["target_relative"],
                    "exists": False,
                }
            )
            continue
        if (
            not final["exists"]
            or final["data"] != item["data"]
            or final["mode"] != item["mode_int"]
            or final["uid"] != item["uid"]
            or final["gid"] != item["gid"]
        ):
            raise InstallError(
                f"installed target readback failed: {item['target_relative']}"
            )
        readback.append(
            {
                "target": item["target"],
                "target_relative": item["target_relative"],
                "exists": True,
                "sha256": final["sha256"],
                "mode": oct(final["mode"]),
                "uid": final["uid"],
                "gid": final["gid"],
            }
        )
    return readback


def _apply_operations(
    root_fd: int,
    operations: list[dict[str, Any]],
    *,
    entries: list[dict[str, Any]],
    target_root: Path,
    created: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    staged: list[dict[str, Any]] = []
    committed: list[dict[str, Any]] = []
    failure: Exception | None = None
    rollback_errors: list[str] = []
    target_readback: list[dict[str, Any]] = []
    composition: dict[str, Any] = {}
    try:
        for operation in operations:
            staged.append(_stage_operation(root_fd, operation, created=created))
        for index, operation in enumerate(staged, start=1):
            parent_fd = operation["parent_fd"]
            if not _preimage_matches(parent_fd, operation["name"], operation["before"]):
                raise InstallError(
                    f"target preimage changed before commit: {operation['relative']}"
                )
            if operation["kind"] == "install":
                if not _same_snapshot(
                    _snapshot_at(parent_fd, operation["staged_name"]),
                    operation["staged_snapshot"],
                ):
                    raise InstallError(
                        f"staged target changed before commit: {operation['relative']}"
                    )
                os.replace(
                    operation["staged_name"],
                    operation["name"],
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                operation["staged_name"] = None
            else:
                os.unlink(operation["name"], dir_fd=parent_fd)
            os.fsync(parent_fd)
            committed.append(operation)
            if TRANSACTION_FAULT_HOOK is not None:
                TRANSACTION_FAULT_HOOK(index, operation["relative"])
        for operation in operations:
            _verify_operation(root_fd, operation)
        target_readback = _verify_entries(root_fd, entries)
        composition = _verify_effective_composition(root_fd)
        # This assignment is the explicit transaction commit point. No failure
        # after it may be described as a target-transaction failure or trigger
        # rollback of the now verified target state.
        commit_point_reached = True
    except Exception as exc:
        failure = exc
        rollback_errors = _rollback(committed)
        commit_point_reached = False
    cleanup = _cleanup_staged(staged, target_root=target_root)
    if failure is not None:
        directory_errors = (
            _remove_created_directories(root_fd, created)
            if not rollback_errors
            else []
        )
        cleanup_errors = [
            *cleanup["warnings"],
            *[
                f"{item['path']}: residue remains"
                for item in cleanup["residue"]
            ],
            *directory_errors,
        ]
        rollback_detail = (
            f"; rollback failures: {', '.join(rollback_errors)}"
            if rollback_errors
            else ""
        )
        cleanup_detail = (
            f"; pre-commit cleanup failures: {', '.join(cleanup_errors)}"
            if cleanup_errors
            else ""
        )
        raise InstallError(
            "transaction failed before commit point"
            f" ({COMMIT_POINT}) and rollback was attempted: {failure}"
            f"{rollback_detail}{cleanup_detail}"
        ) from failure
    assert commit_point_reached
    return target_readback, composition, cleanup


def _open_lock(root_fd: int, uid: int, gid: int):
    created: list[str] = []
    parent_fd, name = _open_parent(
        root_fd,
        LOCK_RELATIVE,
        create=True,
        created=created,
        parent_mode=0o700,
    )
    assert parent_fd is not None
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            _nofollow_flags(os.O_RDWR | os.O_CREAT),
            0o600,
            dir_fd=parent_fd,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallError("installer lock is not a regular file")
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
        os.fsync(parent_fd)
        return os.fdopen(descriptor, "r+b")
    except InstallError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise InstallError(f"cannot safely prepare installer lock: {exc}") from exc
    finally:
        os.close(parent_fd)


def _allowed_residue_parents() -> set[str]:
    return {
        str(PurePosixPath(relative).parent)
        for _source, relative, _mode in FILES
    } | {
        str(PurePosixPath(relative).parent)
        for relative in REMOVALS
    } | {
        BACKUP_ROOT_RELATIVE,
    }


def _validate_residue_relative(relative: str) -> None:
    parts = _relative_parts(relative)
    parent = str(PurePosixPath(relative).parent)
    name = parts[-1]
    name_parts = name.rsplit(".", 2)
    if (
        parent not in _allowed_residue_parents()
        or len(name_parts) != 3
        or name_parts[1] not in {"stage", "rollback"}
        or not RESIDUE_TOKEN.fullmatch(name_parts[2])
        or not name.startswith(".")
    ):
        raise InstallError(f"unsafe receipted cleanup residue: {relative}")


def _recover_receipted_residue(
    root_fd: int,
    *,
    target_root: Path,
) -> dict[str, Any]:
    receipt_snapshot = _snapshot(root_fd, RECEIPT_RELATIVE)
    if not receipt_snapshot["exists"]:
        return {"attempted": 0, "recovered": [], "warnings": []}
    try:
        previous = json.loads(receipt_snapshot["data"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {
            "attempted": 0,
            "recovered": [],
            "warnings": [
                f"{_target_display(target_root, RECEIPT_RELATIVE)}: "
                "previous receipt is unreadable; no residue paths were inferred"
            ],
        }
    transaction = previous.get("transaction")
    if (
        previous.get("schema_version") != 3
        or previous.get("kind")
        != "heim_pc_host_health_remediation_install_receipt"
        or not isinstance(transaction, dict)
        or not transaction.get("committed")
    ):
        return {"attempted": 0, "recovered": [], "warnings": []}
    residue = transaction.get("residue", [])
    if not isinstance(residue, list):
        raise InstallError("previous receipt cleanup residue is invalid")

    recovered: list[str] = []
    errors: list[str] = []
    for item in residue:
        if not isinstance(item, dict) or not isinstance(item.get("relative"), str):
            raise InstallError("previous receipt cleanup residue is invalid")
        relative = item["relative"]
        expected_snapshot = item.get("snapshot")
        if not isinstance(expected_snapshot, dict):
            raise InstallError("previous receipt cleanup residue lacks exact identity")
        _validate_residue_relative(relative)
        parent_fd, name = _open_parent(root_fd, relative, create=False)
        if parent_fd is None:
            recovered.append(_target_display(target_root, relative))
            continue
        try:
            current = _snapshot_at(parent_fd, name)
            if not current["exists"]:
                recovered.append(_target_display(target_root, relative))
                continue
            if any(
                expected_snapshot.get(key) != value
                for key, value in {
                    "sha256": current["sha256"],
                    "mode": oct(current["mode"]),
                    "uid": current["uid"],
                    "gid": current["gid"],
                    "device": current["device"],
                    "inode": current["inode"],
                }.items()
            ):
                errors.append(
                    f"{_target_display(target_root, relative)}: "
                    "residue identity differs from receipt"
                )
                continue
            try:
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError as exc:
                errors.append(
                    f"{_target_display(target_root, relative)}: recovery cleanup failed: {exc}"
                )
            else:
                recovered.append(_target_display(target_root, relative))
        finally:
            os.close(parent_fd)
    if errors:
        raise InstallError(
            "pre-commit receipted residue recovery failed: " + ", ".join(errors)
        )
    return {
        "attempted": len(residue),
        "recovered": recovered,
        "warnings": [],
    }


def _publish_receipt(
    root_fd: int,
    *,
    target_root: Path,
    receipt: dict[str, Any],
    uid: int,
    gid: int,
    created: list[str],
) -> dict[str, Any]:
    parent_fd: int | None = None
    name = PurePosixPath(RECEIPT_RELATIVE).name
    staged_name: str | None = None
    try:
        parent_fd, name = _open_parent(
            root_fd,
            RECEIPT_RELATIVE,
            create=True,
            created=created,
            parent_mode=0o700,
        )
        if parent_fd is None:
            raise InstallError("receipt parent is unavailable")
        receipt_bytes = (
            json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        before = _snapshot_at(parent_fd, name)
        staged_name = _write_temp(
            parent_fd,
            name,
            receipt_bytes,
            mode=0o600,
            uid=uid,
            gid=gid,
            role="stage",
        )
        if not _preimage_matches(parent_fd, name, before):
            raise InstallError("receipt changed before publication")
        os.replace(
            staged_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        staged_name = None
        os.fsync(parent_fd)
        # Re-open through the pinned target root instead of trusting only the
        # still-open parent descriptor. A parent rename/substitution during
        # publication must become an incomplete receipt outcome.
        final = _snapshot(root_fd, RECEIPT_RELATIVE)
        if (
            not final["exists"]
            or final["data"] != receipt_bytes
            or final["mode"] != 0o600
            or final["uid"] != uid
            or final["gid"] != gid
        ):
            raise InstallError("receipt publication exact readback failed")
        return receipt
    except Exception as exc:
        cleanup_warnings: list[str] = []
        residue: list[dict[str, str]] = []
        if staged_name is not None and parent_fd is not None:
            relative = (
                f"{PurePosixPath(RECEIPT_RELATIVE).parent}/{staged_name}"
            )
            try:
                os.unlink(staged_name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError as cleanup_exc:
                path = _target_display(target_root, relative)
                cleanup_warnings.append(
                    f"{path}: failed receipt-stage cleanup: {cleanup_exc}"
                )
                residue.append(
                    {"relative": relative, "path": path, "role": "receipt_stage"}
                )
        failed = json.loads(json.dumps(receipt))
        failed["kind"] = "heim_pc_host_health_remediation_committed_outcome"
        failed["receipt_publication"] = {
            **failed["receipt_publication"],
            "intended_receipt_kind": receipt["kind"],
            "complete": False,
            "fsynced": False,
            "exact_readback": False,
            "error": str(exc),
            "residue": residue,
            "warnings": cleanup_warnings,
        }
        failed["warnings"] = [
            *failed.get("warnings", []),
            f"target transaction committed but receipt publication failed: {exc}",
            *cleanup_warnings,
        ]
        return failed
    finally:
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _transaction_operations(
    *,
    root_fd: int,
    entries: list[dict[str, Any]],
    uid: int,
    gid: int,
) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    backups_added: set[str] = set()
    for item in entries:
        backup_relative = item.get("backup_relative")
        if backup_relative is not None and backup_relative not in backups_added:
            backup_before = _snapshot(root_fd, backup_relative)
            if not backup_before["exists"]:
                operations.append(
                    {
                        "kind": "install",
                        "relative": backup_relative,
                        "data": item["before"]["data"],
                        "mode": 0o600,
                        "uid": uid,
                        "gid": gid,
                        "before": backup_before,
                        "parent_mode": 0o700,
                    }
                )
            backups_added.add(backup_relative)
    for item in entries:
        if item["action"] == "planned":
            operations.append(
                {
                    "kind": "install",
                    "relative": item["target_relative"],
                    "data": item["data"],
                    "mode": item["mode_int"],
                    "uid": uid,
                    "gid": gid,
                    "before": item["before"],
                }
            )
        elif item["action"] == "planned_removal":
            operations.append(
                {
                    "kind": "remove",
                    "relative": item["target_relative"],
                    "before": item["before"],
                }
            )
    return operations


def _base_receipt(
    *,
    apply: bool,
    head: str,
    dirty: bool,
    target_root: Path,
    entries: list[dict[str, Any]],
    composition: dict[str, Any],
    source_object_ids: dict[str, str],
    source_object_format: str,
    installed_at: str | None = None,
    target_readback: list[dict[str, Any]] | None = None,
    cleanup: dict[str, Any] | None = None,
    residue_recovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if apply:
        assert cleanup is not None
        assert target_readback is not None
    transaction_cleanup = cleanup or {
        "complete": None,
        "bounded": True,
        "maximum_attempts": 0,
        "attempted": 0,
        "residue": [],
        "warnings": [],
    }
    return {
        "schema_version": 3,
        "kind": (
            "heim_pc_host_health_remediation_install_receipt"
            if apply
            else "heim_pc_host_health_remediation_install_plan"
        ),
        "valid": True,
        "apply": apply,
        "repository_head": head,
        "repository_dirty": dirty,
        "source_binding": {
            "kind": "git_commit_tree",
            "commit": head,
            "object_format": source_object_format,
            "blob_objects_reverified": True,
            "mutable_worktree_source_bytes_used": False,
            "files": {
                item["source"]: {
                    "git_object_id": source_object_ids[item["source"]],
                    "sha256": item["source_sha256"],
                }
                for item in entries
                if item.get("source") is not None
            },
        },
        "target_root": str(Path(os.path.abspath(os.fspath(target_root)))),
        "installed_at": installed_at,
        "files": [_public_entry(item, applied=apply) for item in entries],
        "effective_systemd_composition": composition,
        "transaction": {
            "exclusive_lock": (
                _target_display(target_root, LOCK_RELATIVE) if apply else None
            ),
            "commit_point": COMMIT_POINT,
            "commit_point_reached": apply,
            "committed": apply,
            "target_state_verified": apply,
            "target_readback": target_readback or [],
            "preflight_complete_before_staging": True,
            "descriptor_relative_nofollow": True,
            "staged_and_fsynced": apply,
            "rollback_images_staged": apply,
            "rollback_fail_closed_before_commit_point": True,
            "post_commit_rollback_performed": False,
            "cleanup_complete": transaction_cleanup["complete"],
            "cleanup_bounded": transaction_cleanup["bounded"],
            "cleanup_maximum_attempts": transaction_cleanup["maximum_attempts"],
            "cleanup_attempted": transaction_cleanup["attempted"],
            "residue": transaction_cleanup["residue"],
            "warnings": transaction_cleanup["warnings"],
            "previous_residue_recovery": residue_recovery or {
                "attempted": 0,
                "recovered": [],
                "warnings": [],
            },
            "receipt_relative": RECEIPT_RELATIVE if apply else None,
        },
        "receipt_publication": {
            "required": apply,
            "post_commit": apply,
            "path": (
                _target_display(target_root, RECEIPT_RELATIVE) if apply else None
            ),
            "atomic_replace": apply,
            "fsynced": apply,
            "exact_readback": apply,
            "complete": apply,
        },
        "warnings": [
            *transaction_cleanup["warnings"],
            *(residue_recovery or {}).get("warnings", []),
        ],
        "activation_performed": False,
        "activation_required": [
            "systemctl daemon-reload",
            "systemctl restart systemd-journald",
            (
                "systemd-analyze cat-config systemd/journald.conf; verify the final "
                "SystemMaxUse=2G, SystemKeepFree=20G and MaxRetentionSec=14day"
            ),
            "systemctl enable --now heim-pc-mce-edac-monitor.timer",
            "systemctl restart cpu-governor.service",
            "restart alex's user manager or reboot before evaluating the FluidSynth condition",
        ],
        "does_not_establish": [
            "systemd_activation",
            "firmware_flash",
            "BIOS_SVM_enablement",
            "absence_of_future_path_substitution_after_the_installer_exits",
        ],
    }


def install(
    *,
    source_root: Path,
    target_root: Path,
    apply: bool,
    expected_head: str | None,
) -> dict[str, Any]:
    target_root = Path(os.path.abspath(os.fspath(target_root)))
    root_fd = _open_root(target_root)
    uid, gid = _expected_owner(target_root)
    try:
        if apply:
            if expected_head is None or not re_full_commit(expected_head):
                raise InstallError("--apply requires a full 40-character --expected-head")
            if target_root == DEFAULT_TARGET_ROOT and os.geteuid() != 0:
                raise InstallError("installing below / requires root")
            with _open_lock(root_fd, uid, gid) as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                head, dirty = repository_identity(source_root)
                if head != expected_head:
                    raise InstallError("repository HEAD differs from --expected-head")
                if dirty:
                    raise InstallError("repository must be clean for a commit-bound install")
                source_data, source_object_ids, source_object_format = (
                    _committed_sources(source_root, expected_head)
                )
                residue_recovery = _recover_receipted_residue(
                    root_fd,
                    target_root=target_root,
                )
                entries, _overlay, composition = _build_plan(
                    root_fd=root_fd,
                    source_data=source_data,
                    target_root=target_root,
                    uid=uid,
                    gid=gid,
                    inspect_apply_state=True,
                )
                installed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                operations = _transaction_operations(
                    root_fd=root_fd,
                    entries=entries,
                    uid=uid,
                    gid=gid,
                )
                created: list[str] = []
                target_readback, committed_composition, cleanup = _apply_operations(
                    root_fd,
                    operations,
                    entries=entries,
                    target_root=target_root,
                    created=created,
                )
                receipt = _base_receipt(
                    apply=True,
                    head=head,
                    dirty=dirty,
                    target_root=target_root,
                    entries=entries,
                    composition=committed_composition,
                    source_object_ids=source_object_ids,
                    source_object_format=source_object_format,
                    installed_at=installed_at,
                    target_readback=target_readback,
                    cleanup=cleanup,
                    residue_recovery=residue_recovery,
                )
                return _publish_receipt(
                    root_fd,
                    target_root=target_root,
                    receipt=receipt,
                    uid=uid,
                    gid=gid,
                    created=created,
                )

        head, dirty = repository_identity(source_root)
        if expected_head is not None and head != expected_head:
            raise InstallError("repository HEAD differs from --expected-head")
        source_data, source_object_ids, source_object_format = _committed_sources(
            source_root,
            head,
        )
        entries, _overlay, composition = _build_plan(
            root_fd=root_fd,
            source_data=source_data,
            target_root=target_root,
            uid=uid,
            gid=gid,
            inspect_apply_state=False,
        )
        return _base_receipt(
            apply=False,
            head=head,
            dirty=dirty,
            target_root=target_root,
            entries=entries,
            composition=composition,
            source_object_ids=source_object_ids,
            source_object_format=source_object_format,
        )
    finally:
        try:
            os.close(root_fd)
        except OSError:
            pass


def install_files(
    *,
    source_root: Path,
    target_root: Path,
    apply: bool,
    expected_head: str | None = None,
) -> list[dict[str, Any]]:
    return install(
        source_root=source_root,
        target_root=target_root,
        apply=apply,
        expected_head=expected_head,
    )["files"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", type=Path, default=DEFAULT_TARGET_ROOT)
    parser.add_argument("--expected-head")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        receipt = install(
            source_root=ROOT,
            target_root=args.target_root,
            apply=args.apply,
            expected_head=args.expected_head,
        )
    except InstallError as exc:
        print(
            json.dumps(
                {
                    "schema_version": 3,
                    "kind": "heim_pc_host_health_remediation_install_error",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    if receipt["apply"] and not receipt["receipt_publication"]["complete"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
