#!/usr/bin/env python3
"""Root-owned, fixed-argument NixOS Restic restore proof (no caller-provided paths)."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

MOUNT = Path("/var/lib/heim-pc-backup")
REPO = MOUNT / "restic" / "heim-pc"
PASSWORD = Path("/persist/secrets/restic/heim-pc-password")
STATE = Path("/var/lib/heim-pc-restic-recovery-probe")
PROOF = STATE / "proof.json"
BACKUP_UUID = "9b626294-7913-4be0-88fa-96b314e96ee5"
REPOSITORY_ID = "85ee278eeb58f42c26745796cb7b23239d4c7c01f5f4d00f2c10e216cefa4972"
HOST = "heim-pc-nixos"
TAG = "nixos-seagate"
SOURCE = "/persist/secrets/restic/heim-pc-excludes"
MAX_AGE_SECONDS = 24 * 3600
CHECK_SUBSET = "1/10"


def _command(argv: list[str], *, timeout: int = 300, binary: bool = False):
    outcome = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=not binary, timeout=timeout, check=False,
    )
    if outcome.returncode != 0:
        raise RuntimeError(f"root recovery command failed: {Path(argv[0]).name} (exit {outcome.returncode})")
    return outcome.stdout


def _restic(*argv: str, timeout: int = 300, binary: bool = False):
    return _command(
        ["restic", "--repo", str(REPO), "--password-file", str(PASSWORD), *argv],
        timeout=timeout, binary=binary,
    )


def _mount_identity() -> str:
    if REPO.is_symlink() or not REPO.is_dir():
        raise RuntimeError("native backup repository missing or symlinked")
    lines = _command([
        "findmnt", "-rn", "-T", str(MOUNT), "-t", "ext4",
        "-o", "TARGET,SOURCE,FSTYPE",
    ]).splitlines()
    fields = [line.split() for line in lines if line.strip()]
    if len(fields) != 1 or len(fields[0]) != 3:
        raise RuntimeError("native backup mount identity is ambiguous")
    target, device, fstype = fields[0]
    if target != str(MOUNT) or not device.startswith("/dev/") or fstype != "ext4":
        raise RuntimeError("native backup mount identity mismatch")
    uuid = _command(["lsblk", "-ndo", "UUID", device]).strip()
    if uuid != BACKUP_UUID:
        raise RuntimeError("native backup UUID mismatch")
    config = json.loads(_restic("cat", "config", "--no-cache", "--no-lock"))
    if not isinstance(config, dict) or config.get("id") != REPOSITORY_ID:
        raise RuntimeError("native backup Restic repository ID mismatch")
    return device


def _snapshot(now: int) -> tuple[str, int]:
    rows = json.loads(_restic("snapshots", "--json", "--host", HOST, "--tag", TAG))
    if not isinstance(rows, list):
        raise RuntimeError("native backup snapshot listing is invalid")
    candidates = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        full_id = item.get("id")
        paths = item.get("paths")
        tags = item.get("tags")
        if (not isinstance(full_id, str) or not re.fullmatch(r"[0-9a-f]{64}", full_id)
                or item.get("hostname") != HOST or not isinstance(paths, list)
                or not isinstance(tags, list) or TAG not in tags
                or not {"/etc", "/persist", "/home/alex"}.issubset(
                    {p for p in paths if isinstance(p, str)})
                or not isinstance(item.get("time"), str)):
            continue
        try:
            at = int(datetime.fromisoformat(
                item["time"].replace("Z", "+00:00")).astimezone(timezone.utc).timestamp())
        except (ValueError, OverflowError):
            continue
        if 0 <= now - at <= MAX_AGE_SECONDS:
            candidates.append((at, full_id))
    if not candidates:
        raise RuntimeError("no fresh complete native backup snapshot")
    return max(candidates)[1], max(candidates)[0]


def _read_regular_restored_bytes(stage: str, source: str, expected_size: int) -> bytes:
    # O_NOFOLLOW on every path segment: a symlink restored from an otherwise
    # valid snapshot must not make the root reader leave its private stage.
    parts = Path(source.lstrip("/")).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise RuntimeError("root-owned Restic restore path is invalid")
    parent_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = child_fd
        file_fd = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            metadata = os.fstat(file_fd)
            if (not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_size != expected_size
                    or metadata.st_nlink != 1):
                raise RuntimeError("root-owned Restic restore type or size mismatch")
            remaining = expected_size
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(file_fd, remaining)
                if not chunk:
                    raise RuntimeError("root-owned Restic restore ended early")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(file_fd, 1):
                raise RuntimeError("root-owned Restic restore grew during read")
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise RuntimeError("root-owned Restic restore type or size mismatch") from exc
    finally:
        os.close(parent_fd)


def _restore_digest(snapshot_id: str) -> str:
    rows = [_line for _line in _restic(
        "ls", "--json", snapshot_id, SOURCE).splitlines() if _line.strip()]
    entries = [json.loads(row) for row in rows]
    matching = [item for item in entries if isinstance(item, dict)
                and item.get("message_type") == "node"
                and item.get("path") == SOURCE and item.get("type") == "file"
                and isinstance(item.get("size"), int)
                and not isinstance(item.get("size"), bool)
                and 0 < item["size"] <= 65536]
    if len(matching) != 1:
        raise RuntimeError("native backup probe file missing or unsafe")
    size = matching[0]["size"]
    with tempfile.TemporaryDirectory(prefix="root-restic-restore-", dir=str(STATE)) as stage:
        _restic("restore", snapshot_id, "--target", stage,
                "--include", SOURCE, "--verify", timeout=1200)
        restored_sha = hashlib.sha256(
            _read_regular_restored_bytes(stage, SOURCE, size)
        ).hexdigest()
        # Never log or publish the content of the root-only probe file.
        dump = _restic("dump", snapshot_id, SOURCE, timeout=300, binary=True)
        if len(dump) != size or hashlib.sha256(dump).hexdigest() != restored_sha:
            raise RuntimeError("restored bytes differ from independent Restic dump")
        return restored_sha


def _backup_timer_ready() -> tuple[str, int, int, int]:
    """Identify one completed successful service invocation, not stale unit defaults."""
    for operation in ("is-enabled", "is-active"):
        _command(["systemctl", operation, "--quiet", "restic-backups-heim-pc.timer"])
    properties = (
        "LoadState", "Result", "ExecMainStatus", "ExecMainCode",
        "ExecMainStartTimestamp", "ExecMainExitTimestamp",
        "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic",
        "InvocationID",
    )
    output = _command([
        "systemctl", "--timestamp=unix", "show",
        *[part for key in properties for part in ("-p", key)],
        "restic-backups-heim-pc.service",
    ])
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in properties or key in values:
            raise RuntimeError("native Restic system backup service has not succeeded")
        values[key] = value
    if (
        set(values) != set(properties)
        or values["LoadState"] != "loaded"
        or values["Result"] != "success"
        or values["ExecMainStatus"] != "0"
        or values["ExecMainCode"] != "1"
        or re.fullmatch(r"[0-9a-f]{32}", values["InvocationID"]) is None
    ):
        raise RuntimeError("native Restic system backup service has not succeeded")
    try:
        started_mono = int(values["ExecMainStartTimestampMonotonic"])
        exited_mono = int(values["ExecMainExitTimestampMonotonic"])
        # --timestamp=unix produces @<seconds>; empty/n/a timestamps fail closed.
        if (re.fullmatch(r"@[0-9]+", values["ExecMainStartTimestamp"]) is None
                or re.fullmatch(r"@[0-9]+", values["ExecMainExitTimestamp"]) is None):
            raise ValueError("missing unix timestamps")
        started = int(values["ExecMainStartTimestamp"][1:])
        exited = int(values["ExecMainExitTimestamp"][1:])
    except ValueError as exc:
        raise RuntimeError("native Restic system backup service has not succeeded") from exc
    if not (0 < started_mono < exited_mono
            and 0 < started <= exited <= int(time.time()) + 2):
        raise RuntimeError("native Restic system backup service has not succeeded")
    return values["InvocationID"], started, exited, exited_mono


def _snapshot_for_backup_run(now: int, backup_run: tuple[str, int, int, int]) -> tuple[str, int]:
    snapshot_id, snapshot_time = _snapshot(now)
    if not backup_run[1] <= snapshot_time <= backup_run[2]:
        raise RuntimeError("native Restic snapshot is not from the successful backup service run")
    return snapshot_id, snapshot_time


def _require_backup_run_unchanged(backup_run: tuple[str, int, int, int]) -> None:
    if _backup_timer_ready() != backup_run:
        raise RuntimeError("native Restic backup service invocation changed during recovery")


def _write_proof(record: dict[str, object]) -> None:
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temp = tempfile.mkstemp(prefix=".proof-", dir=str(STATE))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, PROOF)
        parent_fd = os.open(STATE, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main() -> int:
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise RuntimeError("root-only fixed-argument recovery probe")
    directory = STATE.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or directory.st_mode & 0o022:
        raise RuntimeError("root proof directory is not trusted")
    # Never leave old success evidence after a failed new proof.
    PROOF.unlink(missing_ok=True)
    started_at = int(time.time())
    mounted_device = _mount_identity()
    backup_run = _backup_timer_ready()
    snapshot_id, snapshot_time = _snapshot_for_backup_run(started_at, backup_run)
    restored_sha = _restore_digest(snapshot_id)
    _restic("check", "--read-data-subset=" + CHECK_SUBSET, "--retry-lock", "30m", timeout=2100)
    if _mount_identity() != mounted_device:
        raise RuntimeError("backup mount identity changed while proving recovery")
    _require_backup_run_unchanged(backup_run)
    completed = int(time.time())
    if not 0 <= completed - snapshot_time <= MAX_AGE_SECONDS:
        raise RuntimeError("snapshot stale after Restic check")
    _write_proof({
        "schema_version": 1,
        "kind": "heim_pc.nixos_restic_recovery_root_proof",
        "started_at_unix": started_at,
        "completed_at_unix": completed,
        "snapshot_id": snapshot_id,
        "snapshot_time_unix": snapshot_time,
        "repository_id": REPOSITORY_ID,
        "backup_uuid": BACKUP_UUID,
        "backup_source": mounted_device,
        "restore_sha256": restored_sha,
        "restore_probe_valid": True,
        "repository_check_valid": True,
    })
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"root recovery proof failed: {exc}", file=sys.stderr)
        sys.exit(1)
