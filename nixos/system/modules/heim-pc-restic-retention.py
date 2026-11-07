#!/usr/bin/env python3
"""Conservative weekly NixOS snapshot retention, no off-host proof or password prompt."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

MOUNT = Path("/var/lib/heim-pc-backup")
REPO = MOUNT / "restic/heim-pc"
PASSWORD = Path("/persist/secrets/restic/heim-pc-password")
DEVICE_UUID = "9b626294-7913-4be0-88fa-96b314e96ee5"
REPO_ID = "85ee278eeb58f42c26745796cb7b23239d4c7c01f5f4d00f2c10e216cefa4972"
HOST, TAG = "heim-pc-nixos", "nixos-seagate"
REQUIRED_PATHS = {
    "/home/alex", "/persist", "/etc", "/var/lib/tailscale",
    "/var/lib/NetworkManager", "/var/lib/nixos", "/var/lib/grabowski",
}
MAX_BACKUP_AGE = 72 * 3600
HEX64 = re.compile(r"^[0-9a-f]{64}$")
POLICY = (
    "--host", HOST, "--tag", TAG, "--group-by", "host,paths,tags",
    "--keep-last", "14", "--keep-within", "7d", "--keep-daily", "14",
    "--keep-weekly", "8", "--keep-monthly", "12", "--keep-yearly", "2",
)


def command(argv: list[str], timeout: int = 60) -> str:
    outcome = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if outcome.returncode:
        raise RuntimeError(f"{Path(argv[0]).name} failed with status {outcome.returncode}")
    return outcome.stdout


def restic(*argv: str, timeout: int = 1800) -> str:
    return command(
        ["restic", "--repo", str(REPO), "--password-file", str(PASSWORD), *argv],
        timeout=timeout,
    )


def require_repository() -> None:
    if REPO.is_symlink() or not REPO.is_dir() or not (REPO / "config").is_file():
        raise RuntimeError("backup repository is missing or symlinked")
    mounts = command(["findmnt", "-rn", "-T", str(MOUNT), "-t", "ext4",
                      "-o", "TARGET,SOURCE,FSTYPE"]).splitlines()
    if len(mounts) != 1:
        raise RuntimeError("backup mount is not the expected ext4 filesystem")
    columns = mounts[0].split()
    if len(columns) != 3 or columns[0] != str(MOUNT) or columns[2] != "ext4":
        raise RuntimeError("backup mount identity differs")
    if command(["lsblk", "-ndo", "UUID", columns[1]]).strip() != DEVICE_UUID:
        raise RuntimeError("backup disk UUID differs")
    config = json.loads(restic("cat", "config", "--no-cache", "--no-lock"))
    if not isinstance(config, dict) or config.get("id") != REPO_ID:
        raise RuntimeError("Restic repository ID differs")


def latest_healthy_snapshot(all_snapshots: dict, now: int) -> str:
    """Conservatively skip deletion unless a recent complete NixOS backup exists."""
    candidates = []
    for sid, snap in all_snapshots.items():
        if (snap.get("hostname") != HOST
                or TAG not in snap.get("tags", [])
                or not REQUIRED_PATHS.issubset(set(snap.get("paths", [])))):
            continue
        try:
            created = int(datetime.fromisoformat(
                snap["time"].replace("Z", "+00:00")
            ).astimezone(timezone.utc).timestamp())
        except (KeyError, ValueError, TypeError, OverflowError):
            continue
        if 0 <= now - created <= MAX_BACKUP_AGE:
            candidates.append((created, sid))
    if not candidates:
        raise RuntimeError("no recent complete NixOS backup; retention skipped")
    return max(candidates)[1]


def snapshots() -> dict:
    rows = json.loads(restic("snapshots", "--json", "--retry-lock=6h"))
    if not isinstance(rows, list):
        raise RuntimeError("invalid repository snapshot list")
    by_id = {}
    for snap in rows:
        if not isinstance(snap, dict):
            raise RuntimeError("invalid snapshot record")
        sid = snap.get("id")
        if not isinstance(sid, str) or not HEX64.fullmatch(sid) or sid in by_id:
            raise RuntimeError("missing or duplicate snapshot ID")
        by_id[sid] = snap
    return by_id


def removal_plan(all_snapshots: dict, protected_snapshot: str) -> list[str]:
    groups = json.loads(restic("forget", "--dry-run", "--json", "--retry-lock=6h", *POLICY))
    if not isinstance(groups, list):
        raise RuntimeError("invalid forget dry-run plan")
    removing: set[str] = set()
    for group in groups:
        if not isinstance(group, dict):
            raise RuntimeError("invalid forget group")
        entries = group.get("remove")
        # Restic 0.18.1 emits null, not [], when every snapshot is kept.
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise RuntimeError("invalid forget removal list")
        for item in entries:
            if not isinstance(item, dict):
                raise RuntimeError("invalid forget removal item")
            sid = item.get("id")
            if not isinstance(sid, str) or sid not in all_snapshots or sid in removing:
                raise RuntimeError("forget plan contains unknown or duplicate ID")
            snap = all_snapshots[sid]
            if (snap.get("hostname") != HOST
                    or TAG not in snap.get("tags", [])
                    or sid == protected_snapshot):
                raise RuntimeError("forget plan would delete protected history")
            removing.add(sid)
    return sorted(removing)


def main() -> int:
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise RuntimeError("root-only fixed-argument retention command")
    require_repository()
    before = snapshots()
    protected = latest_healthy_snapshot(before, int(time.time()))
    removed = removal_plan(before, protected)
    if not removed:
        print("Retention: no snapshots eligible; prune skipped")
        return 0
    if snapshots() != before:
        raise RuntimeError("repository snapshot set changed after dry-run")
    # USB mount and Restic repository must remain the ones we inspected.
    require_repository()
    restic("forget", "--retry-lock=6h", *removed, timeout=6 * 3600)
    # Referenced Pop!_OS data is preserved by Restic's normal prune semantics.
    require_repository()
    restic("prune", "--retry-lock=6h", timeout=6 * 3600)
    print(f"Retention: removed {len(removed)} NixOS snapshots; other hosts preserved")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Retention skipped: {exc}", file=sys.stderr)
        sys.exit(1)