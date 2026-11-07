#!/usr/bin/env python3
"""Scoped Restic retention. No deletion without off-host restore attestation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

MOUNT = Path("/var/lib/heim-pc-backup")
REPO = MOUNT / "restic/heim-pc"
PASSWORD = Path("/persist/secrets/restic/heim-pc-password")
ATTESTATION = Path("/persist/secrets/restic/independent-restore.json")
SIGNATURE = Path("/persist/secrets/restic/independent-restore.json.sig")
PUBLIC_KEY = Path("/persist/secrets/restic/independent-restore-public.pem")
DEVICE_UUID = "9b626294-7913-4be0-88fa-96b314e96ee5"
REPO_ID = "85ee278eeb58f42c26745796cb7b23239d4c7c01f5f4d00f2c10e216cefa4972"
HOST, TAG = "heim-pc-nixos", "nixos-seagate"
REQUIRED_PATHS = {
    "/home/alex", "/persist", "/etc", "/var/lib/tailscale",
    "/var/lib/NetworkManager", "/var/lib/nixos", "/var/lib/grabowski",
}
MAX_PROOF_AGE = 30 * 86400
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


def read_trusted(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or info.st_nlink != 1
            or info.st_size < 1 or info.st_size > limit):
        raise RuntimeError("invalid root-owned restore attestation material")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        live = os.fstat(fd)
        if (live.st_ino != info.st_ino or live.st_dev != info.st_dev
                or live.st_size != info.st_size):
            raise RuntimeError("restore attestation changed during inspection")
        return os.read(fd, limit + 1)
    finally:
        os.close(fd)


def independent_proof(now: int, all_snapshots: dict) -> str:
    # Verification private key MUST remain on the independent restore host.
    raw = read_trusted(ATTESTATION, 32768)
    read_trusted(SIGNATURE, 8192)
    read_trusted(PUBLIC_KEY, 8192)
    command(["openssl", "dgst", "-sha256", "-verify", str(PUBLIC_KEY),
             "-signature", str(SIGNATURE), str(ATTESTATION)])
    proof = json.loads(raw)
    if not isinstance(proof, dict):
        raise RuntimeError("invalid independent restore attestation")
    snapshot = proof.get("snapshot_id")
    complete_at = proof.get("completed_at_unix")
    inventory = proof.get("inventory")
    host = proof.get("restore_host")
    if (proof.get("kind") != "heim_pc.restic_independent_full_restore.v1"
            or proof.get("repository_id") != REPO_ID
            or proof.get("backup_uuid") != DEVICE_UUID
            or proof.get("source_host") != HOST
            or proof.get("restore_medium") not in ("independent-repository-copy", "external-backup-disk")
            or proof.get("complete_restore") is not True
            or proof.get("off_host_recovery_access_verified") is not True
            or not isinstance(host, str) or not host or host.startswith("heim-pc")
            or not isinstance(complete_at, int) or isinstance(complete_at, bool)
            or not 0 <= now - complete_at <= MAX_PROOF_AGE
            or not isinstance(snapshot, str) or not HEX64.fullmatch(snapshot)
            or snapshot not in all_snapshots
            or not isinstance(inventory, dict)):
        raise RuntimeError("independent full restore proof absent, stale or mismatched")
    source_hash = inventory.get("source_sha256")
    restored_hash = inventory.get("restored_sha256")
    paths = inventory.get("covered_paths")
    if (not isinstance(source_hash, str) or not HEX64.fullmatch(source_hash)
            or source_hash != restored_hash
            or not isinstance(paths, list) or not REQUIRED_PATHS.issubset(set(
                p for p in paths if isinstance(p, str)))
            or type(inventory.get("file_count")) is not int
            or inventory["file_count"] < 1
            or type(inventory.get("total_bytes")) is not int
            or inventory["total_bytes"] < 1):
        raise RuntimeError("independent restore inventory equality is not proven")
    snap = all_snapshots[snapshot]
    if snap.get("hostname") != HOST or TAG not in snap.get("tags", []):
        raise RuntimeError("attested snapshot does not belong to NixOS backup")
    return snapshot


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


def removal_plan(all_snapshots: dict, attested_snapshot: str) -> list[str]:
    groups = json.loads(restic("forget", "--dry-run", "--json", "--retry-lock=6h", *POLICY))
    if not isinstance(groups, list):
        raise RuntimeError("invalid forget dry-run plan")
    removing: set[str] = set()
    for group in groups:
        if not isinstance(group, dict):
            raise RuntimeError("invalid forget group")
        entries = group.get("remove")
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
                    or sid == attested_snapshot):
                raise RuntimeError("forget plan would delete protected history")
            removing.add(sid)
    return sorted(removing)


def main() -> int:
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise RuntimeError("root-only fixed-argument retention command")
    require_repository()
    before = snapshots()
    attested = independent_proof(int(time.time()), before)
    removed = removal_plan(before, attested)
    # Exact IDs from the validated dry run: new snapshots cannot change scope.
    if not removed:
        print("Retention: dry-run contains no deletions; prune skipped")
        return 0
    if snapshots() != before:
        raise RuntimeError("repository snapshot set changed after dry-run")
    # Recheck disk and repository identity immediately before BOTH mutations:
    # an automounted USB device may disappear or be exchanged after dry-run.
    require_repository()
    independent_proof(int(time.time()), before)
    restic("forget", "--retry-lock=6h", *removed, timeout=6 * 3600)
    # Prune affects unreferenced packs; other hosts' snapshots remain referenced.
    require_repository()
    restic("prune", "--retry-lock=6h", timeout=6 * 3600)
    print(f"Retention: removed {len(removed)} scoped snapshots, other hosts preserved")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Retention blocked: {exc}", file=sys.stderr)
        sys.exit(1)