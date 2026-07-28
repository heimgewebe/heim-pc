#!/usr/bin/env python3
"""Install a commit-bound local hostname mapping without replacing unrelated hosts entries."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY_RELATIVE_PATH = "config/network-identity.v1.json"
DEFAULT_TARGET = Path("/etc/hosts")
DEFAULT_BACKUP_ROOT = Path("/var/lib/heim-pc/network-identity/hosts-backups")
BEGIN_MARKER = "# BEGIN heim-pc network identity v1"
END_MARKER = "# END heim-pc network identity v1"
HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class InstallError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise InstallError(f"{' '.join(argv)} failed: {detail[:1000]}")
    return completed


def repository_identity(root: Path) -> tuple[str, bool]:
    head = run(["git", "-c", f"safe.directory={root}", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    if len(head) != 40 or any(character not in "0123456789abcdef" for character in head):
        raise InstallError("repository HEAD is invalid")
    status = run(["git", "-c", f"safe.directory={root}", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root).stdout
    return head, bool(status.strip())


def repository_blob(root: Path, *, head: str, relative_path: str) -> bytes:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={root}", "show", f"{head}:{relative_path}"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise InstallError(f"cannot read commit-bound blob {relative_path}: {detail[:500]}")
    return completed.stdout


def network_policy(policy_data: bytes) -> dict[str, Any]:
    try:
        policy = json.loads(policy_data)
    except json.JSONDecodeError as exc:
        raise InstallError(f"policy is invalid JSON: {exc}") from exc
    if not isinstance(policy, dict):
        raise InstallError("policy must be a JSON object")
    if policy.get("schema_version") != 1 or policy.get("kind") != "heim_pc_network_identity_policy":
        raise InstallError("unsupported policy identity")
    hostname = policy.get("hostname")
    address = policy.get("hosts_address")
    interface = policy.get("expected_default_interface")
    minimum = policy.get("minimum_link_speed_mbps")
    if not isinstance(hostname, str) or HOSTNAME_RE.fullmatch(hostname) is None:
        raise InstallError("policy hostname is invalid")
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise InstallError("policy hosts_address is invalid") from exc
    if parsed_address.version != 4 or not parsed_address.is_loopback:
        raise InstallError("policy hosts_address must be an IPv4 loopback address")
    if not isinstance(interface, str) or not interface or len(interface) > 64:
        raise InstallError("policy expected_default_interface is invalid")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 100:
        raise InstallError("policy minimum_link_speed_mbps is invalid")
    return {
        "hostname": hostname,
        "hosts_address": str(parsed_address),
        "expected_default_interface": interface,
        "minimum_link_speed_mbps": minimum,
    }


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _assert_safe_regular(path: Path, *, allow_absent: bool) -> None:
    if path.is_symlink():
        raise InstallError(f"path must not be a symlink: {path}")
    if not path.exists():
        if allow_absent:
            return
        raise InstallError(f"path does not exist: {path}")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallError(f"path must be a regular file: {path}")


def _active_fields(line: str) -> list[str]:
    active = line.split("#", 1)[0].strip()
    return active.split() if active else []


def merge_hosts(existing: bytes, *, hostname: str, address: str) -> bytes:
    try:
        text = existing.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("existing hosts file is not UTF-8") from exc
    lines = text.splitlines()
    begin_indexes = [index for index, line in enumerate(lines) if line.strip() == BEGIN_MARKER]
    end_indexes = [index for index, line in enumerate(lines) if line.strip() == END_MARKER]
    if len(begin_indexes) != len(end_indexes) or len(begin_indexes) > 1:
        raise InstallError("managed hosts block markers are malformed")
    block = [BEGIN_MARKER, f"{address}\t{hostname}", END_MARKER]
    if begin_indexes:
        begin = begin_indexes[0]
        end = end_indexes[0]
        if end <= begin:
            raise InstallError("managed hosts block marker order is invalid")
        outside = lines[:begin] + lines[end + 1 :]
        replacement = lines[:begin] + block + lines[end + 1 :]
    else:
        outside = lines
        replacement = list(lines)
        while replacement and not replacement[-1].strip():
            replacement.pop()
        if replacement:
            replacement.append("")
        replacement.extend(block)
    for line in outside:
        fields = _active_fields(line)
        if hostname not in fields[1:]:
            continue
        if fields[0] != address:
            raise InstallError(
                f"hostname {hostname!r} already has conflicting unmanaged address {fields[0]!r}"
            )
        raise InstallError(f"hostname {hostname!r} already has an unmanaged mapping")
    return ("\n".join(replacement).rstrip("\n") + "\n").encode("utf-8")


_EXPECTED_UNSET = object()


def atomic_install(
    path: Path,
    data: bytes,
    *,
    mode: int,
    expected_current: bytes | object = _EXPECTED_UNSET,
) -> None:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise InstallError(f"target parent is unsafe: {parent}")
    _assert_safe_regular(path, allow_absent=False)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if expected_current is not _EXPECTED_UNSET:
            _assert_safe_regular(path, allow_absent=False)
            if path.read_bytes() != expected_current:
                raise InstallError(f"target preimage changed before replacement: {path}")
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    _assert_safe_regular(path, allow_absent=False)
    if path.read_bytes() != data or stat.S_IMODE(path.stat().st_mode) != mode:
        raise InstallError(f"installed file readback failed: {path}")


def resolve_addresses(hostname: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise InstallError(f"hostname {hostname!r} did not resolve after install") from exc
    addresses: set[str] = set()
    for answer in answers:
        try:
            addresses.add(str(ipaddress.ip_address(answer[4][0].split("%", 1)[0])))
        except ValueError as exc:
            raise InstallError("hostname resolved to an invalid address") from exc
    if not addresses:
        raise InstallError("hostname resolution returned no addresses")
    return sorted(addresses)


def apply_policy(
    *,
    target: Path,
    backup_root: Path,
    policy_data: bytes,
    apply: bool,
) -> dict[str, Any]:
    target = _absolute_without_resolving(target)
    backup_root = _absolute_without_resolving(backup_root)
    if target == DEFAULT_TARGET and apply and os.geteuid() != 0:
        raise InstallError("installing /etc/hosts requires root")
    _assert_safe_regular(target, allow_absent=False)
    before = target.read_bytes()
    policy = network_policy(policy_data)
    after = merge_hosts(
        before,
        hostname=policy["hostname"],
        address=policy["hosts_address"],
    )
    changed = before != after
    backup: dict[str, Any] | None = None
    if apply and changed:
        backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if backup_root.is_symlink() or not backup_root.is_dir():
            raise InstallError(f"backup root is unsafe: {backup_root}")
        before_sha = sha256(before)
        backup_path = backup_root / f"hosts-{before_sha}.txt"
        if backup_path.exists():
            _assert_safe_regular(backup_path, allow_absent=False)
            if backup_path.read_bytes() != before:
                raise InstallError(f"existing backup content mismatch: {backup_path}")
        else:
            descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                remaining = before
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise InstallError("backup write made no progress")
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        backup = {"path": str(backup_path), "sha256": before_sha}
        atomic_install(target, after, mode=0o644, expected_current=before)
    readback = target.read_bytes() if apply else after
    if readback != after:
        raise InstallError("hosts readback differs from planned content")
    return {
        "target": str(target),
        "apply": apply,
        "action": "unchanged" if not changed else ("installed" if apply else "planned"),
        "before_sha256": sha256(before),
        "after_sha256": sha256(after),
        "policy_sha256": sha256(policy_data),
        "backup": backup,
        "policy": policy,
    }


def install(
    *,
    target: Path,
    backup_root: Path,
    apply: bool,
    expected_head: str | None,
) -> dict[str, Any]:
    head, dirty = repository_identity(ROOT)
    if dirty:
        raise InstallError("repository must be clean before a commit-bound install")
    if expected_head is not None and head != expected_head:
        raise InstallError("repository HEAD differs from expected_head")
    policy_data = repository_blob(ROOT, head=head, relative_path=POLICY_RELATIVE_PATH)
    result = apply_policy(
        target=target,
        backup_root=backup_root,
        policy_data=policy_data,
        apply=apply,
    )
    resolved_addresses = (
        resolve_addresses(result["policy"]["hostname"])
        if apply and target == DEFAULT_TARGET
        else None
    )
    if resolved_addresses is not None and result["policy"]["hosts_address"] not in resolved_addresses:
        raise InstallError("installed hostname mapping is absent from resolver readback")
    receipt = {
        "schema_version": 1,
        "kind": "heim_pc_network_identity_install_receipt",
        "generated_at_unix": int(time.time()),
        "repository_head": head,
        "repository_dirty": dirty,
        "resolved_addresses": resolved_addresses,
        **result,
        "does_not_establish": [
            "absence_of_dns_queries_from_unrelated_hostnames",
            "physical_ethernet_link_health",
            "future_pi_hole_rate_limit_absence_without_load_validation",
        ],
    }
    receipt["receipt_sha256"] = sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT)
    parser.add_argument("--expected-head")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        receipt = install(
            target=args.target,
            backup_root=args.backup_root,
            apply=args.apply,
            expected_head=args.expected_head,
        )
    except (InstallError, OSError, ValueError) as exc:
        print(
            json.dumps({"kind": "heim_pc_network_identity_install_error", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
