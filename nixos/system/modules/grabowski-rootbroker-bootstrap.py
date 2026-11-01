"""Explicit one-time NixOS Rootbroker policy bootstrap; never a boot service.

Only adds the exact original Grabowski operator-power contract from immutable
Git source and invokes the already installed private-policy installer.
Does not modify systemd units, broker executables or attestation files.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable


SOURCE = Path("/persist/secrets/grabowski/privileged-actions.json")
INSTALLED = Path("/etc/grabowski/privileged-actions.json")
REPO = Path("/home/alex/repos/grabowski")
LOCK = Path("/run/grabowski/rootbroker-cutover.lock")
BACKUPS = Path("/var/lib/grabowski/rootbroker-cutover-backups")
PINNED_COMMIT = "8259921996010ac77ff9a02013d3af322ed55937"
PINNED_POWER_SHA256 = "12d15770e33f3562011822cfe328270a7fc6f3f46cafbf8326601a0be98745ca"
POWER = "operator_power_argv"
MAX_BYTES = 512 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")


class BootstrapError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def root_directories(path: Path, *, uid: int, trusted_boundary: Path = Path("/")) -> None:
    ancestors = [path.parent, *path.parent.parents]
    if trusted_boundary not in ancestors:
        raise BootstrapError("path escapes trusted boundary")
    for parent in reversed(ancestors[:ancestors.index(trusted_boundary) + 1]):
        metadata = parent.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid
                or metadata.st_mode & 0o022):
            raise BootstrapError("unsafe parent: " + str(parent))


def guarded_read(path: Path, *, uid: int = 0,
                 trusted_boundary: Path = Path("/")) -> bytes:
    root_directories(path, uid=uid, trusted_boundary=trusted_boundary)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size <= 0 or before.st_size > MAX_BYTES):
            raise BootstrapError("unsafe root policy: " + str(path))
        data = os.read(descriptor, MAX_BYTES + 1)
        after = os.fstat(descriptor)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_size,
                    value.st_mtime_ns, value.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(after):
            raise BootstrapError("policy changed while reading: " + str(path))
        return data
    finally:
        os.close(descriptor)


def read_pinned_action(repository: Path, revision: str, action_sha256: str,
                       *, runner: Callable = subprocess.run) -> dict:
    if not SHA40.fullmatch(revision) or not SHA256.fullmatch(action_sha256):
        raise BootstrapError("invalid revision or action digest")
    argv = ["git", "--no-pager", "-c", f"safe.directory={repository}",
            "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "protocol.file.allow=never", "-C", str(repository),
            "show", f"{revision}:config/privileged-actions.example.json"]
    env = {"PATH": "/run/current-system/sw/bin:/usr/bin",
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_TERMINAL_PROMPT": "0"}
    result = runner(argv, capture_output=True, timeout=20, env=env)
    if result.returncode != 0 or not (0 < len(result.stdout) <= MAX_BYTES):
        raise BootstrapError("commit-addressed upstream source cannot be verified")
    action = json.loads(result.stdout)["actions"][POWER]
    if sha(canonical_json(action)) != action_sha256:
        raise BootstrapError("pinned upstream action SHA mismatch")
    if (action.get("enabled") is not True or action.get("mode") != "argv-json"
            or action.get("policy_intent") != "trusted-owner-root-autonomy"
            or action.get("allowed_peer_unit") != "grabowski-operator.service"
            or action.get("allowed_peer_uid") != 1000
            or "allowed_argv_prefixes" in action):
        raise BootstrapError("upstream action violates canonical peer contract")
    return action


def make_plan(source: bytes, installed: bytes, *, expected_old_sha: str,
              action: dict) -> tuple[bytes, str]:
    if not SHA256.fullmatch(expected_old_sha):
        raise BootstrapError("invalid expected policy SHA")
    if source != installed or sha(source) != expected_old_sha:
        raise BootstrapError("source / installed policy mismatch or changed preimage")
    document = json.loads(source)
    if (not isinstance(document, dict) or set(document) != {"schema_version", "actions"}
            or document["schema_version"] != 2 or not isinstance(document["actions"], dict)
            or any(not isinstance(k, str) or not k or not isinstance(v, dict)
                   for k, v in document["actions"].items())):
        raise BootstrapError("unsupported private policy schema")
    before = document["actions"].get(POWER)
    if before is not None:
        if before != action:
            raise BootstrapError("existing root power action differs from pinned source")
        return source, "already_applied"
    document["actions"][POWER] = action
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(), "ready"


def atomic_replace(path: Path, data: bytes, *, uid: int = 0,
                   trusted_boundary: Path = Path("/")) -> None:
    root_directories(path, uid=uid, trusted_boundary=trusted_boundary)
    descriptor, temporary = tempfile.mkstemp(prefix=".rootbroker-bootstrap-", dir=path.parent)
    try:
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, uid)
        elif os.fstat(descriptor).st_uid != uid:
            raise BootstrapError("temporary file owner differs from test authority")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = ""
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def save_backup(old: bytes, *, backups: Path, uid: int = 0,
                trusted_boundary: Path = Path("/")) -> Path:
    root_directories(backups / "backup", uid=uid, trusted_boundary=trusted_boundary)
    metadata = backups.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise BootstrapError("backup directory must be root-only 0700")
    directory = backups / (str(time.time_ns()) + "-" + sha(old)[:16])
    directory.mkdir(mode=0o700)
    target = directory / "privileged-actions.before.json"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, old)
        os.fsync(fd)
    finally:
        os.close(fd)
    for parent in (directory, backups):
        fd = os.open(parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return target


def bootstrap(*, source: Path, installed: Path, lock: Path, backups: Path,
              expected_old_sha: str, action: dict, installer: Callable[[], None],
              apply: bool = False, uid: int = 0,
              trusted_boundary: Path = Path("/")) -> dict:
    if apply and os.geteuid() != uid:
        raise BootstrapError("explicit apply requires root")
    def observe():
        return (guarded_read(source, uid=uid, trusted_boundary=trusted_boundary),
                guarded_read(installed, uid=uid, trusted_boundary=trusted_boundary))
    if not apply:
        old, installed_old = observe()
        new, state = make_plan(old, installed_old, expected_old_sha=expected_old_sha,
                               action=action)
        return {"state": state, "changed": False, "old_sha256": sha(old),
                "proposed_sha256": sha(new)}
    root_directories(lock, uid=uid, trusted_boundary=trusted_boundary)
    descriptor = os.open(lock, os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        lock_metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_uid != uid
                or lock_metadata.st_nlink != 1):
            raise BootstrapError("unsafe existing rootbroker lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old, installed_old = observe()
        new, state = make_plan(old, installed_old, expected_old_sha=expected_old_sha,
                               action=action)
        if state == "already_applied":
            return {"state": state, "changed": False, "old_sha256": sha(old)}
        backup = save_backup(old, backups=backups, uid=uid,
                             trusted_boundary=trusted_boundary)
        try:
            if observe() != (old, installed_old):
                raise BootstrapError("policy changed before commit")
            atomic_replace(source, new, uid=uid, trusted_boundary=trusted_boundary)
            installer()  # Existing NixOS private policy installer; no systemd restart.
            if observe() != (new, new):
                raise BootstrapError("installed policy differs from source")
        except Exception as failure:
            current_source, current_installed = observe()
            if current_source == new:
                atomic_replace(source, old, uid=uid, trusted_boundary=trusted_boundary)
            elif current_source != old:
                raise BootstrapError("source drift prevents safe rollback") from failure
            if current_installed == new:
                installer()
            elif current_installed != old:
                raise BootstrapError("installed drift prevents safe rollback") from failure
            if observe() != (old, old):
                raise BootstrapError("rollback readback failed") from failure
            raise
        return {"state": "applied", "changed": True, "old_sha256": sha(old),
                "new_sha256": sha(new), "backup_path": str(backup)}
    finally:
        os.close(descriptor)


def run_native_installer() -> None:
    # Bootstrap and the original installer live together in one immutable Nix derivation.
    companion = Path(__file__).with_name("grabowski-private-policy-install.py")
    if not companion.is_file():
        raise BootstrapError("NixOS private policy installer is not co-packaged")
    runpy.run_path(str(companion), run_name="bootstrap_import")["install"]()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-current-policy-sha256", required=True)
    parser.add_argument("--source-revision", default=PINNED_COMMIT)
    parser.add_argument("--expected-action-sha256", default=PINNED_POWER_SHA256)
    parser.add_argument("--source-repository", type=Path, default=REPO)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.source_revision != PINNED_COMMIT:
        raise BootstrapError("initial bootstrap supports only the exact serving commit")
    action = read_pinned_action(args.source_repository, args.source_revision,
                                args.expected_action_sha256)
    result = bootstrap(source=SOURCE, installed=INSTALLED, lock=LOCK, backups=BACKUPS,
        expected_old_sha=args.expected_current_policy_sha256, action=action,
        installer=run_native_installer, apply=args.apply)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print("rootbroker-bootstrap-error: " + type(error).__name__ + ": " +
              str(error)[:240], file=sys.stderr)
        raise SystemExit(2)