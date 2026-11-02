#!/usr/bin/env python3
"""One-shot NixOS Grabowski service trial; explicit confirmation or rollback.

Uses only temporary /run/systemd/system drop-ins. Never replaces the NixOS
generated /etc systemd unit symlinks, changes the desktop, or builds NixOS.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import stat
import subprocess
import sys
import time

OLD_OP = "/nix/store/1qhqyfkvffdy00nixccl631hrv9cdjg5-grabowski-operator-82599219"
OLD_BR = "/nix/store/a3plmgbwy71yfrsf0sf5yg5srs58nxz0-grabowski-rootbroker-source-82599219"
NEW_OP = "/nix/store/3l2cwpj417l99fhbqdq4vn9jczd8p7n5-grabowski-operator-3fbe93d2"
NEW_BR = "/nix/store/cs18w2c5a9dxp920q5ndicwmfq0kv7l3-grabowski-rootbroker-source-3fbe93d2"
INGRESS = "/nix/store/al87gc9094pirbyzvn0ya2wy8hagigf5-grabowski-ingress-rebind.py"
HEAD = "3fbe93d2f4c7a99c3c1aaf2c35952bac3541d98f"
RELEASE = "3fbe93d2-nixos-lock264e747ad05a-contract23851f3e6dea"
MANIFEST_SHA = "59e9d850d050dcb9bdb61f544b300a1fe4224c53df80cb53a3b03e5d3d83c610"
SYSTEMCTL = "/run/current-system/sw/bin/systemctl"
RUN_ROOT = Path("/run/systemd/system")
STATE_ROOT = Path("/run/grabowski")
CONF = "90-grabowski-nixos-research-trial.conf"
STATE = STATE_ROOT / "nixos-grabowski-trial-3fbe.json"
ACK = STATE_ROOT / "nixos-grabowski-trial-3fbe.ack"
LOCK = STATE_ROOT / "nixos-grabowski-trial-3fbe.lock"
UNITS = ("grabowski-operator.service", "grabowski-privileged-broker@.service",
         "grabowski-runtime-schema-install.service")
ORIGINAL_SHA = (
    "24cbeca1339b249ad67495aaac667f16f6b7041910895f0b2ecf9cb19189a4c7",
    "45b9886132022c38b560b20a3736f5e00bdf017b7e750dbb17e53b5b8341daec",
    "19f1a8a3fab829fed3f0e892db02ee705b360742e551760b69f44f05e793f831",
)

class TrialError(RuntimeError):
    pass

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def ctl(*args: str) -> str:
    r = subprocess.run([SYSTEMCTL, *args], capture_output=True,
                       text=True, timeout=35, check=False)
    if r.returncode:
        raise TrialError("systemctl " + args[0] + " exit=" + str(r.returncode)
                         + " " + r.stderr[:240])
    return r.stdout.strip()

def value(unit: str, prop: str) -> str:
    return ctl("show", unit, "--no-pager", "--property=" + prop, "--value")

def checked_regular(path: Path) -> bytes:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise TrialError("nontrusted file: " + str(path))
    return path.read_bytes()

def original_units() -> tuple[str, str, str]:
    units = []
    for name, expected in zip(UNITS, ORIGINAL_SHA):
        path = Path("/etc/systemd/system") / name
        resolved = path.resolve(strict=True)
        if not path.is_symlink() or not resolved.is_relative_to("/nix/store"):
            raise TrialError("unit is not a NixOS Store symlink: " + name)
        data = checked_regular(resolved)
        if digest(data) != expected:
            raise TrialError("unit source drifted: " + name)
        units.append(data.decode("utf-8"))
    return tuple(units)  # type: ignore[return-value]

def verified_release() -> None:
    needed = (Path(NEW_OP) / "bin/grabowski-operator",
              Path(NEW_BR) / "bin/grabowski-privileged-broker",
              Path(NEW_OP) / "lib/python3.12/site-packages/grabowski_runtime_contract.py",
              Path(INGRESS))
    for p in needed:
        checked_regular(p)
    manifest = checked_regular(Path(NEW_OP) / "share/grabowski/nixos-integrity-manifest.json")
    if digest(manifest) != MANIFEST_SHA:
        raise TrialError("pinned runtime manifest digest drifted")
    m = json.loads(manifest)
    release = json.loads(checked_regular(Path(NEW_OP) / "share/grabowski/nixos-release.json"))
    if (m.get("repo_head") != HEAD or m.get("release_id") != RELEASE
            or len(m.get("entrypoint_contract", {}).get("expected_tools", [])) != 206
            or release.get("source_revision") != HEAD or release.get("release_id") != RELEASE):
        raise TrialError("pinned NixOS runtime contract mismatch")

def render(old: tuple[str, str, str]) -> dict[str, str]:
    op, broker, schema = old
    if (op.count("ExecStart=" + OLD_OP + "/bin/grabowski-operator") != 1
        or op.count("ExecStartPost=" + OLD_OP + "/bin/python3") != 1
        or broker.count("ExecStart=" + OLD_BR + "/bin/grabowski-privileged-broker") != 1):
        raise TrialError("old entrypoint topology drifted")
    path_lines = [line[len("Environment=PATH="):] for line in op.splitlines()
                  if line.startswith("Environment=PATH=")]
    if len(path_lines) != 1 or path_lines[0].count(OLD_BR + "/bin") != 1:
        raise TrialError("old Rootbroker PATH is not unique")
    new_path = path_lines[0].replace(OLD_BR + "/bin", NEW_BR + "/bin")
    schema_lines = [line for line in schema.splitlines() if line.startswith("ExecStart=")]
    if len(schema_lines) != 1:
        raise TrialError("old schema unit ExecStart ambiguous")
    old_schema = OLD_OP + "/lib/python3.12/site-packages/grabowski_runtime_contract.py"
    if schema_lines[0].count(old_schema) != 1:
        raise TrialError("schema source is not the pinned old operator")
    schema_line = schema_lines[0].replace(
        old_schema, NEW_OP + "/lib/python3.12/site-packages/grabowski_runtime_contract.py")
    return {
        UNITS[0]: ("[Service]\nExecStart=\nExecStart=" + NEW_OP + "/bin/grabowski-operator\n"
                   "ExecStartPost=\nExecStartPost=" + NEW_OP + "/bin/python3 -I -B "
                   + INGRESS + " " + NEW_OP + "/share/grabowski/nixos-integrity-manifest.json\n"
                   'Environment="GRABOWSKI_PRIVILEGED_BROKER='
                   + NEW_BR + '/bin/grabowski-privileged-broker"\n'
                   + 'Environment="PATH=' + new_path + '"\n'),
        UNITS[1]: ("[Service]\nExecStart=\nExecStart=" + NEW_BR
                   + "/bin/grabowski-privileged-broker\n"
                   + 'Environment="GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT='
                   + NEW_OP + '/bin/grabowski-operator"\n'),
        UNITS[2]: "[Service]\nExecStart=\n" + schema_line + "\n",
    }

def root_dir(path: Path, mode: int, *, create: bool = False) -> None:
    if not path.exists() and create:
        path.mkdir(mode=mode)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode:
        raise TrialError("unsafe root-owned directory: " + str(path))

def exclusive_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                 | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

def dropin_paths() -> dict[str, Path]:
    return {u: RUN_ROOT / (u + ".d") / CONF for u in UNITS}

def operator_matches(root: str) -> bool:
    if value(UNITS[0], "ActiveState") != "active":
        return False
    try:
        pid = int(value(UNITS[0], "MainPID"))
        argv = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
        expected = [root + "/bin/grabowski-operator", "-m", "grabowski_operator",
                    "--transport", "streamable-http", "--host", "127.0.0.1",
                    "--port", "18181"]
        return [x.decode() for x in argv if x] == expected
    except (OSError, ValueError, UnicodeError):
        return False

def await_operator(root: str, deadline: int) -> bool:
    stop = time.monotonic() + deadline
    while time.monotonic() < stop:
        if operator_matches(root):
            if root == OLD_OP:
                return True
            try:
                with socket.create_connection(("127.0.0.1", 18181), timeout=2):
                    return True
            except OSError:
                pass
        time.sleep(2)
    return False

def remove_own_dropins(expected: dict[str, str]) -> None:
    for u, p in dropin_paths().items():
        if not p.exists():
            continue
        if digest(checked_regular(p)) != digest(expected[u].encode()):
            raise TrialError("trial drop-in modified during rollback: " + u)
        p.unlink()
        try:
            p.parent.rmdir()
        except OSError:
            pass

def revert(expected: dict[str, str]) -> None:
    remove_own_dropins(expected)
    ctl("daemon-reload")
    ctl("restart", UNITS[2])
    ctl("restart", UNITS[0])
    if not await_operator(OLD_OP, 60):
        raise TrialError("old operator not restored after trial rollback")

def plan() -> tuple[dict[str, str], dict[str, object]]:
    verified_release()
    old = original_units()
    fragments = render(old)
    root_dir(RUN_ROOT, 0o755)
    root_dir(STATE_ROOT, 0o750)
    if STATE.exists() or ACK.exists() or any(p.exists() or p.is_symlink()
                                              for p in dropin_paths().values()):
        raise TrialError("another native trial is already present")
    if value(UNITS[0], "NeedDaemonReload") != "no" or not operator_matches(OLD_OP):
        raise TrialError("original operator not serving expected preimage")
    if value("grabowski-privileged-broker.socket", "ActiveState") != "active":
        raise TrialError("original broker socket is inactive")
    proof = {"status": "ready", "head": HEAD, "desktop_changes": 0,
             "source_hashes": ORIGINAL_SHA,
             "fragments": {u: digest(s.encode()) for u, s in fragments.items()}}
    return fragments, proof

def apply() -> None:
    fragments, proof = plan()
    settled = False
    try:
        for u, path in dropin_paths().items():
            root_dir(path.parent, 0o755, create=True)
            exclusive_write(path, fragments[u].encode(), 0o644)
        exclusive_write(STATE, json.dumps(proof, sort_keys=True).encode())
        ctl("daemon-reload")
        ctl("restart", UNITS[2])
        ctl("restart", UNITS[0])
        if not await_operator(NEW_OP, 85):
            raise TrialError("new operator did not become healthy")
        print(json.dumps({"status": "serving-trial", "head": HEAD,
                          "confirmation_required": True}), flush=True)
        stop = time.monotonic() + 150
        while time.monotonic() < stop:
            if ACK.exists():
                if checked_regular(ACK) != HEAD.encode() or not operator_matches(NEW_OP):
                    raise TrialError("confirmation was invalid")
                settled = True
                print(json.dumps({"status": "confirmed", "head": HEAD}), flush=True)
                return
            if not operator_matches(NEW_OP):
                raise TrialError("new serving identity lost")
            time.sleep(2)
        raise TrialError("new serving connector did not confirm trial")
    except BaseException:
        revert(fragments)
        settled = True
        print(json.dumps({"status": "rolled-back", "head": HEAD}), flush=True)
        raise
    finally:
        # Retain the root-owned recovery record if rollback itself fails.
        if settled:
            STATE.unlink(missing_ok=True)
            ACK.unlink(missing_ok=True)

def rollback() -> None:
    paths = dropin_paths()
    if not STATE.exists() and not any(p.exists() or p.is_symlink()
                                      for p in paths.values()):
        raise TrialError("no trial state or matching drop-ins to roll back")
    fragments = render(original_units())
    revert(fragments)
    STATE.unlink(missing_ok=True)
    ACK.unlink(missing_ok=True)
    print(json.dumps({"status": "manual-rollback-complete", "head": HEAD}), flush=True)

def confirm() -> None:
    state = json.loads(checked_regular(STATE))
    if state.get("head") != HEAD or not operator_matches(NEW_OP) or ACK.exists():
        raise TrialError("no live exact candidate trial to confirm")
    exclusive_write(ACK, HEAD.encode())
    print(json.dumps({"status": "confirmation-recorded", "head": HEAD}), flush=True)

def exclusive_release_lock(*, owner_uid: int = 0) -> int:
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != owner_uid
                or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
            raise TrialError("unsafe root trial lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    options = p.add_mutually_exclusive_group(required=True)
    options.add_argument("--plan", action="store_true")
    options.add_argument("--apply", action="store_true")
    options.add_argument("--confirm", action="store_true")
    options.add_argument("--rollback", action="store_true")
    args = p.parse_args()
    if os.geteuid() != 0:
        raise TrialError("root authorization required")
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(TrialError("trial terminated")))
    if args.plan:
        _, result = plan()
        print(json.dumps(result, sort_keys=True))
    elif args.confirm:
        # The applying watchdog holds the lock; confirmation is a root-only
        # request to that same live trial, not an independent release.
        confirm()
    else:
        # Only the one owner of the root-validated lock may switch or revert.
        fd = exclusive_release_lock()
        try:
            if args.apply:
                apply()
            else:
                rollback()
        finally:
            os.close(fd)
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (TrialError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)[:350]}), file=sys.stderr)
        raise SystemExit(2)