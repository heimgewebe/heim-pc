#!/usr/bin/env python3
"""Independent LAN Wake-on-LAN recovery for heim-pc, run by heimberry systemd."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

LAN_HOST = "192.168.178.55"
TAILNET_HOST = "100.68.88.111"
GATEWAY = "192.168.178.1"
BROADCAST = "192.168.178.255"
MAC = "c8:7f:54:6f:0d:1a"
MIN_FAILURES = 3
COOLDOWN_SECONDS = 20 * 60
MAX_ATTEMPTS = 3


def ssh_port_alive(host):
    try:
        with socket.create_connection((host, 22), timeout=2):
            return True
    except OSError:
        return False


def local_lan_alive():
    return subprocess.run(
        ["/usr/bin/ping", "-n", "-c", "1", "-W", "2", GATEWAY],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        check=False,
    ).returncode == 0


def wake():
    return subprocess.run(
        ["/usr/bin/wakeonlan", "-i", BROADCAST, "-p", "9", MAC],
        check=True, timeout=10, capture_output=True, text=True,
    ).stdout.strip()


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"failures": 0, "attempts": 0, "last_wake": 0, "first_failure": 0}


def save(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".state-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, sort_keys=True)
            stream.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path("/var/lib/heim-pc-wol-recovery/state.json"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--wake", action="store_true", help="send one manual WoL packet")
    args = parser.parse_args()
    if args.status:
        print(json.dumps(load(args.state), sort_keys=True))
        return
    if args.wake:
        print(wake())
        return

    state = load(args.state)
    lan = ssh_port_alive(LAN_HOST)
    tailnet = ssh_port_alive(TAILNET_HOST)
    if lan or tailnet:
        if not args.dry_run and state["failures"]:
            save(args.state, {"failures": 0, "attempts": 0, "last_wake": 0, "first_failure": 0})
        print("healthy lan=%s tailnet=%s" % (lan, tailnet))
        return

    if not local_lan_alive():
        print("LAN gateway unreachable; no wake packet sent")
        return

    now = int(time.time())
    state["failures"] += 1
    if state["first_failure"] == 0:
        state["first_failure"] = now

    due = (
        state["failures"] >= MIN_FAILURES
        and state["attempts"] < MAX_ATTEMPTS
        and now - state["last_wake"] >= COOLDOWN_SECONDS
    )
    if due and not args.dry_run:
        print(wake())
        state["attempts"] += 1
        state["last_wake"] = now
    else:
        print("offline failures=%s wake_attempts=%s due=%s dry_run=%s" %
              (state["failures"], state["attempts"], due, args.dry_run))

    if not args.dry_run:
        save(args.state, state)


if __name__ == "__main__":
    main()
