#!/usr/bin/env python3
"""Independent LAN Wake-on-LAN recovery for heim-pc, run by heimberry systemd."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

CONFIG_PATH = Path("/etc/heim-pc-wol-recovery.json")
MIN_FAILURES = 3
COOLDOWN_SECONDS = 20 * 60
MAX_ATTEMPTS = 3


def load_config(path):
    """Read private host identifiers on the independent recovery machine."""
    data = json.loads(path.read_text(encoding="utf-8"))
    required_ips = ("lan_host", "tailnet_host", "gateway", "broadcast")
    for name in required_ips:
        value = data.get(name)
        if not isinstance(value, str):
            raise ValueError("missing or invalid recovery config field: " + name)
        ipaddress.IPv4Address(value)
    mac = data.get("mac")
    if not isinstance(mac, str) or re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac) is None:
        raise ValueError("missing or invalid recovery config field: mac")
    return data


def ssh_port_alive(host):
    try:
        with socket.create_connection((host, 22), timeout=2):
            return True
    except OSError:
        return False


def local_lan_alive(config):
    return subprocess.run(
        ["/usr/bin/ping", "-n", "-c", "1", "-W", "2", config["gateway"]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        check=False,
    ).returncode == 0


def wake(config):
    return subprocess.run(
        ["/usr/bin/wakeonlan", "-i", config["broadcast"], "-p", "9", config["mac"]],
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
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--state", type=Path, default=Path("/var/lib/heim-pc-wol-recovery/state.json"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--wake", action="store_true", help="send one manual WoL packet")
    args = parser.parse_args()
    if args.status:
        print(json.dumps(load(args.state), sort_keys=True))
        return

    config = load_config(args.config)
    if args.wake:
        print(wake(config))
        return

    state = load(args.state)
    lan = ssh_port_alive(config["lan_host"])
    tailnet = ssh_port_alive(config["tailnet_host"])
    if lan or tailnet:
        if not args.dry_run and state["failures"]:
            save(args.state, {"failures": 0, "attempts": 0, "last_wake": 0, "first_failure": 0})
        print("healthy lan=%s tailnet=%s" % (lan, tailnet))
        return

    if not local_lan_alive(config):
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
        print(wake(config))
        state["attempts"] += 1
        state["last_wake"] = now
    else:
        print("offline failures=%s wake_attempts=%s due=%s dry_run=%s" %
              (state["failures"], state["attempts"], due, args.dry_run))

    if not args.dry_run:
        save(args.state, state)


if __name__ == "__main__":
    main()
