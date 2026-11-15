#!/usr/bin/env python3
"""Independent Heimberry heartbeat monitor (no new daemon, no remote mutation)."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.request import Request, urlopen

KIND = "heimberry-deadman.v1"
HEARTBEAT = "/home/alex/.local/commonthing-watch-state/heartbeat.json"
SECONDS = 20 * 60
UTC = timezone.utc
TOPIC = re.compile(r"[A-Za-z0-9-]{32,128}\Z")


def iso(dt):
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_date(value):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(UTC) if dt.tzinfo else None
    except (ValueError, TypeError, AttributeError):
        return None


def observe(now):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "ConnectTimeout=6", "--", "heimberry", "cat", HEARTBEAT]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=12, check=False)
        if result.returncode != 0 or len(result.stdout) > 8192:
            return {"kind": "unobservable"}
        obj = json.loads(result.stdout)
        dt = parse_date(obj.get("checked_at_utc"))
    except (OSError, ValueError, UnicodeError, AttributeError, subprocess.TimeoutExpired):
        return {"kind": "unobservable"}
    if dt is None:
        return {"kind": "unobservable"}
    age = int((now - dt).total_seconds())
    if age < -120:
        return {"kind": "unobservable"}
    return {"kind": "healthy" if age < 15 * 60 else "stale",
            "age_seconds": max(0, age)}


def load(path):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {"kind": KIND, "last_good": None, "first_bad": None, "alerted": False}
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
            or st.st_nlink != 1 or st.st_size > 4096 or st.st_mode & 0o077):
        raise ValueError("invalid existing state file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or set(value) !=
            {"kind", "last_good", "first_bad", "alerted"} or value["kind"] != KIND
            or type(value["alerted"]) is not bool
            or any(v is not None and parse_date(v) is None
                   for v in (value["last_good"], value["first_bad"]))):
        raise ValueError("invalid existing state contents")
    return value


def persist(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".deadman-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(value, f, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def decision(before, obs, now):
    after = dict(before)
    if obs["kind"] == "healthy":
        after.update(last_good=iso(now), first_bad=None, alerted=False)
        return after, "RECOVERY" if before["alerted"] else None
    first_bad = parse_date(before["first_bad"]) or now
    after["first_bad"] = iso(first_bad)
    duration = (now - first_bad).total_seconds()
    # A sleeping/rebooting Heim-PC may have an old last_good timestamp;
    # one transient SSH failure after wake must not become an instant alert.
    # Stale heartbeat age is direct Pi evidence; SSH loss needs continuous
    # locally observed failure duration since first_bad.
    if obs["kind"] == "stale":
        duration = max(duration, obs["age_seconds"])
    if duration >= SECONDS and not before["alerted"]:
        after["alerted"] = True
        return after, "ALARM"
    return after, None


def send(topic_path, event, reason):
    st = topic_path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
            or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_size > 256):
        raise ValueError("private recipient unavailable")
    topic = topic_path.read_text(encoding="ascii").strip()
    if not TOPIC.fullmatch(topic):
        raise ValueError("invalid private recipient")
    msg = ("Heimberry-Watcher seit mindestens 20 Minuten nicht nachweisbar; "
           "Heimberry selbst ist damit nicht zwingend ausgeschaltet."
           if event == "ALARM" else "Heimberry-Watcher wieder mit frischem Heartbeat erreichbar.")
    req = Request("https://ntfy.sh/" + topic, method="POST", data=msg.encode(),
                  headers={"Title": "Heimberry " + event,
                           "Priority": "5" if event == "ALARM" else "3",
                           "User-Agent": "heimberry-deadman-v1"})
    with urlopen(req, timeout=8) as resp:
        if resp.status not in (200, 201, 202):
            raise ValueError("remote transport did not accept alert")
        resp.read(1024)


def run(now, state_path, topic_path, *, check_only=False, observer=observe, sender=send):
    old = load(state_path)
    first = observer(now)
    if first["kind"] == "healthy":
        obs = first
    else:
        again = observer(now)
        obs = again if again["kind"] == first["kind"] else {"kind": "unobservable"}
    new, event = decision(old, obs, now)
    if not check_only:
        if event:
            # Failed/uncertain HTTP must not be recorded as acknowledged.
            # Crash after HTTP acceptance but before fsync can cause a duplicate.
            try:
                sender(topic_path, event, obs["kind"])
            except Exception:
                raise RuntimeError("ntfy acceptance not confirmed") from None
        persist(state_path, new)
    return {"status": obs["kind"], "age_seconds": obs.get("age_seconds"),
            "transition": event, "dry_run": check_only,
            "ntfy_accepted": bool(event) and not check_only}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path("/var/lib/heimberry-deadman/state.json"))
    parser.add_argument("--topic-file", type=Path,
                        default=Path("/home/alex/.config/heimberry-deadman/ntfy-topic"))
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    try:
        result = run(datetime.now(UTC), args.state, args.topic_file, check_only=args.check_only)
    except (OSError, ValueError, RuntimeError) as ex:
        # Do not expose URL or topic from errors or exception strings.
        print(json.dumps({"status": "unverifiable", "error_type": type(ex).__name__}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
