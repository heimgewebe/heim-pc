#!/usr/bin/python3
from __future__ import annotations

import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path("/var/lib/heim-pc/memory-pressure")
HISTORY = STATE_DIR / "history.jsonl"
LATEST = STATE_DIR / "latest.json"
MAX_HISTORY = 240
MAX_HISTORY_BYTES = 5 * 1024 * 1024
MAX_CGROUPS = 4096
TOP_PROCESSES = 30
TOP_CGROUPS = 30


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return ""


def read_int(path: Path) -> int:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return 0


def parse_key_values(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return result


def meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in read_text(Path("/proc/meminfo")).splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.strip().split()
        if not parts:
            continue
        try:
            value = int(parts[0])
        except ValueError:
            continue
        if len(parts) > 1 and parts[1] == "kB":
            value *= 1024
        values[key] = value
    return values


def pressure() -> dict[str, dict[str, float | int]]:
    result: dict[str, dict[str, float | int]] = {}
    for line in read_text(Path("/proc/pressure/memory")).splitlines():
        parts = line.split()
        if not parts:
            continue
        row: dict[str, float | int] = {}
        for item in parts[1:]:
            if "=" not in item:
                continue
            key, raw = item.split("=", 1)
            try:
                row[key] = int(raw) if key == "total" else float(raw)
            except ValueError:
                pass
        result[parts[0]] = row
    return result


def process_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        status_text = read_text(entry / "status")
        if not status_text:
            continue
        fields: dict[str, str] = {}
        for line in status_text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                if key in {"Name", "VmRSS", "VmSwap", "Uid"}:
                    fields[key] = value.strip()
        def kb(name: str) -> int:
            raw = fields.get(name, "0").split()
            try:
                return int(raw[0]) * 1024
            except (ValueError, IndexError):
                return 0
        rss = kb("VmRSS")
        swap = kb("VmSwap")
        if rss == 0 and swap == 0:
            continue
        cgroup = ""
        for line in read_text(entry / "cgroup").splitlines():
            if line.startswith("0::"):
                cgroup = line[3:]
                break
        uid_raw = fields.get("Uid", "").split()
        uid = int(uid_raw[0]) if uid_raw and uid_raw[0].isdigit() else None
        rows.append({
            "pid": int(entry.name),
            "name": fields.get("Name", "?")[:80],
            "uid": uid,
            "rss_bytes": rss,
            "swap_bytes": swap,
            "total_bytes": rss + swap,
            "cgroup": cgroup[:512],
        })
    rows.sort(key=lambda row: int(row["total_bytes"]), reverse=True)
    return rows[:TOP_PROCESSES]


def cgroup_rows() -> list[dict[str, object]]:
    root = Path("/sys/fs/cgroup")
    rows: list[dict[str, object]] = []
    seen = 0
    for base, dirs, _files in os.walk(root):
        seen += 1
        if seen > MAX_CGROUPS:
            dirs[:] = []
            break
        path = Path(base)
        current = read_int(path / "memory.current")
        swap = read_int(path / "memory.swap.current")
        if current == 0 and swap == 0:
            continue
        events = parse_key_values(read_text(path / "memory.events"))
        cg_events = parse_key_values(read_text(path / "cgroup.events"))
        try:
            relative = "/" + str(path.relative_to(root))
        except ValueError:
            relative = str(path)
        if relative == "/.":
            relative = "/"
        rows.append({
            "path": relative[:1024],
            "memory_bytes": current,
            "swap_bytes": swap,
            "total_bytes": current + swap,
            "populated": bool(cg_events.get("populated", 0)),
            "oom": events.get("oom", 0),
            "oom_kill": events.get("oom_kill", 0),
        })
    rows.sort(key=lambda row: int(row["total_bytes"]), reverse=True)
    return rows[:TOP_CGROUPS]


def validate_history() -> list[str]:
    if not HISTORY.exists():
        return []
    st = HISTORY.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_HISTORY_BYTES:
        raise RuntimeError("unsafe or oversized history file")
    lines = HISTORY.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-(MAX_HISTORY - 1):]


def atomic_write(path: Path, data: str) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(STATE_DIR))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = STATE_DIR.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise RuntimeError("unsafe state directory")

    mem = meminfo()
    psi = pressure()
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    mem_total = mem.get("MemTotal", 0)
    mem_available = mem.get("MemAvailable", 0)
    swap_used = max(0, swap_total - swap_free)

    available_ratio = (mem_available / mem_total) if mem_total else 0.0
    swap_ratio = (swap_used / swap_total) if swap_total else 0.0
    some_avg10 = float(psi.get("some", {}).get("avg10", 0.0))
    full_avg10 = float(psi.get("full", {}).get("avg10", 0.0))

    severity = "ok"
    if available_ratio < 0.05 or swap_ratio >= 0.90 or full_avg10 >= 20.0:
        severity = "critical"
    elif available_ratio < 0.10 or swap_ratio >= 0.80 or some_avg10 >= 10.0:
        severity = "warning"

    payload = {
        "schema_version": 1,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "memory": {
            "total_bytes": mem_total,
            "available_bytes": mem_available,
            "available_ratio": round(available_ratio, 6),
            "swap_total_bytes": swap_total,
            "swap_used_bytes": swap_used,
            "swap_used_ratio": round(swap_ratio, 6),
        },
        "pressure": psi,
        "root_memory_events": parse_key_values(read_text(Path("/sys/fs/cgroup/memory.events"))),
        "top_processes": process_rows(),
        "top_cgroups": cgroup_rows(),
        "bounds": {
            "history_samples": MAX_HISTORY,
            "top_processes": TOP_PROCESSES,
            "top_cgroups": TOP_CGROUPS,
            "max_cgroups_scanned": MAX_CGROUPS,
        },
    }

    compact = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    lines = validate_history()
    lines.append(compact)
    atomic_write(HISTORY, "\n".join(lines) + "\n")
    atomic_write(LATEST, json.dumps(payload, sort_keys=True, indent=2) + "\n")
    print(json.dumps({
        "status": "recorded",
        "severity": severity,
        "available_ratio": round(available_ratio, 4),
        "swap_used_ratio": round(swap_ratio, 4),
        "psi_some_avg10": some_avg10,
        "psi_full_avg10": full_avg10,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())