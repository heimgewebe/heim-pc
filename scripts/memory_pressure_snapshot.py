#!/usr/bin/python3
from __future__ import annotations

import heapq
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
# A self-generated history can temporarily exceed the steady-state byte cap
# when samples are near their bounded path/row maxima. Recovery may read a
# bounded multiple so the next tick can converge it instead of wedging forever.
MAX_HISTORY_RECOVERY_BYTES = 4 * MAX_HISTORY_BYTES
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


def process_rows(proc: Path = Path("/proc")) -> list[dict[str, object]]:
    top: list[tuple[int, int, dict[str, object]]] = []
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
        pid = int(entry.name)
        total = rss + swap
        row: dict[str, object] = {
            "pid": pid,
            "name": fields.get("Name", "?")[:80],
            "uid": uid,
            "rss_bytes": rss,
            "swap_bytes": swap,
            "total_bytes": total,
            "cgroup": cgroup[:512],
        }
        candidate = (total, pid, row)
        if len(top) < TOP_PROCESSES:
            heapq.heappush(top, candidate)
        elif candidate[:2] > top[0][:2]:
            heapq.heapreplace(top, candidate)
    top.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [row for _total, _pid, row in top]


def cgroup_rows(
    root: Path = Path("/sys/fs/cgroup"),
) -> tuple[list[dict[str, object]], int, bool]:
    rows: list[dict[str, object]] = []
    scanned = 0
    truncated = False
    for base, dirs, _files in os.walk(root):
        if scanned >= MAX_CGROUPS:
            dirs[:] = []
            truncated = True
            break
        scanned += 1
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
    return rows[:TOP_CGROUPS], scanned, truncated


def validate_history() -> list[str]:
    if not HISTORY.exists():
        return []
    st = HISTORY.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise RuntimeError("unsafe history file")
    if st.st_size > MAX_HISTORY_RECOVERY_BYTES:
        raise RuntimeError("history file exceeds bounded recovery limit")
    return HISTORY.read_text(encoding="utf-8", errors="replace").splitlines()


def bounded_history(lines: list[str], current: str) -> str:
    entries = [*lines[-(MAX_HISTORY - 1):], current]
    encoded = [(line + "\n").encode("utf-8") for line in entries]
    total = sum(len(line) for line in encoded)
    while len(encoded) > 1 and total > MAX_HISTORY_BYTES:
        total -= len(encoded[0])
        del encoded[0]
    if total > MAX_HISTORY_BYTES:
        raise RuntimeError("current snapshot exceeds history byte cap")
    return b"".join(encoded).decode("utf-8")


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
    # cgroup v2 defines memory.events only for non-root cgroups. Its absence at
    # the real hierarchy root is normal, not a failed host-pressure observation.
    # Check controller availability through an interface that exists at root.
    root_memory_events_text = read_text(Path("/sys/fs/cgroup/memory.events"))
    controllers = read_text(Path("/sys/fs/cgroup/cgroup.controllers")).split()
    observation_errors: list[str] = []
    for field in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
        if field not in mem:
            observation_errors.append(f"meminfo_missing:{field}")
    if not {"some", "full"}.issubset(psi):
        observation_errors.append("memory_psi_incomplete")
    if "memory" not in controllers:
        observation_errors.append("cgroup_memory_controller_unavailable")

    mem_total = mem.get("MemTotal")
    mem_available = mem.get("MemAvailable")
    swap_total = mem.get("SwapTotal")
    swap_free = mem.get("SwapFree")

    if mem_total is not None and mem_total <= 0:
        observation_errors.append("meminfo_invalid:MemTotal")
    if mem_available is not None and (
        mem_available < 0
        or (mem_total is not None and mem_total > 0 and mem_available > mem_total)
    ):
        observation_errors.append("meminfo_invalid:MemAvailable")
    if swap_total is not None and swap_total < 0:
        observation_errors.append("meminfo_invalid:SwapTotal")
    if swap_free is not None and (
        swap_free < 0
        or (swap_total is not None and swap_total >= 0 and swap_free > swap_total)
    ):
        observation_errors.append("meminfo_invalid:SwapFree")

    memory_ratio_valid = (
        mem_total is not None
        and mem_total > 0
        and mem_available is not None
        and 0 <= mem_available <= mem_total
    )
    swap_ratio_valid = (
        swap_total is not None
        and swap_total >= 0
        and swap_free is not None
        and 0 <= swap_free <= swap_total
    )
    available_ratio = (mem_available / mem_total) if memory_ratio_valid else None
    swap_used = (swap_total - swap_free) if swap_ratio_valid else None
    swap_ratio = (
        (swap_used / swap_total)
        if swap_ratio_valid and swap_total
        else (0.0 if swap_ratio_valid else None)
    )
    some_avg10 = float(psi.get("some", {}).get("avg10", 0.0))
    full_avg10 = float(psi.get("full", {}).get("avg10", 0.0))

    top_processes = process_rows()
    top_cgroups, cgroups_scanned, cgroup_scan_truncated = cgroup_rows()
    if cgroup_scan_truncated:
        observation_errors.append("cgroup_scan_truncated")

    severity = "ok"
    if (
        (available_ratio is not None and available_ratio < 0.05)
        or (swap_ratio is not None and swap_ratio >= 0.90)
        or full_avg10 >= 20.0
    ):
        severity = "critical"
    elif (
        (available_ratio is not None and available_ratio < 0.10)
        or (swap_ratio is not None and swap_ratio >= 0.80)
        or some_avg10 >= 10.0
    ):
        severity = "warning"
    elif observation_errors:
        severity = "unknown"

    payload = {
        "schema_version": 1,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "observation_complete": not observation_errors,
        "observation_errors": observation_errors,
        "memory": {
            "total_bytes": mem_total,
            "available_bytes": mem_available,
            "available_ratio": (
                round(available_ratio, 6) if available_ratio is not None else None
            ),
            "swap_total_bytes": swap_total,
            "swap_used_bytes": swap_used,
            "swap_used_ratio": round(swap_ratio, 6) if swap_ratio is not None else None,
        },
        "pressure": psi,
        "root_memory_events": parse_key_values(root_memory_events_text),
        "root_memory_events_available": bool(root_memory_events_text),
        "top_processes": top_processes,
        "top_cgroups": top_cgroups,
        "cgroup_scan": {
            "scanned": cgroups_scanned,
            "truncated": cgroup_scan_truncated,
        },
        "bounds": {
            "history_samples": MAX_HISTORY,
            "history_bytes": MAX_HISTORY_BYTES,
            "history_recovery_bytes": MAX_HISTORY_RECOVERY_BYTES,
            "top_processes": TOP_PROCESSES,
            "top_cgroups": TOP_CGROUPS,
            "max_cgroups_scanned": MAX_CGROUPS,
        },
    }

    compact = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    atomic_write(HISTORY, bounded_history(validate_history(), compact))
    atomic_write(LATEST, json.dumps(payload, sort_keys=True, indent=2) + "\n")
    print(json.dumps({
        "status": "recorded",
        "severity": severity,
        "observation_complete": not observation_errors,
        "available_ratio": round(available_ratio, 4) if available_ratio is not None else None,
        "swap_used_ratio": round(swap_ratio, 4) if swap_ratio is not None else None,
        "psi_some_avg10": some_avg10,
        "psi_full_avg10": full_avg10,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
