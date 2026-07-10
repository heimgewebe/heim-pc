#!/usr/bin/env python3
"""Collect raw local program inventory artifacts outside Git.

This collector writes raw CSV/TXT files below
~/.local/share/heim-utilities/program-inventory/<timestamp>/ and updates the
latest symlink. It does not read private file contents; executable scans record
metadata only: path, size and mtime.
"""
from __future__ import annotations

import csv
import json
import os
import socket
import stat
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

HOME = Path.home()
OUT_ROOT = HOME / ".local/share/heim-utilities/program-inventory"
SKIP_PREFIXES = (
    "/proc/", "/sys/", "/dev/", "/run/", "/tmp/", "/var/tmp/", "/mnt/", "/media/", "/lost+found/",
)
SCAN_ROOTS = [
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
    "/opt", "/var/lib/flatpak", "/var/lib/snapd", "/var/snap",
    str(HOME / ".local/bin"), str(HOME / ".cargo/bin"), str(HOME / "go/bin"),
    str(HOME / ".local/share/uv/tools"), str(HOME / ".local/pipx"), str(HOME / "snap"),
    str(HOME / "Applications"), str(HOME / ".local/share/applications"), str(HOME / ".config/systemd/user"),
]
RAW_COMMANDS = {
    "processes_ps.tsv": ["ps", "-eo", "pid,ppid,user,stat,comm,args", "--no-headers"],
    "systemd_user_services.txt": ["systemctl", "--user", "list-units", "--type=service", "--all", "--no-pager"],
    "systemd_system_services.txt": ["systemctl", "list-units", "--type=service", "--all", "--no-pager"],
    "docker_ps.tsv": ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"],
    "docker_images.tsv": ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}"],
    "flatpak_apps.tsv": ["flatpak", "list", "--app", "--columns=application,name,version,installation"],
    "snap_list.txt": ["snap", "list"],
    "apt_manual.txt": ["apt-mark", "showmanual"],
    "dpkg_packages.tsv": ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${binary:Summary}\n"],
    "pipx_list.txt": ["pipx", "list", "--short"],
    "npm_globals.txt": ["npm", "list", "-g", "--depth=0"],
    "pnpm_globals.txt": ["pnpm", "list", "-g", "--depth=0"],
    "cargo_installs.txt": ["bash", "-lc", "command -v cargo >/dev/null && cargo install --list || true"],
    "ollama_list.txt": ["ollama", "list"],
    "tailscale_targets.txt": ["tailscale", "file", "cp", "--targets"],
}


def run(argv: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.returncode, p.stdout.rstrip()
    except Exception as exc:
        return 999, f"ERR {type(exc).__name__}: {exc}"


def write_text(out: Path, name: str, text: str) -> None:
    (out / name).write_text(text.rstrip() + "\n", encoding="utf-8")


def is_executable(path: Path) -> bool:
    try:
        st = path.stat()
        return path.is_file() and bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except Exception:
        return False


def collect_desktop_apps(out: Path) -> int:
    apps: list[dict[str, str]] = []
    roots = [
        Path("/usr/share/applications"),
        HOME / ".local/share/applications",
        Path("/var/lib/flatpak/exports/share/applications"),
        HOME / ".local/share/flatpak/exports/share/applications",
    ]
    for root in roots:
        if not root.exists():
            continue
        for desktop_file in root.glob("*.desktop"):
            data: dict[str, str] = {}
            try:
                for line in desktop_file.read_text(errors="ignore").splitlines():
                    if "=" in line and not line.startswith("#"):
                        key, value = line.split("=", 1)
                        if key in {"Name", "GenericName", "Comment", "Exec", "NoDisplay", "Hidden", "Categories"}:
                            data[key] = value
            except Exception:
                continue
            if data.get("NoDisplay", "false").lower() == "true" or data.get("Hidden", "false").lower() == "true":
                continue
            if data.get("Name"):
                apps.append({
                    "name": data.get("Name", ""),
                    "generic": data.get("GenericName", ""),
                    "categories": data.get("Categories", ""),
                    "exec": data.get("Exec", ""),
                    "desktop_file": str(desktop_file),
                })
    with (out / "desktop_apps.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "generic", "categories", "exec", "desktop_file"])
        writer.writeheader()
        writer.writerows(sorted(apps, key=lambda row: row["name"].lower()))
    return len(apps)


def collect_processes(out: Path) -> int:
    rows: list[dict[str, str]] = []
    rc, output = run(["ps", "-eo", "pid=,ppid=,user=,stat=,comm=,args="], timeout=20)
    if rc == 0:
        for line in output.splitlines():
            parts = line.strip().split(None, 5)
            if len(parts) >= 5:
                pid, ppid, user, stat_value, comm = parts[:5]
                args = parts[5] if len(parts) > 5 else ""
                rows.append({"pid": pid, "ppid": ppid, "user": user, "stat": stat_value, "comm": comm, "args": args})
    with (out / "running_processes.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["pid", "ppid", "user", "stat", "comm", "args"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def add_executable(rows: list[dict[str, Any]], seen: set[str], path: Path, source: str) -> None:
    try:
        resolved = str(path.resolve()) if path.exists() else str(path)
        if resolved in seen:
            return
        seen.add(resolved)
        st = path.stat()
        rows.append({"name": path.name, "path": str(path), "resolved": resolved, "source": source, "size": st.st_size, "mtime": int(st.st_mtime)})
    except Exception:
        return


def collect_curated_executables(out: Path) -> int:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dir_s in os.environ.get("PATH", "").split(":"):
        if not dir_s:
            continue
        directory = Path(dir_s).expanduser()
        if directory.is_dir():
            for path in directory.iterdir():
                if is_executable(path):
                    add_executable(rows, seen, path, "PATH")
    for root_s in SCAN_ROOTS:
        root = Path(root_s).expanduser()
        if not root.exists():
            continue
        for path in root.rglob("*"):
            raw = str(path)
            if raw.startswith(SKIP_PREFIXES):
                continue
            if is_executable(path):
                add_executable(rows, seen, path, "fs-scan")
    with (out / "executables.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "path", "resolved", "source", "size", "mtime"])
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: (row["name"].lower(), row["path"])))
    return len(rows)


def collect_rootfs_executables(out: Path) -> dict[str, Any]:
    stdout_path = out / "executables_full_rootfs.csv"
    stderr_path = out / "executables_full_rootfs.stderr"
    start = time.time()
    cmd = [
        "find", "/", "-xdev",
        "(", "-path", "/proc", "-o", "-path", "/sys", "-o", "-path", "/dev", "-o", "-path", "/run", "-o", "-path", "/tmp", "-o", "-path", "/var/tmp", "-o", "-path", "/mnt", "-o", "-path", "/media", "-o", "-path", "/lost+found", ")", "-prune", "-o",
        "-type", "f", "-perm", "/111", "-printf", "%p\t%s\t%T@\n",
    ]
    proc = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=240)
    rows = []
    for line in proc.stdout.splitlines():
        try:
            path, size, mtime = line.split("\t", 2)
        except ValueError:
            continue
        rows.append({"name": Path(path).name, "path": path, "size": size, "mtime": mtime})
    with stdout_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "path", "size", "mtime"])
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: (row["name"].lower(), row["path"])))
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    result = {"count": len(rows), "rc": proc.returncode, "duration_sec": round(time.time() - start, 2), "stderr_tail": proc.stderr.splitlines()[-50:]}
    (out / "full-rootfs-scan-result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def main() -> None:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = OUT_ROOT / stamp
    out.mkdir(parents=True, exist_ok=True)
    start = time.time()
    for name, argv in RAW_COMMANDS.items():
        rc, output = run(argv)
        write_text(out, name, f"# rc={rc}\n{output}")
    desktop_count = collect_desktop_apps(out)
    process_count = collect_processes(out)
    executable_count = collect_curated_executables(out)
    rootfs = collect_rootfs_executables(out)
    result = {
        "out": str(out),
        "host": socket.gethostname(),
        "duration_sec": round(time.time() - start, 2),
        "process_rows": process_count,
        "desktop_apps": desktop_count,
        "executables": executable_count,
        "rootfs_executables_non_sudo": rootfs.get("count", 0),
        "note": "raw local inventory; keep outside Git",
    }
    (out / "run-result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary = ["# Heim-PC raw program inventory", "", f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}", f"Output: `{out}`", "", "## Counts", "", f"- running_process_rows: {process_count}", f"- desktop_apps: {desktop_count}", f"- curated_executables: {executable_count}", f"- rootfs_executables_non_sudo: {rootfs.get('count', 0)}", "", "Run `scripts/program_inventory_sudo_scan.sh` for the optional sudo rootfs metadata scan."]
    (out / "SUMMARY.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    latest = OUT_ROOT / "latest"
    latest.unlink(missing_ok=True)
    latest.symlink_to(out)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
