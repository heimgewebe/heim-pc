#!/usr/bin/env python3
"""Generate compact, reviewable program inventory artifacts.

The large raw inventories live outside Git, usually below
~/.local/share/heim-utilities/program-inventory/. This script reads the latest
raw run when available and writes only small runtime artifacts:

- runtime/program-inventory-summary.md
- runtime/program-inventory.v1.json

It intentionally keeps raw CSV dumps out of the repository.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_DIR = Path.home() / ".local/share/heim-utilities/program-inventory/latest"
DEFAULT_SUMMARY = ROOT / "runtime/program-inventory-summary.md"
DEFAULT_JSON = ROOT / "runtime/program-inventory.v1.json"

DESKTOP_CATEGORIES = [
    "Audio / Video / Medien",
    "Browser / Kommunikation / Netzwerk",
    "Dokumente / Wissen / Office",
    "Entwicklung / Operator",
    "Grafik / Bilder",
    "Gaming / Kompatibilität",
    "System / Sicherheit / Utilities",
    "Sonstige Desktop-Starter",
]

OPERATOR_TOOL_NAMES = [
    "git", "gh", "docker", "node", "npm", "npx", "pnpm", "python3", "uv",
    "ruff", "cargo", "rustc", "codex", "claude", "gemini", "qwen", "aider",
    "openhands", "repomix", "ollama", "docling", "qpdf", "tesseract",
    "ocrmypdf", "rga", "rg", "restic", "rclone", "tailscale", "bw", "tmux",
    "difft", "yt-dlp", "ffmpeg", "ffprobe", "jq", "yq", "shellcheck",
    "shfmt", "bats", "kubectl", "helm",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def display_path(path: Path | str) -> str:
    raw = str(path)
    home = str(Path.home())
    if raw == home:
        return "~"
    if raw.startswith(home + "/"):
        return "~" + raw[len(home):]
    return raw


def sanitize_text(value: str) -> str:
    home = str(Path.home())
    return value.replace(home, "~")


def sanitize_sudo_items(items: list[Any], key_name: str) -> list[Any]:
    cleaned: list[Any] = []
    for item in items:
        if isinstance(item, dict):
            copy = dict(item)
            if key_name in copy and isinstance(copy[key_name], str):
                copy[key_name] = sanitize_text(copy[key_name])
            cleaned.append(copy)
        elif isinstance(item, (list, tuple)) and item:
            first = sanitize_text(str(item[0]))
            cleaned.append([first, *item[1:]])
        else:
            cleaned.append(item)
    return cleaned


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.rstrip("\n") for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]


def command_output(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            env={**os.environ, "PATH": f"{Path.home() / '.local/bin'}:{os.environ.get('PATH', '')}"},
        )
    except FileNotFoundError:
        return 127, "not found"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return completed.returncode, completed.stdout.strip()


def parse_flatpaks(lines: Iterable[str]) -> list[dict[str, str]]:
    apps: list[dict[str, str]] = []
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) >= 2:
            apps.append({
                "application": cols[0],
                "name": cols[1],
                "version": cols[2] if len(cols) > 2 else "",
                "installation": cols[3] if len(cols) > 3 else "",
            })
    return sorted(apps, key=lambda row: row["name"].lower())


def parse_snaps(lines: Iterable[str]) -> list[dict[str, str]]:
    snaps: list[dict[str, str]] = []
    for line in lines:
        if not line.strip() or line.startswith("#") or line.startswith("Name "):
            continue
        cols = line.split()
        if len(cols) >= 4:
            snaps.append({"name": cols[0], "version": cols[1], "revision": cols[2], "channel": cols[3]})
    return sorted(snaps, key=lambda row: row["name"].lower())


def parse_containers(lines: Iterable[str]) -> list[dict[str, str]]:
    containers: list[dict[str, str]] = []
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) >= 3:
            containers.append({
                "name": cols[0],
                "image": cols[1],
                "status": cols[2],
                "ports": cols[3] if len(cols) > 3 else "",
            })
    return sorted(containers, key=lambda row: row["name"].lower())


def categorize_desktop_app(name: str, categories: str) -> str:
    lowered = name.lower()
    if any(x in categories for x in ["Development", "IDE"]) or any(x in lowered for x in ["code", "pycharm", "datagrip", "fleet", "git", "postman", "insomnia", "cursor", "antigravity", "zed", "vim"]):
        return "Entwicklung / Operator"
    if any(x in categories for x in ["Office", "Education"]) or any(x in lowered for x in ["libreoffice", "obsidian", "pdf", "document", "paper", "muse", "schule"]):
        return "Dokumente / Wissen / Office"
    if any(x in categories for x in ["Audio", "Video", "Music"]) or any(x in lowered for x in ["ardour", "audacity", "vlc", "obs", "kdenlive", "musescore", "easyeffects", "spotify", "kodi"]):
        return "Audio / Video / Medien"
    if any(x in categories for x in ["Network", "WebBrowser", "Email", "Chat"]) or any(x in lowered for x in ["brave", "chrome", "firefox", "signal", "discord", "mattermost", "whatsapp", "zoom", "geary", "ferdium", "localsend"]):
        return "Browser / Kommunikation / Netzwerk"
    if any(x in categories for x in ["System", "Settings", "Utility"]) or any(x in lowered for x in ["system", "settings", "disk", "gparted", "flatseal", "veracrypt", "timeshift", "stacer", "solaar", "tailscale"]):
        return "System / Sicherheit / Utilities"
    if any(x in categories for x in ["Graphics", "Photography"]) or any(x in lowered for x in ["gimp", "inkscape", "image", "photo", "krita"]):
        return "Grafik / Bilder"
    if "Game" in categories or any(x in lowered for x in ["steam", "lutris", "wine"]):
        return "Gaming / Kompatibilität"
    return "Sonstige Desktop-Starter"


def desktop_groups(rows: list[dict[str, str]]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {name: [] for name in DESKTOP_CATEGORIES}
    for row in rows:
        name = row.get("name", "").strip()
        if not name:
            continue
        groups[categorize_desktop_app(name, row.get("categories", ""))].append(name)
    return {key: sorted(set(values), key=str.lower) for key, values in groups.items() if values}


def top_prefix(rows: list[dict[str, str]], depth: int = 3, limit: int = 20) -> list[dict[str, int | str]]:
    counter: Counter[str] = Counter()
    for row in rows:
        path = row.get("path", "")
        if not path:
            continue
        parts = Path(path).parts
        key = "/".join(parts[:depth]).replace("//", "/") if len(parts) > depth else path
        counter[key] += 1
    return [{"prefix": key, "count": count} for key, count in counter.most_common(limit)]


def top_names(rows: list[dict[str, str]], limit: int = 25) -> list[dict[str, int | str]]:
    counter = Counter(row.get("name", "") for row in rows if row.get("name"))
    return [{"name": key, "count": count} for key, count in counter.most_common(limit)]


def operator_tools(executable_rows: list[dict[str, str]]) -> dict[str, list[str]]:
    by_name: dict[str, list[str]] = defaultdict(list)
    for row in executable_rows:
        name = row.get("name", "")
        if name in OPERATOR_TOOL_NAMES:
            path = row.get("path", "")
            if path:
                by_name[name].append(display_path(path))
    return {name: sorted(set(paths))[:5] for name, paths in sorted(by_name.items())}


def build_snapshot(raw_dir: Path, *, generated_at: str | None = None) -> dict[str, Any]:
    generated_at = generated_at or utc_now()
    run_result = read_json(raw_dir / "run-result.json", {})
    sudo_result = read_json(raw_dir / "full-rootfs-sudo-scan-result.json", {})
    non_sudo_result = read_json(raw_dir / "full-rootfs-scan-result.json", {})
    sudo_delta = read_json(raw_dir / "sudo-delta-summary.json", {})

    desktop_rows = read_csv(raw_dir / "desktop_apps.csv")
    process_rows = read_csv(raw_dir / "running_processes.csv")
    executable_rows = read_csv(raw_dir / "executables.csv")
    added_by_sudo = read_csv(raw_dir / "executables_added_by_sudo.csv")
    flatpaks = parse_flatpaks(read_lines(raw_dir / "flatpak_apps.tsv"))
    snaps = parse_snaps(read_lines(raw_dir / "snap_list.txt"))
    containers = parse_containers(read_lines(raw_dir / "docker_ps.tsv"))

    process_counts = Counter(row.get("comm", "") for row in process_rows if row.get("comm"))
    raw_files = sorted(path.name for path in raw_dir.iterdir()) if raw_dir.exists() else []

    counts = {
        "running_process_rows": int(run_result.get("process_rows", len(process_rows) or 0)),
        "running_process_names": len(process_counts),
        "desktop_apps": int(run_result.get("desktop_apps", len(desktop_rows) or 0)),
        "flatpak_apps": len(flatpaks),
        "snap_packages": len(snaps),
        "docker_containers": len(containers),
        "curated_executables": int(run_result.get("executables", len(executable_rows) or 0)),
        "rootfs_executables_non_sudo": int(non_sudo_result.get("count", 0)),
        "rootfs_executables_sudo": int(sudo_result.get("count", 0)),
        "executables_added_by_sudo": int(sudo_delta.get("added_by_sudo", len(added_by_sudo) or 0)),
    }

    snapshot: dict[str, Any] = {
        "schema": "program-inventory.v1",
        "generated_at": generated_at,
        "source_inventory_path": display_path(raw_dir),
        "counts": counts,
        "scan_boundaries": {
            "repo_policy": "Commit compact summaries and generator logic only; keep raw CSV/TXT inventories local.",
            "included_sources": [
                "running processes", "systemd services", "Docker containers/images", "Flatpak apps", "Snap packages",
                "apt/dpkg packages", "desktop starters", "local tool dirs", "rootfs executable metadata scan",
            ],
            "excluded_from_git": ["executables_full_rootfs_sudo.csv", "executables_full_rootfs.csv", "programs_all.csv", "raw process/package dumps"],
            "sudo_note": sudo_result.get("note", "sudo scan unavailable"),
            "permission_warnings": [sanitize_text(str(w)) for w in sudo_result.get("stderr_tail", [])[-10:]],
        },
        "running_process_top": [{"name": name, "count": count} for name, count in process_counts.most_common(40)],
        "docker_containers": containers,
        "flatpak_apps": flatpaks,
        "snap_packages": snaps,
        "desktop_groups": desktop_groups(desktop_rows),
        "operator_tools": operator_tools(executable_rows),
        "sudo_delta": {
            "additional_count": counts["executables_added_by_sudo"],
            "top_prefixes": sanitize_sudo_items(sudo_delta.get("top_added_prefixes") or top_prefix(added_by_sudo), "prefix"),
            "top_names": sanitize_sudo_items(sudo_delta.get("top_added_names") or top_names(added_by_sudo), "name"),
        },
        "raw_files_reference": raw_files,
    }
    return snapshot


def render_markdown(snapshot: dict[str, Any]) -> str:
    counts = snapshot["counts"]
    lines = [
        "---",
        "id: program-inventory-summary",
        "role: reality",
        "status: canonical",
        "last_reviewed: 2026-07-09",
        "depends_on:",
        "  - software-inventory",
        "verifies_with:",
        "  - scripts/generate_program_inventory.py",
        "  - runtime/program-inventory.v1.json",
        "---",
        "",
        "# Program Inventory Summary",
        "",
        f"Generated at: `{snapshot['generated_at']}`",
        f"Raw inventory source: `{snapshot['source_inventory_path']}`",
        "",
        "## Boundary",
        "",
        "This document is a compact, reviewable summary of the current heim-pc program surface. Large raw inventories stay outside Git under `~/.local/share/heim-utilities/program-inventory/`.",
        "",
        "The summary may include program names, executable metadata counts, package managers, service/container names and safe paths to local inventory artifacts. It must not contain secrets, browser profiles, private file contents, keyrings or raw history.",
        "",
        "## Counts",
        "",
        "| Area | Count |",
        "|---|---:|",
    ]
    count_labels = {
        "running_process_rows": "Running process rows",
        "running_process_names": "Unique running process names",
        "desktop_apps": "Desktop starters",
        "flatpak_apps": "Flatpak apps",
        "snap_packages": "Snap packages",
        "docker_containers": "Docker containers",
        "curated_executables": "Executables in curated program roots",
        "rootfs_executables_non_sudo": "Executables on rootfs, non-sudo",
        "rootfs_executables_sudo": "Executables on rootfs, sudo",
        "executables_added_by_sudo": "Executables additionally visible through sudo",
    }
    for key, label in count_labels.items():
        lines.append(f"| {label} | {counts.get(key, 0)} |")

    lines += ["", "## Running process focus", ""]
    for row in snapshot.get("running_process_top", [])[:40]:
        lines.append(f"- `{row['name']}`: {row['count']}")

    lines += ["", "## Docker containers", ""]
    for row in snapshot.get("docker_containers", []):
        lines.append(f"- `{row['name']}` — `{row['image']}` — {row['status']}")

    lines += ["", "## Flatpak apps", ""]
    for row in snapshot.get("flatpak_apps", []):
        version = f" {row['version']}" if row.get("version") else ""
        lines.append(f"- {row['name']}{version} — `{row['application']}` ({row.get('installation', '')})")

    lines += ["", "## Snap packages", ""]
    for row in snapshot.get("snap_packages", []):
        lines.append(f"- {row['name']} {row['version']} — {row['channel']}")

    lines += ["", "## Desktop programs by work area", ""]
    for category, names in snapshot.get("desktop_groups", {}).items():
        lines += [f"### {category} ({len(names)})", ""]
        for name in names:
            lines.append(f"- {name}")
        lines.append("")

    lines += ["## Operator CLI tools", ""]
    for name, paths in snapshot.get("operator_tools", {}).items():
        formatted = ", ".join(f"`{path}`" for path in paths)
        lines.append(f"- `{name}`: {formatted}")

    sudo_delta = snapshot.get("sudo_delta", {})
    lines += [
        "",
        "## Sudo rootfs scan delta",
        "",
        f"Additional executables visible through sudo: **{sudo_delta.get('additional_count', 0)}**",
        "",
        "### Top additional path prefixes",
        "",
    ]
    for item in sudo_delta.get("top_prefixes", [])[:20]:
        if isinstance(item, dict):
            prefix, count = item.get("prefix"), item.get("count")
        else:
            prefix, count = item[0], item[1]
        lines.append(f"- `{prefix}`: {count}")
    lines += ["", "### Top additional executable names", ""]
    for item in sudo_delta.get("top_names", [])[:25]:
        if isinstance(item, dict):
            name, count = item.get("name"), item.get("count")
        else:
            name, count = item[0], item[1]
        lines.append(f"- `{name}`: {count}")

    lines += ["", "## Raw artifact policy", ""]
    for file_name in snapshot.get("raw_files_reference", []):
        if file_name.endswith((".csv", ".tsv", ".txt", ".json", ".md")):
            lines.append(f"- `{file_name}`")
    lines += ["", "## Scan caveats", ""]
    for warning in snapshot.get("scan_boundaries", {}).get("permission_warnings", []):
        lines.append(f"- `{warning}`")
    if not snapshot.get("scan_boundaries", {}).get("permission_warnings"):
        lines.append("- No permission warnings recorded in the compact snapshot.")
    lines.append("")
    return "\n".join(lines)


def write_outputs(snapshot: dict[str, Any], summary_out: Path, json_out: Path) -> None:
    summary_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    summary_out.write_text(render_markdown(snapshot), encoding="utf-8")
    json_out.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate compact heim-pc program inventory artifacts.")
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR, help="Directory containing local raw program inventory files.")
    parser.add_argument("--summary-out", type=Path, default=DEFAULT_SUMMARY, help="Markdown summary output path.")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON, help="Compact JSON output path.")
    parser.add_argument("--generated-at", default=None, help="Override generated_at for deterministic tests.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    snapshot = build_snapshot(args.raw_dir.expanduser().resolve(), generated_at=args.generated_at)
    write_outputs(snapshot, args.summary_out, args.json_out)
    print(args.summary_out)
    print(args.json_out)


if __name__ == "__main__":
    main()
