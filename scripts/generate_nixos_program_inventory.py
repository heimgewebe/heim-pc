#!/usr/bin/env python3
"""Bounded metadata-only NixOS observation; never reads app configuration contents."""
from __future__ import annotations

import argparse
import configparser
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
# Host-local roles supplied by the operator, not ecosystem ownership or health.
APPS = {
    "paperless": ("Paperless", "Dokumente und OCR", "compose"),
    "audiobookshelf": ("Audiobookshelf", "Hörbücher und Podcasts", "quadlet"),
    "readeck": ("Readeck", "Leseliste und Webarchiv", "quadlet"),
    "immich": ("Immich", "Fotoverwaltung", "compose"),
    "penpot": ("Penpot", "Design und Prototypen", "compose"),
    "filebrowser": ("FileBrowser Quantum", "Dateiverwaltung", "quadlet"),
    "it-tools": ("IT Tools", "Lokale Entwicklerwerkzeuge", "quadlet"),
}
CLI = ("git", "gh", "nix", "podman", "restic", "python3", "node", "npm",
       "rg", "jq", "uv", "ffmpeg", "tesseract", "ocrmypdf", "mcp-inspector")
UNIT_STATES = {"enabled", "enabled-runtime", "disabled", "static", "indirect",
               "alias", "generated", "transient", "masked", "masked-runtime", "linked",
               "linked-runtime", "not-found"}



def scan_desktop_apps(directory: Path) -> list[dict[str, str]]:
    """Only visible NixOS system launchers, never user .desktop/profile contents."""
    if not directory.is_dir():
        raise FileNotFoundError("NixOS application directory missing")
    rows = []
    for path in sorted(directory.glob("*.desktop")):
        entry = configparser.ConfigParser(interpolation=None, strict=False)
        entry.read(path, encoding="utf-8")
        if "Desktop Entry" not in entry:
            raise ValueError("Malformed system desktop entry")
        app = entry["Desktop Entry"]
        if app.getboolean("NoDisplay", fallback=False) or app.getboolean("Hidden", fallback=False):
            continue
        if app.get("Type", "Application") != "Application":
            continue
        rows.append({"id": safe_name(path.stem),
                     "name": safe_name(app.get("Name", path.stem))})
    return sorted(rows, key=lambda row: (row["name"].casefold(), row["id"]))


def safe_name(value):
    """Reject rather than publish unstructured or potentially identifying metadata."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._+()-]{0,95}", value):
        return "[redacted]"
    if re.search(r"(?:\d{1,3}\.){3}\d{1,3}|tailscale|tailnet|token|secret|password", value, re.I):
        return "[redacted]"
    return value


def version(value):
    # Only the version token, never arbitrary CLI lines, URLs, paths or diagnostics.
    value = value.splitlines()[0] if value.splitlines() else ""
    if re.search(r"(?:\d{1,3}\.){3}\d{1,3}|https?://|/nix/store/|@|tailscale|tailnet", value, re.I):
        return "[redacted]"
    match = re.search(r"(?<![\w./])v?(\d+\.\d+(?:\.[0-9A-Za-z]+)*(?:[-+][0-9A-Za-z.-]+)?)(?![\w/])", value)
    return match.group(1)[:80] if match else "unknown"


def run(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15,
                                env={**os.environ, "LC_ALL": "C", "NO_COLOR": "1", "PATH": f"{Path.home() / '.local/bin'}:{Path.home() / '.nix-profile/bin'}:{os.environ.get('PATH', '')}"})
        return result.returncode, result.stdout
    except FileNotFoundError:
        return 127, ""
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return 126, ""


def collect(runner=run, clock=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"), desktop_loader=None):
    if os.geteuid() == 0:
        raise PermissionError("Run as the desktop user; root inventory is excluded")
    def observe(argv, parser, accepted=(0,)):
        started = clock()
        rc, output = runner(argv)
        row = {"source": " ".join(argv), "observed_at": started,
               "status": "unavailable" if rc == 127 else "error", "exit_code": rc}
        if rc in accepted:
            try:
                row["items"] = parser(output)
                row["status"] = "ok"
            except (ValueError, TypeError, KeyError, AttributeError, IndexError):
                row["reason"] = "invalid_output"
        return row

    def profiles(output):
        data = json.loads(output)
        if not isinstance(data["elements"], dict):
            raise ValueError()
        return sorted({safe_name(name) for name in data["elements"]})

    def flatpaks(output):
        rows = []
        for line in output.splitlines():
            app, name, ver = line.split("\t")
            rows.append({"id": safe_name(app), "name": safe_name(name),
                         "version": version(ver)})
        return sorted(rows, key=lambda row: row["id"])

    def containers(output):
        rows = []
        for line in output.splitlines():
            name, image = line.split("\t")
            # Only curated application groups and their DB/helper containers.
            if not any(re.fullmatch(r"(?:heimgewebe-)?" + re.escape(app) + r"(?:[-_][a-z0-9_-]+)*", name)
                       for app in APPS):
                continue
            # Drop registry/repository, digest and all addresses; retain tag only.
            leaf = image.rsplit("/", 1)[-1]
            tag = ("digest-pinned" if "@sha256:" in leaf else
                   leaf.rsplit(":", 1)[1] if ":" in leaf else "unknown")
            rows.append({"name": safe_name(name), "image_version": safe_name(tag)})
        return sorted(rows, key=lambda row: row["name"])

    def os_version(output):
        value = version(output)
        if value in {"unknown", "[redacted]"}:
            raise ValueError()
        return [{"name": "NixOS", "version": value}]

    if desktop_loader is None:
        desktop_loader = lambda: scan_desktop_apps(Path("/run/current-system/sw/share/applications"))
    started_desktop = clock()
    desktop = {"source": "NixOS system desktop entries (system-only)",
               "observed_at": started_desktop, "status": "error", "exit_code": 1}
    try:
        desktop["items"] = desktop_loader()
        desktop["status"] = "ok"
        desktop["exit_code"] = 0
    except FileNotFoundError:
        desktop["status"] = "unavailable"
        desktop["exit_code"] = 127
    except (OSError, ValueError, TypeError, configparser.Error):
        desktop["reason"] = "invalid_output"
    snapshot = {"schema": "nixos-program-inventory.v1", "role": "reality",
                "temporal_scope": "point_in_time", "observed_at": clock(),
                "scope": "heim-pc; curated metadata; no health or completeness claim",
                "os": observe(["nixos-version"], os_version),
                "desktop_apps": desktop,
                "nix_profiles": observe(["nix", "profile", "list", "--json"], profiles),
                "flatpak": observe(["flatpak", "list", "--app", "--columns=application,name,version"], flatpaks),
                "podman": observe(["podman", "ps", "--all", "--format", "{{.Names}}\t{{.Image}}"], containers),
                "cli": {}, "units": {}}
    for command in sorted(CLI):
        snapshot["cli"][command] = observe(
            [command, "version" if command == "restic" else "-version" if command == "ffmpeg" else "--version"],
            lambda out: [version(out)])
    for scope, names in {
        "user": [f"heimgewebe-{app}.service" for app in APPS],
        "system": ["restic-backups-heim-pc.service", "restic-backups-heim-pc.timer", "podman.service"],
    }.items():
        for name in sorted(names):
            def state(out):
                value = out.strip()
                if value not in UNIT_STATES:
                    raise ValueError()
                return [{"exists": value != "not-found", "is_enabled": value}]
            snapshot["units"][f"{scope}:{name}"] = observe(
                ["systemctl", f"--{scope}", "is-enabled", name], state, (0, 1, 3, 4))
    snapshot["completed_at"] = clock()
    return snapshot


def render(snapshot):
    lines = ["---", "role: reality", "status: report", "temporal_scope: point_in_time",
             f'observed_at: "{snapshot["observed_at"]}"', "---", "",
             "# NixOS-Programminventar", "",
             "Zeitgebundene Beobachtung auf Heim-PC, kein canonical live state und kein Vollinventar.",
             "Versionen und Unit-Enablement gelten nur zum jeweiligen Beobachtungszeitpunkt; keine Health-/Aktivitätsaussage.",
             "Nix-Profilnamen betreffen das aufrufende Nutzerprofil, nicht alle NixOS-Systempakete.",
             "Desktopstarter sind nur sichtbare systemweite NixOS-Launcher; keine Nutzerprofile oder KDE-Einstellungs-Unterdialoge.",
             "`unavailable`: Befehl fehlt. `error`: Abfrage/Format fehlgeschlagen; keine leere Installation ableiten.",
             "", "Erneuern (ohne Installation/Downloads): `python3 scripts/generate_nixos_program_inventory.py`.",
             "JSON: [nixos-program-inventory.v1.json](nixos-program-inventory.v1.json). "
             "App-Rollen/Restore: versionierte Heim-PC-Notiz unter docs/heim-pc-apps.md.", "",
             "Die [Juli-Programme](program-inventory-summary.md) und das [Softwareinventar](software-inventory.md) "
             "bleiben HISTORISCHE Pop!_OS-Quellen vom 9. Juli 2026.", ""]
    observations = [(key, snapshot[key]) for key in ("os", "desktop_apps", "nix_profiles", "flatpak", "podman")]
    observations += [(f"CLI {key}", value) for key, value in snapshot["cli"].items()]
    observations += list(snapshot["units"].items())
    for name, row in observations:
        lines += [f"## {name}", "", f"Quelle: `{row['source']}`; beobachtet: `{row['observed_at']}`; "
                  f"Ergebnis: **{row['status']}** (rc={row['exit_code']}).", ""]
        for item in row.get("items", []):
            lines.append("- " + ("; ".join(f"{key}: `{value}`" for key, value in item.items())
                                if isinstance(item, dict) else f"`{item}`"))
        if row.get("status") == "ok" and not row.get("items"):
            lines.append("- Keine Einträge in dieser erfolgreichen Abfrage.")
        lines.append("")
    return "\n".join(lines)


def write_outputs(snapshot, directory):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "nixos-program-inventory.v1.json").write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    (directory / "nixos-program-inventory.md").write_text(render(snapshot), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path.home() / ".local/state/heim-pc/inventory")
    args = parser.parse_args()
    write_outputs(collect(), args.output_dir)


if __name__ == "__main__":
    main()
