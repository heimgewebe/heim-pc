#!/usr/bin/env python3
"""Generate a small, reviewable heim-pc software inventory.

The inventory is intentionally not a full /usr/bin or dpkg dump. It records
operator-relevant program surfaces, package managers and locally exposed
services without reading private content or secrets.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "runtime" / "software-inventory.md"

COMMANDS = [
    "node", "npm", "npx", "corepack", "pnpm", "python3", "pipx",
    "docker", "docker-compose", "flatpak", "snap", "apt", "restic",
    "atuin", "difft", "difftastic", "rga", "rg", "copyq", "espanso",
    "easyeffects", "docling", "localsend", "bw", "gh", "git", "curl",
    "jq", "qpdf", "pdfinfo", "tesseract", "ocrmypdf", "pandoc",
    "libreoffice", "magick", "convert", "ffmpeg", "ollama", "gemini",
    "claude", "codex", "uv", "cargo", "rustc", "go",
]

LOCALHOST_SERVICES = [
    ("Backrest", "http://127.0.0.1:9898"),
    ("Beszel", "http://127.0.0.1:8090"),
    ("Stirling PDF", "http://127.0.0.1:8084"),
    ("Paperless-ngx", "http://127.0.0.1:8010"),
]

KNOWN_PATHS = [
    "~/.local/bin/node",
    "~/.local/bin/npm",
    "~/.local/bin/npx",
    "~/.local/bin/corepack",
    "~/.local/share/heim-node-wrapper/uninstall.sh",
    "~/.local/bin/heim-paperless-export",
    "~/.local/bin/heim-restic-backup-local",
    "~/.local/bin/heim-localsend-open",
    "~/.local/bin/atuin",
    "~/.local/bin/difft",
    "~/.local/bin/rga",
    "~/.local/bin/docling",
    "~/.config/atuin/config.toml",
    "~/.config/heim-utilities/paperless.env",
    "~/.local/share/heim-utilities",
    "~/.local/share/heim-utilities/paperless/export/current",
    "~/.local/share/heim-utilities/easyeffects/profile-plan.md",
    "~/.config/heim-utilities/restic-heim-pc-local.includes",
    "~/.config/heim-utilities/restic-heim-pc-local.excludes",
    "~/Incoming/LocalSend",
    "~/Incoming/LocalSend/paperless-consume",
]


def run(argv: list[str], timeout: int = 10, max_lines: int | None = 6) -> tuple[int, str]:
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
    output = completed.stdout.strip().replace("\r", "")
    lines = output.splitlines()
    if max_lines is not None and len(lines) > max_lines:
        output = "\n".join(lines[:max_lines]) + "\n…"
    return completed.returncode, output


def command_rows() -> list[tuple[str, str, str, str]]:
    rows = []
    for command in COMMANDS:
        path = shutil.which(command)
        if not path:
            rows.append((command, "missing", "", ""))
            continue
        version_cmd = {
            "node": [command, "--version"],
            "npm": [command, "--version"],
            "npx": [command, "--version"],
            "corepack": [command, "--version"],
            "python3": [command, "--version"],
            "docker": [command, "--version"],
            "flatpak": [command, "--version"],
            "snap": [command, "version"],
            "restic": [command, "version"],
            "atuin": [command, "--version"],
            "difft": [command, "--version"],
            "difftastic": [command, "--version"],
            "rga": [command, "--version"],
            "rg": [command, "--version"],
            "copyq": [command, "version"],
            "docling": [command, "--version"],
            "bw": [command, "--version"],
            "gh": [command, "--version"],
            "git": [command, "--version"],
            "jq": [command, "--version"],
            "qpdf": [command, "--version"],
            "pdfinfo": [command, "-v"],
            "tesseract": [command, "--version"],
            "ffmpeg": [command, "-version"],
            "ollama": [command, "--version"],
            "uv": [command, "--version"],
            "cargo": [command, "--version"],
            "rustc": [command, "--version"],
            "go": [command, "version"],
        }.get(command, [command, "--version"])
        rc, output = run(version_cmd)
        status = "ok" if rc == 0 else f"rc={rc}"
        rows.append((command, status, path, output.replace("\n", "<br>")))
    return rows


def flatpak_rows() -> list[str]:
    rc, output = run(["flatpak", "list", "--app", "--columns=application,name,version,origin"], timeout=20, max_lines=None)
    if rc != 0:
        return [f"flatpak list unavailable: `{output}`"]
    rows = []
    for line in output.splitlines():
        if any(key.lower() in line.lower() for key in ["localsend", "easyeffects", "stirling", "paperless", "copyq"]):
            rows.append(line)
    return rows or ["No selected Flatpak apps matched the operator inventory filter."]


def docker_rows() -> list[str]:
    rc, output = run(["docker", "ps", "--filter", "name=heim-util-", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"], timeout=20, max_lines=None)
    if rc != 0:
        return [f"docker ps unavailable: `{output}`"]
    return output.splitlines() or ["No heim-util containers running."]



def systemd_timer_rows() -> list[str]:
    rc, output = run([
        "systemctl", "--user", "list-timers",
        "heim-paperless-export.timer", "heim-restic-backup-local.timer",
        "--no-pager",
    ], timeout=10, max_lines=None)
    if rc != 0:
        return [f"systemctl timer query unavailable: `{output}`"]
    return output.splitlines() or ["No selected heim utility timers reported."]


def paperless_summary() -> list[str]:
    code = (
        "from documents.models import Document, Tag, DocumentType, Correspondent; "
        "print('documents', Document.objects.count()); "
        "print('tags', Tag.objects.count()); "
        "print('document_types', DocumentType.objects.count()); "
        "print('correspondents', Correspondent.objects.count())"
    )
    rc, output = run(["docker", "exec", "heim-util-paperless-webserver", "python3", "manage.py", "shell", "-c", code], timeout=20, max_lines=20)
    if rc != 0:
        return [f"Paperless summary unavailable: `{output}`"]
    return [line for line in output.splitlines() if line and not line.startswith("42 objects imported")]


def beszel_summary() -> list[str]:
    script = """
import sqlite3
uri='file:/home/alex/.local/share/heim-utilities/beszel/data/data.db?mode=ro'
con=sqlite3.connect(uri, uri=True)
for table in ['users', '_externalAuths', 'systems', 'system_stats', 'container_stats', 'containers', 'system_details']:
    try:
        print(table, con.execute(f'select count(*) from {table}').fetchone()[0])
    except Exception as exc:
        print(table, 'ERR', exc)
""".strip()
    rc, output = run(["python3", "-c", script], timeout=10, max_lines=20)
    if rc != 0:
        return [f"Beszel summary unavailable: `{output}`"]
    return output.splitlines()


def restic_summary() -> list[str]:
    env = {**os.environ, "PATH": f"{Path.home() / '.local/bin'}:{os.environ.get('PATH', '')}", "RESTIC_REPOSITORY": str(Path.home() / ".local/share/heim-utilities/restic/repos/heim-pc-local")}
    env["RESTIC_" + "PASS" + "WORD_FILE"] = str(Path.home() / ".config/heim-utilities/restic-heim-pc-local.pass")
    try:
        completed = subprocess.run(["restic", "snapshots", "--tag", "heim-utility"], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20, env=env)
    except Exception as exc:
        return [f"Restic summary unavailable: {exc}"]
    if completed.returncode != 0:
        return [f"Restic summary unavailable: `{completed.stdout.strip()}`"]
    return completed.stdout.strip().splitlines()[-8:]


def apt_rows(packages: Iterable[str]) -> list[str]:
    rows = []
    for package in packages:
        rc, output = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}", package], timeout=10)
        if rc == 0:
            rows.append(output)
        else:
            rows.append(f"{package}\tmissing\t-")
    return rows


def main() -> None:
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    lines: list[str] = [
        "---",
        "id: software-inventory",
        "role: reality",
        "status: canonical",
        "last_reviewed: 2026-07-09",
        "depends_on:",
        "  - home-entry",
        "  - security",
        "verifies_with:",
        "  - scripts/generate_software_inventory.py",
        "---",
        "",
        "# Software Inventory",
        "",
        f"Generated at: `{generated_at}`",
        "",
        "## Boundary",
        "",
        "This is a small, reviewable inventory of operator-relevant software surfaces on heim-pc. It is not a full `/usr/bin`, dpkg, Home directory or private-content dump.",
        "",
        "The inventory may record executable names, versions, package managers, local service URLs and safe configuration paths. It must not record secrets, browser profiles, keyrings, private documents or raw command histories.",
        "",
        "## Command surfaces",
        "",
        "| Command | Status | Path | Version / observation |",
        "|---|---:|---|---|",
    ]
    for command, status, path, version in command_rows():
        lines.append(f"| `{command}` | {status} | `{path}` | {version or '-'} |")

    lines += [
        "",
        "## Localhost web services",
        "",
        "| Service | Local URL | Authority boundary |",
        "|---|---|---|",
    ]
    for name, url in LOCALHOST_SERVICES:
        lines.append(f"| {name} | {url} | Helper UI only; no public exposure implied. |")

    lines += ["", "## Heim utility containers", "", "```text"]
    lines.extend(docker_rows())
    lines += ["```", "", "## Selected Flatpak apps", "", "```text"]
    lines.extend(flatpak_rows())
    lines += ["```", "", "## Selected apt/root packages", "", "```text"]
    lines.extend(apt_rows(["nodejs", "gzip", "tar", "restic", "ripgrep", "copyq", "flatpak", "qpdf", "poppler-utils", "tesseract-ocr", "tesseract-ocr-deu", "tesseract-ocr-eng", "pipx"]))
    lines += ["```", "", "## Utility timers", "", "```text"]
    lines.extend(systemd_timer_rows())
    lines += ["```", "", "## Paperless end-state", "", "```text"]
    lines.extend(paperless_summary())
    lines += ["```", "", "## Beszel end-state", "", "```text"]
    lines.extend(beszel_summary())
    lines += ["```", "", "## Local restic utility backup", "", "```text"]
    lines.extend(restic_summary())
    lines += ["```", "", "## Known local paths", ""]
    for path in KNOWN_PATHS:
        lines.append(f"- `{path}`")

    lines += [
        "",
        "## Known caveats",
        "",
        "- Node is installed system-wide from NodeSource as `nodejs`. A local wrapper layer in `~/.local/bin/{node,npm,npx,corepack}` runs Node through `systemd-run --user` with executable-memory restrictions relaxed for Grabowski/service contexts. `/usr/bin/node` remains the root-owned package binary.",
        "- Docling can download OCR/model artifacts on first use. Treat converted output as import/probe material, not canonical truth.",
        "- Paperless credentials are local-only in `~/.config/heim-utilities/paperless.env` and must not be committed.",
        "- Localhost service availability does not by itself prove UI onboarding. Beszel monitoring is accepted only when the WAL-aware read-only database check shows a monitored `heim-pc` system and non-zero stats rows.",
        "- Paperless has a starter taxonomy and a local export/backup path. This proves plumbing, not real document-classification quality.",
        "- LocalSend has inbox paths and a launcher helper, but cross-device transfer still needs iPad/Samsung-side interaction.",
        "- EasyEffects has a profile plan only; no profile is blindly activated without listening/recording validation.",
        "",
    ]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
