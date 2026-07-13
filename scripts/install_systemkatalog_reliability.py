#!/usr/bin/env python3
"""Install the repositories-root agent entry and Systemkatalog drift watchdog."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _install_file(source: Path, target: Path, mode: int, *, apply: bool) -> dict[str, object]:
    action = "unchanged" if target.exists() and target.read_bytes() == source.read_bytes() else "install"
    if apply and action == "install":
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        shutil.copyfile(source, temporary)
        os.chmod(temporary, mode)
        temporary.replace(target)
    elif apply and target.exists():
        os.chmod(target, mode)
    return {"source": str(source), "target": str(target), "mode": oct(mode), "action": action}


def install(*, home: Path, apply: bool, enable: bool) -> dict[str, object]:
    targets = [
        _install_file(ROOT / "config/agents/repos-root-AGENTS.md", home / "repos/AGENTS.md", 0o644, apply=apply),
        _install_file(ROOT / "scripts/systemkatalog_drift_watch.py", home / ".local/bin/systemkatalog-drift-watch", 0o755, apply=apply),
        _install_file(ROOT / "systemd/user/systemkatalog-drift-watch.service", home / ".config/systemd/user/systemkatalog-drift-watch.service", 0o644, apply=apply),
        _install_file(ROOT / "systemd/user/systemkatalog-drift-watch.timer", home / ".config/systemd/user/systemkatalog-drift-watch.timer", 0o644, apply=apply),
    ]
    systemd = "not-requested"
    if enable:
        if not apply:
            raise ValueError("--enable requires --apply")
        for argv in (
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "enable", "--now", "systemkatalog-drift-watch.timer"],
        ):
            result = subprocess.run(argv, text=True, capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"{' '.join(argv)} failed: {result.stderr.strip()}")
        systemd = "enabled"
    return {
        "schemaVersion": 1,
        "kind": "heim_pc_systemkatalog_reliability_install_receipt",
        "apply": apply,
        "home": str(home),
        "files": targets,
        "systemd": systemd,
        "doesNotEstablish": ["watchdog_run_success", "catalog_freshness", "semantic_truth"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--enable", action="store_true")
    args = parser.parse_args()
    try:
        receipt = install(home=args.home.expanduser().resolve(), apply=args.apply, enable=args.enable)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"kind": "heim_pc_systemkatalog_reliability_install_error", "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
