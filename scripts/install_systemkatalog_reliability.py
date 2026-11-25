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
DECLARED_USER_UNITS = Path('/run/current-system/etc/systemd/user')


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


def _migrate_legacy_units(home: Path, *, apply: bool) -> dict[str, object]:
    """Remove only the exact reproducible units owned by the old installer.

    A customized file or symlink is an explicit local override, not ours to
    remove. The legacy executable and all watchdog state are left untouched.
    """
    unit_dir = home / ".config/systemd/user"
    names = ("systemkatalog-drift-watch.service", "systemkatalog-drift-watch.timer")
    owned: list[Path] = []
    overrides: list[Path] = []
    for name in names:
        target = unit_dir / name
        if target.is_symlink():
            overrides.append(target)
        elif target.exists():
            template = ROOT / "systemd/user" / name
            if target.is_file() and target.read_bytes() == template.read_bytes():
                owned.append(target)
            else:
                overrides.append(target)
        drop_in = unit_dir / (name + ".d")
        if drop_in.exists() or drop_in.is_symlink():
            overrides.append(drop_in)
    timer = unit_dir / names[1]
    link = unit_dir / "timers.target.wants" / timer.name
    # The legacy installer enabled its own timer using a user-local symlink.
    # A different target is not installer-owned, and must not be discarded.
    if link.is_symlink() and link.resolve(strict=False) == timer.resolve(strict=False):
        owned.insert(0, link)
    elif link.is_symlink() and link.resolve(strict=False) == (DECLARED_USER_UNITS / timer.name).resolve(strict=False):
        pass  # already points to the declared unit
    elif link.exists() or link.is_symlink():
        overrides.append(link)
    if overrides:
        if apply:
            raise RuntimeError(
                "custom Systemkatalog user-unit override preserved; "
                "resolve declarative shadowing explicitly: "
                + ", ".join(str(path) for path in overrides)
            )
        return {"status": "custom_override", "paths": [str(p) for p in overrides]}
    if apply:
        for path in owned:
            path.unlink()
    return {
        "status": ("migrated" if apply else "migration_needed") if owned else "absent",
        "paths": [str(p) for p in owned],
        "requiresDaemonReload": bool(owned and apply),
    }


def _systemctl(*args: str) -> str:
    argv = ["systemctl", "--user", *args]
    result = subprocess.run(argv, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def install(*, home: Path, apply: bool, enable: bool, declarative: bool | None = None) -> dict[str, object]:
    if declarative is None:
        declarative = (DECLARED_USER_UNITS / 'systemkatalog-drift-watch.timer').is_file()
    if enable and not apply:
        raise ValueError("--enable requires --apply")
    legacy = _migrate_legacy_units(home, apply=apply) if declarative else None
    targets = [
        _install_file(ROOT / "config/agents/repos-root-AGENTS.md", home / "repos/AGENTS.md", 0o644, apply=apply),
    ]
    if not declarative:
        targets.extend([
        _install_file(ROOT / "scripts/systemkatalog_drift_watch.py", home / ".local/bin/systemkatalog-drift-watch", 0o755, apply=apply),
        _install_file(ROOT / "systemd/user/systemkatalog-drift-watch.service", home / ".config/systemd/user/systemkatalog-drift-watch.service", 0o644, apply=apply),
        _install_file(ROOT / "systemd/user/systemkatalog-drift-watch.timer", home / ".config/systemd/user/systemkatalog-drift-watch.timer", 0o644, apply=apply),
        ])
    systemd = "declarative" if declarative else "not-requested"
    if enable and not declarative:
        _systemctl("daemon-reload")
        _systemctl("enable", "--now", "systemkatalog-drift-watch.timer")
        systemd = "enabled"
    elif enable and legacy is not None:
        _systemctl("daemon-reload")
        for name in ("systemkatalog-drift-watch.service", "systemkatalog-drift-watch.timer"):
            effective = _systemctl("show", "--property=FragmentPath", "--value", name)
            declared = DECLARED_USER_UNITS / name
            if not effective or Path(effective).resolve() != declared.resolve():
                raise RuntimeError(f"declarative fragment not effective for {name}: {effective}")
        _systemctl("restart" if legacy["status"] == "migrated" else "start", "systemkatalog-drift-watch.timer")
        legacy["requiresDaemonReload"] = False
    return {
        "schemaVersion": 1,
        "kind": "heim_pc_systemkatalog_reliability_install_receipt",
        "apply": apply,
        "home": str(home),
        "files": targets,
        "legacyUnits": legacy,
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
