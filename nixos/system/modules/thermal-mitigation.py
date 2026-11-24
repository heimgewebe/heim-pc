"""Apply the measured, reversible mitigation on the actual Ryzen workstation.

Do not enforce it continuously: firmware fan control stays in Smart Fan IV mode
and an intentional later power-profile change remains possible. A generation
switch can stop the oneshot and restore only values still owned by this apply.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

BOARD = "ROG STRIX B550-F GAMING"
CPU = "AMD Ryzen 9 5900XT 16-Core Processor"
CAP_KHZ = 4_200_000
FAN_CURVES = {
    2: (8, (55_000, 70_000, 85_000), (128, 230)),
    3: (1, (40_000, 45_000, 55_000), (102, 153)),
    4: (1, (40_000, 45_000, 55_000), (102, 153)),
}


def read(path: Path) -> str:
    return path.read_text().strip()


def matches(root: Path) -> bool:
    try:
        board = read(root / "sys/class/dmi/id/board_name")
        models = {
            line.split(":", 1)[1].strip()
            for line in read(root / "proc/cpuinfo").splitlines()
            if line.startswith("model name") and ":" in line
        }
        return board == BOARD and models == {CPU}
    except OSError:
        return False


def policies(root: Path) -> list[Path]:
    return sorted((root / "sys/devices/system/cpu/cpufreq").glob("policy[0-9]*"))


def fan_device(root: Path) -> Path | None:
    devices = [
        p for p in sorted((root / "sys/class/hwmon").glob("hwmon*"))
        if (p / "name").is_file() and read(p / "name") == "nct6798"
    ]
    return devices[0] if len(devices) == 1 else None


def fan_layout(device: Path, channel: int) -> bool:
    source, temperatures, _ = FAN_CURVES[channel]
    base = f"pwm{channel}"
    try:
        return (
            read(device / f"{base}_enable") == "5"
            and int(read(device / f"{base}_temp_sel")) == source
            and tuple(int(read(device / f"{base}_auto_point{i}_temp"))
                      for i in (1, 2, 3)) == temperatures
            and int(read(device / f"{base}_auto_point3_pwm")) == 255
        )
    except (OSError, ValueError):
        return False


def plan(root: Path) -> list[dict[str, str]]:
    """Resolve the known hardware; keep existing stricter caps/higher fan curves."""
    if not matches(root):
        print("thermal-mitigation: different hardware; no changes")
        return []
    changes: list[dict[str, str]] = []

    def add(path: Path, old: str, value: str) -> None:
        if old != value:
            changes.append({"path": str(path.relative_to(root)), "old": old, "new": value})

    cpu_policies = policies(root)
    if not cpu_policies:
        raise RuntimeError("no CPU frequency policies on expected host")
    for p in cpu_policies:
        if read(p / "scaling_driver") != "amd-pstate-epp":
            raise RuntimeError("unexpected CPU frequency driver")
        maximum = int(read(p / "scaling_max_freq"))
        minimum = int(read(p / "scaling_min_freq"))
        if minimum > CAP_KHZ:
            raise RuntimeError("CPU minimum exceeds thermal cap")
        add(p / "scaling_max_freq", str(maximum), str(min(maximum, CAP_KHZ)))
        epp = p / "energy_performance_preference"
        # Do not override another explicitly selected power profile.
        preference = read(epp)
        if preference == "balance_performance":
            if "balance_power" not in read(p / "energy_performance_available_preferences").split():
                raise RuntimeError("balance_power unavailable")
            add(epp, preference, "balance_power")

    device = fan_device(root)
    if device is None:
        print("thermal-mitigation: NCT6798 telemetry unavailable; CPU changes only")
        return changes
    for channel, (_, _, targets) in FAN_CURVES.items():
        if not fan_layout(device, channel):
            print(f"thermal-mitigation: fan {channel} firmware layout changed; preserving it")
            continue
        points = [device / f"pwm{channel}_auto_point{i}_pwm" for i in (1, 2)]
        current = [int(read(p)) for p in points]
        if not 0 <= current[0] <= current[1] <= 255:
            print(f"thermal-mitigation: fan {channel} nonmonotonic curve; preserving it")
            continue
        desired = [max(a, b) for a, b in zip(current, targets)]
        # Raise the later point first; restoration reverses this ordering.
        for index in (1, 0):
            add(points[index], str(current[index]), str(desired[index]))
    return changes


def allowed_paths(root: Path) -> set[str]:
    allowed = {
        str((p / name).relative_to(root))
        for p in policies(root) if read(p / "scaling_driver") == "amd-pstate-epp"
        for name in ("scaling_max_freq", "energy_performance_preference")
    }
    device = fan_device(root)
    if device is not None:
        allowed.update(
            str((device / f"pwm{channel}_auto_point{i}_pwm").relative_to(root))
            for channel in FAN_CURVES if fan_layout(device, channel)
            for i in (1, 2)
        )
    return allowed


def write(path: Path, value: str) -> None:
    path.write_text(value + "\n")
    if read(path) != value:
        raise RuntimeError(f"readback failed: {path}")


def restore(root: Path, state: Path) -> None:
    if not state.exists():
        return
    changes = json.loads(state.read_text())
    allowed = allowed_paths(root) if matches(root) else set()
    # Treat the two points of each fan curve as one unit. Restoring a later
    # point after an intervening manual change to the earlier point could
    # otherwise produce a nonmonotonic curve.
    groups: dict[str, list[dict[str, str]]] = {}
    for change in changes:
        name = change["path"]
        group = name.split("_auto_point", 1)[0] if "_auto_point" in name else name
        groups.setdefault(group, []).append(change)
    errors = []
    for group, records in reversed(list(groups.items())):
        try:
            if not all(
                c["path"] in allowed
                and read(root / c["path"]) in (c["old"], c["new"])
                for c in records
            ):
                print(f"thermal-mitigation: preserving changed/unavailable {group}")
                continue
            if "_auto_point" in records[0]["path"]:
                original = {c["path"]: c["old"] for c in records}
                names = [f"{group}_auto_point{i}_pwm" for i in (1, 2)]
                values = [int(original.get(n, read(root / n))) for n in names]
                if not 0 <= values[0] <= values[1] <= 255:
                    print(f"thermal-mitigation: preserving nonmonotonic restore {group}")
                    continue
            for change in reversed(records):
                path = root / change["path"]
                if read(path) == change["new"]:
                    write(path, change["old"])
        except (OSError, ValueError, RuntimeError) as exc:
            errors.append(f"{group}: {exc}")
    if errors:
        raise RuntimeError("incomplete thermal restore: " + "; ".join(errors))
    state.unlink()


def apply(root: Path, state: Path) -> None:
    if state.exists():
        raise RuntimeError("previous mitigation state still present; stop before reapply")
    changes = plan(root)
    # Record only attempted writes. An unattempted target may already have
    # been selected by another actor; it is not ours to restore.
    attempted: list[dict[str, str]] = []

    def save() -> None:
        pending = state.with_suffix(".tmp")
        pending.write_text(json.dumps(attempted) + "\n")
        pending.replace(state)

    save()
    try:
        for change in changes:
            path = root / change["path"]
            if read(path) != change["old"]:
                raise RuntimeError(f"concurrent setting change: {path}")
            # A failed sysfs write/readback may still have changed the value.
            attempted.append(change)
            save()
            write(path, change["new"])
    except Exception:
        restore(root, state)
        raise
    print(f"thermal-mitigation: applied {len(changes)} settings; automatic fan control retained")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply", "restore"))
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    (apply if args.action == "apply" else restore)(Path("/"), args.state)


if __name__ == "__main__":
    main()
