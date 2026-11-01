#!/usr/bin/env python3
"""Exclusive, reversible KWin virtual-output handoff for KRDP on the iPad."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

DOCTOR = "/run/current-system/sw/bin/kscreen-doctor"
VIRTUAL = "Virtual-1168x812@1"
WIDTH, HEIGHT = 1168, 812
STATE = Path("/home/alex/.local/state/krdp-ipad")
PREIMAGE = STATE / "physical-outputs.json"
STOP = False


def log(*items):
    print("krdp-ipad:", *items, flush=True)


def on_signal(_number, _frame):
    global STOP
    STOP = True


signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)


def doctor(*arguments):
    r = subprocess.run([DOCTOR, *arguments], capture_output=True, text=True, timeout=12)
    if r.returncode:
        raise RuntimeError(f"kscreen-doctor rc={r.returncode}: {r.stderr[-350:]}")
    return r.stdout


def outputs():
    return json.loads(doctor("-j"))["outputs"]


def desired_virtual(all_outputs):
    return next((o for o in all_outputs
                 if o.get("name") == VIRTUAL and o.get("connected") and o.get("enabled")), None)


def physical_enabled(all_outputs):
    return [o for o in all_outputs if o.get("connected") and o.get("enabled")
            and not o.get("name", "").startswith("Virtual-")]


def snapshot(all_outputs):
    current = physical_enabled(all_outputs)
    if not current:
        raise RuntimeError("no enabled physical output to preserve")
    return [{"name": o["name"], "pos": o["pos"], "scale": o.get("scale", 1),
             "mode": o.get("currentModeId"), "size": o.get("size")}
            for o in current]


def write_preimage(items):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE, 0o700)
    payload = json.dumps({"version": 1, "outputs": items}, sort_keys=True).encode() + b"\n"
    fd, tmp = tempfile.mkstemp(prefix=".display-preimage-", dir=STATE)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        if PREIMAGE.exists():
            raise RuntimeError("preimage already exists; refusing overwrite")
        os.replace(tmp, PREIMAGE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_preimage():
    if not PREIMAGE.exists():
        return None
    record = json.loads(PREIMAGE.read_text())
    if record.get("version") != 1 or not record.get("outputs"):
        raise RuntimeError("invalid physical output preimage")
    return record["outputs"]


def restore():
    old = read_preimage()
    if old is None:
        return True
    current = {o["name"]: o for o in outputs()}
    commands = []
    for item in old:
        o = current.get(item["name"])
        if o is None or not o.get("connected"):
            log("restore delayed: physical output unavailable", item["name"])
            return False
        name = item["name"]
        commands += [f"output.{name}.enable",
                     f"output.{name}.position.{item['pos']['x']},{item['pos']['y']}"]
        if item.get("mode") and item["mode"] != o.get("currentModeId"):
            commands.append(f"output.{name}.mode.{item['mode']}")
        if item.get("scale", 1) != o.get("scale", 1):
            commands.append(f"output.{name}.scale.{item['scale']}")
    doctor(*commands)
    now = {o["name"]: o for o in outputs()}
    ok = all(now.get(p["name"], {}).get("enabled")
             and now[p["name"]].get("pos") == p["pos"]
             for p in old)
    if not ok:
        log("restore readback mismatch; retaining preimage")
        return False
    PREIMAGE.unlink()
    log("PHYSICAL_RESTORED", [p["name"] for p in old])
    return True


def native_mode(v):
    mode = "1168x812@60"
    names = [m.get("name", "") for m in v.get("modes", [])]
    key = f"output.{v['id']}"
    if not any(n.startswith("1168x812@") for n in names):
        doctor(f"{key}.addCustomMode.1168.812.60000.full")
        v = desired_virtual(outputs())
        if v is None:
            raise RuntimeError("virtual display disappeared after mode add")
    if v.get("size") != {"width": WIDTH, "height": HEIGHT}:
        doctor(f"{key}.mode.{mode}")


def takeover(all_outputs, v):
    saved = read_preimage()
    if saved is None:
        saved = snapshot(all_outputs)
        write_preimage(saved)
    native_mode(v)
    current = outputs()
    virtual = desired_virtual(current)
    if virtual is None:
        raise RuntimeError("remote output missing during transition")
    commands = [f"output.{p['name']}.disable" for p in physical_enabled(current)]
    commands.append(f"output.{virtual['id']}.position.0,0")
    doctor(*commands)
    new = desired_virtual(outputs())
    if new is None or new.get("size") != {"width": WIDTH, "height": HEIGHT} or new.get("pos") != {"x": 0, "y": 0}:
        raise RuntimeError("virtual output mode/position readback failed")
    log("IPAD_NATIVE_READY", f"{WIDTH}x{HEIGHT}", "physical screens temporarily disabled")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--restore":
        if not restore():
            raise RuntimeError("Unable to restore saved physical outputs")
        return
    if len(sys.argv) == 2 and sys.argv[1] == "--check":
        all_outputs = outputs()
        log("CHECK", [(o["name"], o.get("enabled"), o.get("size")) for o in all_outputs],
            "saved_preimage", PREIMAGE.exists())
        return
    if len(sys.argv) > 1:
        raise RuntimeError("unsupported arguments")
    active = False
    errors = 0
    log("START", f"{WIDTH}x{HEIGHT}", "virtual", VIRTUAL)
    try:
        while not STOP:
            try:
                current = outputs()
                virtual = desired_virtual(current)
                if virtual is not None:
                    if not active:
                        takeover(current, virtual)
                        active = True
                    else:
                        # A compositor reconfiguration should not silently lose the iPad geometry.
                        if virtual.get("size") != {"width": WIDTH, "height": HEIGHT} or virtual.get("pos") != {"x": 0, "y": 0}:
                            takeover(current, virtual)
                    errors = 0
                else:
                    if read_preimage() is not None:
                        if restore():
                            active = False
                    else:
                        active = False
                    errors = 0
            except Exception as exc:
                errors += 1
                if errors in (1, 5, 20):
                    log("ERROR", type(exc).__name__, str(exc)[:550])
                if read_preimage() is not None and errors >= 3:
                    try:
                        restore()
                        active = False
                    except Exception as recovery_exc:
                        log("RESTORE_RETRY", type(recovery_exc).__name__, str(recovery_exc)[:350])
            time.sleep(1.5)
    finally:
        for _ in range(3):
            try:
                if restore():
                    break
            except Exception as exc:
                log("FINAL_RESTORE_RETRY", type(exc).__name__, str(exc)[:350])
            time.sleep(1)
        log("STOP")


if __name__ == "__main__":
    main()
