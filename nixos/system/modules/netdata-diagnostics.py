import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:19999"
STATE = Path.home() / ".local/state/heim-pc/netdata-watch"
MAX_BODY = 16 * 1024 * 1024
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, body=None, headers=None):
    h = dict(headers or {})
    payload = None
    if body is not None:
        h["Content-Type"] = "application/json"
        payload = json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=payload, headers=h)
    with OPENER.open(req, timeout=6) as response:
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError("Netdata response exceeds bounded read")
        if headers is not None and response.headers.get("Mcp-Session-Id"):
            headers["Mcp-Session-Id"] = response.headers["Mcp-Session-Id"]
    text = raw.decode()
    if text.startswith(("event:", "data:")):
        text = next(line[6:] for line in text.splitlines() if line.startswith("data: "))
    return json.loads(text)


def mcp_probe():
    headers = {"Accept": "application/json, text/event-stream"}
    def call(i, method, params):
        result = request("/mcp", {"jsonrpc": "2.0", "id": i, "method": method, "params": params}, headers)
        if "error" in result or result.get("result", {}).get("isError"):
            raise ValueError("native MCP " + method + " failed")
        return result["result"]
    call(1, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
         "clientInfo": {"name": "heim-pc-netdata", "version": "1"}})
    tools = call(2, "tools/list", {})["tools"]
    query = call(3, "tools/call", {"name": "query_metrics", "arguments": {
        "metric": "system.cpu", "dimensions": ["user", "system"], "after": -60,
        "before": 0, "points": 3, "time_group": "average",
        "group_by": ["dimension"], "aggregation": "average",
        "cardinality_limit": 4, "timeout": 5}})
    payload = json.loads(query["content"][0]["text"])
    dimensions = payload["summary"]["dimensions"]
    if not any(finite(d.get("statistics", {}).get("avg")) for d in dimensions):
        raise ValueError("MCP CPU query returned no finite metrics")
    return {"status": "ok", "endpoint": BASE + "/mcp",
            "tools": [t["name"] for t in tools], "cpu_query": "finite"}


def finite(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def history(chart, minutes, points=12, group="average"):
    q = urllib.parse.urlencode({"chart": chart, "after": -60 * minutes,
                               "points": points, "group": group, "format": "json"})
    result = request("/api/v1/data?" + q)
    rows = sorted(result.get("data", []), key=lambda r: r[0])
    labels = result.get("labels", [])
    if not labels or labels[0] != "time":
        raise ValueError("invalid time series labels")
    return labels, rows


def summarize(chart, meta, minutes):
    labels, rows = history(chart, minutes)
    dimensions = {}
    for idx, label in enumerate(labels[1:], 1):
        vals = [r[idx] for r in rows if len(r) > idx and finite(r[idx])]
        if vals:
            dimensions[label] = {"min": min(vals), "mean": sum(vals)/len(vals),
                                 "max": max(vals), "samples": len(vals),
                                 "latest": rows[-1][idx] if len(rows[-1]) > idx and finite(rows[-1][idx]) else None}
    return {"context": meta.get("context"), "unit": meta.get("units"),
            "oldest": meta.get("first_entry"), "newest": meta.get("last_entry"),
            "dimensions": dimensions}


def podman():
    def run(args):
        p = subprocess.run(["podman", *args], capture_output=True, text=True, timeout=15)
        if p.returncode:
            raise RuntimeError("Podman read failed")
        return p.stdout
    names = set(run(["ps", "--format", "{{.Names}}"]).splitlines())
    data = json.loads(run(["stats", "--no-stream", "--format", "json"]))
    if not isinstance(data, list) or len(data) > 512:
        raise ValueError("unexpected Podman stats result")
    rows = [{k: x.get(k) for k in ("name", "cpu_percent", "mem_usage",
                "mem_percent", "net_io", "block_io", "pids")} for x in data]
    observed = {x["name"] for x in rows}
    return {"source": "rootless podman stats", "expected": len(names),
            "observed": len(names & observed), "missing": sorted(names - observed),
            "status": "ok" if names == observed else "partial",
            "historical": False, "containers": rows}


def alarms():
    a = request("/api/v1/alarms?all")["alarms"]
    return [{"key": key, "name": v.get("name"), "chart": v.get("chart"),
             "status": v.get("status"), "value": v.get("value") if finite(v.get("value")) else None,
             "units": v.get("units")} for key, v in a.items()
            if v.get("status") in ("WARNING", "CRITICAL")]


def info():
    i = request("/api/v1/info")
    return {"version": i["version"], "claimed": i.get("agent-claimed"),
            "cloud_link_available": i.get("aclk-available"), "memory_mode": i.get("memory-mode")}


def coverage_errors(series, now):
    # These contexts exist on the production Heim-PC. Keep a bounded
    # snapshot honest when collectors are missing, empty or stale.
    fresh = {k: v for k, v in series.items()
             if finite(v.get("newest")) and 0 <= now - v["newest"] <= 90
             and any(finite(d.get("latest")) for d in v["dimensions"].values())}
    contexts = {v["context"] for v in fresh.values()}
    required = {"system.cpu", "system.ram", "system.memory_some_pressure",
                "system.io_some_pressure", "disk.io", "btrfs.device_errors",
                "nvidia_smi.gpu_utilization"}
    errors = ["coverage:" + k for k in sorted(required - contexts)]
    if not any("k10temp" in k and k.endswith("_Tctl_input")
               for k in fresh):
        errors.append("coverage:cpu_tctl")
    return errors


def snapshot(minutes):
    result = {"schema_version": 1, "observed_at": int(time.time()), "status": "ok",
              "errors": [], "source": BASE, "window_minutes": minutes}
    try:
        result["netdata"] = info()
        charts = request("/api/v1/charts")["charts"]
        contexts = {"system.cpu", "system.ram", "system.memory_some_pressure",
                    "system.memory_full_pressure", "system.io_some_pressure",
                    "system.io_full_pressure", "system.hw.sensor.temperature.input",
                    "disk.io", "disk.await", "disk.backlog", "btrfs.device_errors",
                    "netdata.dbengine_tier_retention"}
        selected = [(k, v) for k, v in sorted(charts.items())
                    if v.get("context") in contexts or str(v.get("context")).startswith("nvidia_smi.")]
        result["chart_count"] = len(charts)
        result["series"] = {}
        selected.sort(key=lambda item: (not item[0].startswith("system."), item[0]))
        for k, v in selected[:64]:
            try:
                result["series"][k] = summarize(k, v, minutes)
                if not result["series"][k]["dimensions"]:
                    result["errors"].append("series:" + k + ":no_finite_values")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                result["errors"].append("series:" + k + ":" + type(exc).__name__)
        result["omitted_charts"] = max(0, len(selected) - 64)
        result["errors"].extend(coverage_errors(result["series"], time.time()))
        result["alarms"] = alarms()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result["errors"].append("netdata:" + type(exc).__name__)
    try:
        result["podman"] = podman()
        if result["podman"]["status"] != "ok":
            result["errors"].append("podman:incomplete")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result["errors"].append("podman:" + type(exc).__name__)
    try:
        p = subprocess.run(["systemctl", "show", "netdata.service", "-p", "MemoryCurrent",
                            "-p", "CPUUsageNSec", "-p", "ActiveState", "-p", "NRestarts"],
                           capture_output=True, text=True, timeout=6)
        result["unit"] = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
        if p.returncode or result["unit"].get("ActiveState") != "active":
            result["errors"].append("netdata:unit_not_active")
    except (OSError, subprocess.SubprocessError) as exc:
        result["errors"].append("unit:" + type(exc).__name__)
    result["status"] = "partial" if result["errors"] else "ok"
    return result


BTRFS_COUNTERS = {"write_errs", "read_errs", "flush_errs",
                  "corruption_errs", "generation_errs"}


def fresh_row(rows, now):
    return bool(rows and finite(rows[-1][0]) and -5 <= now - rows[-1][0] <= 30)


def read_conditions():
    charts = request("/api/v1/charts")["charts"]
    raised = alarms()
    # Only current critical alarms require automatic attention. Generic
    # backlog warnings and old cumulative Btrfs warnings remain diagnostic.
    active = {"critical:" + a["key"]: {"condition": "native_critical",
              "alarm": str(a["name"])[:100]} for a in raised
              if a["status"] == "CRITICAL" and not str(a["name"]).startswith("btrfs_device_")}
    errors = []
    tctl = next((k for k in charts if "k10temp" in k and k.endswith("_Tctl_input")), None)
    thermal = None
    if not tctl:
        errors.append("cpu_tctl_missing")
    else:
        try:
            labels, rows = history(tctl, 5, 30)
            values = [r[1] for r in rows if len(r) > 1 and finite(r[1])]
            # None is also the normal hysteresis band. Explicit errors
            # distinguish it from unavailable measurements.
            if (len(values) < 24 or not fresh_row(rows, time.time())
                    or len(rows[-1]) < 2 or not finite(rows[-1][1])):
                errors.append("cpu_tctl_incomplete_or_stale")
            elif sum(v >= 89 for v in values) >= 0.8 * len(values):
                thermal = True
            elif sum(v < 85 for v in values) >= 0.8 * len(values):
                thermal = False
        except (OSError, ValueError, KeyError, TypeError):
            errors.append("cpu_tctl_read_failed")
    counters = {}
    disks = [chart for chart, meta in charts.items()
             if meta.get("context") == "btrfs.device_errors"]
    if not disks:
        errors.append("btrfs_counters_missing")
    for chart in disks:
        try:
            labels, rows = history(chart, 2, 6, group="max")
            if not fresh_row(rows, time.time()):
                errors.append("btrfs_counters_stale")
                continue
            valid = {label: int(rows[-1][idx])
                     for idx, label in enumerate(labels[1:], 1)
                     if label in BTRFS_COUNTERS and len(rows[-1]) > idx
                     and finite(rows[-1][idx]) and rows[-1][idx] >= 0
                     and int(rows[-1][idx]) == rows[-1][idx]}
            if set(valid) != BTRFS_COUNTERS:
                errors.append("btrfs_counters_incomplete")
            counters.update({chart + ":" + label: value for label, value in valid.items()})
        except (OSError, ValueError, KeyError, TypeError):
            errors.append("btrfs_counters_read_failed")
    # Keep valid independent measurements useful even during a partial
    # collector outage. Missing measurements must never clear an episode.
    return (active, thermal, counters), sorted(set(errors))

def advance(state, observed, now):
    active, thermal, counters = observed
    old = state["active"]
    active = dict(active)
    if thermal is True or (thermal is None and "cpu_thermal" in old):
        active["cpu_thermal"] = {"condition": "cpu_temperature_sustained",
                                  "threshold": "89C for most of 5min"}
    new = {}
    for key, fields in active.items():
        event = old.get(key)
        if event is None:
            event = str(now)
            state["pending"].append({"key": key, "event": event, "fields": fields,
                                     "class": "owner_decision"})
        new[key] = event
    state["active"] = new
    for key, value in counters.items():
        previous = state["counters"].get(key)
        if previous is not None and value > previous:
            state["pending"].append({"key": "btrfs:" + key, "event": f"{now}:{value}",
                "class": "owner_decision", "fields": {"condition": "new_btrfs_device_errors",
                "counter": key.rsplit(":", 1)[-1][:100], "count": str(value)}})
        # A reset changes the baseline, it is not itself evidence of repair.
        state["counters"][key] = value


def poll(state, now):
    try:
        observed, errors = read_conditions()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors = ["netdata_read:" + type(exc).__name__]
    else:
        advance(state, observed, now)
    if errors:
        state["failures"] += 1
        if state["failures"] == 2:
            state["pending"].append({"key": "netdata_unavailable", "event": str(now),
                "class": "service_failure", "fields": {"error_type": "two_failed_reads"}})
    else:
        state["failures"] = 0
    return errors


def save_state(path, state):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        json.dump(state, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def watch(dry_run=False):
    # Keep a tiny episode/baseline state; actual notification durability and
    # idempotency remain the responsibility of Grabowski's existing outbox.
    path = STATE / "state.json"
    def evaluate():
        state = json.loads(path.read_text()) if path.exists() else {
            "schema_version": 1, "active": {}, "counters": {}, "pending": [], "failures": 0}
        if state.get("schema_version") != 1:
            raise ValueError("unsupported watch state")
        now = time.time_ns()
        read_errors = poll(state, now)
        if dry_run:
            return {"status": "preview", "active": list(state["active"]),
                    "would_enqueue": state["pending"][:64],
                    "pending_publication_count": len(state["pending"]),
                    "read_failures": state["failures"], "read_errors": read_errors}
        # Persist observations and their event identities before publishing.
        # Bound work per poll, not the durable backlog: refusing an oversized
        # pending list would prevent recovery forever.
        save_state(path, state)
        import grabowski_alert_outbox as outbox
        sent = []
        publication_error = None
        while state["pending"] and len(sent) < 64:
            e = state["pending"][0]
            try:
                receipt = outbox.enqueue_alert(event_class=e["class"], producer="netdata_watch",
                    subject="heim-pc-netdata", correlation_key=e["key"],
                    deduplication_key=e["event"], fields=e["fields"])
                alert_id = receipt["alert"]["alert_id"]
            except Exception as exc:
                # Keep the event and its identity for the next invocation.
                publication_error = type(exc).__name__
                break
            sent.append(alert_id)
            state["pending"].pop(0)
            save_state(path, state)
        if state["pending"]:
            return {"status": "publication_pending", "enqueued": sent,
                    "pending_publication_count": len(state["pending"]),
                    "publication_error": publication_error,
                    "read_failures": state["failures"], "read_errors": read_errors}
        queued = outbox.list_alerts(state="queued", limit=100)
        ours = [a for a in queued["alerts"] if a.get("producer") == "netdata_watch"]
        # The shared dispatcher consumes other producers' events as well.
        # A saturated queue must be triaged, not drained blindly by this
        # new timer. Missing topic configuration is a delivery gap, not
        # a Netdata collector failure.
        from grabowski_ntfy_dispatch import TOPIC_PATH
        blocker = None
        if not TOPIC_PATH.is_file():
            blocker = "ntfy_topic_missing"
        elif len(queued["alerts"]) >= 100:
            blocker = "shared_outbox_backlog"
        dispatch = None
        if blocker is None and (ours or sent):
            p = subprocess.run([sys.executable, "-I", "-m", "grabowski_ntfy_dispatch"],
                               capture_output=True, timeout=25)
            dispatch = p.returncode
        remaining = outbox.list_alerts(state="queued", limit=100)
        remaining_ids = [a["alert_id"] for a in remaining["alerts"] if a.get("producer") == "netdata_watch"]
        window_full = len(remaining["alerts"]) >= 100
        status = "delivery_pending" if blocker or window_full or remaining_ids or dispatch not in (None, 0) else "ok"
        if state["failures"] or queued.get("invalid_receipts") or remaining.get("invalid_receipts"):
            status = "degraded"
        return {"status": status, "enqueued": sent,
                "queued_window_count": len(remaining["alerts"]),
                "queue_window_full": window_full,
                "pending_after_dispatch": remaining_ids,
                "delivery_blocker": blocker,
                "dispatch_exit": dispatch, "read_failures": state["failures"],
                "read_errors": read_errors}
    if dry_run:
        return evaluate()
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return evaluate()


def main():
    p = argparse.ArgumentParser(description="Local bounded Heim-PC Netdata diagnostics")
    p.add_argument("operation", choices=("doctor", "snapshot", "watch"), nargs="?", default="snapshot")
    p.add_argument("--minutes", type=int, default=10, metavar="1..1440")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if not 1 <= args.minutes <= 1440:
        p.error("--minutes must be in 1..1440")
    if args.dry_run and args.operation != "watch":
        p.error("--dry-run is only valid for watch")
    try:
        if args.operation == "doctor":
            result = {"status": "ok", "netdata": info(), "mcp": mcp_probe()}
        elif args.operation == "snapshot":
            result = snapshot(args.minutes)
        else:
            result = watch(args.dry_run)
    except Exception as exc:
        result = {"status": "error", "error": type(exc).__name__}
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, sort_keys=True))
    return 0 if result["status"] in ("ok", "preview", "delivery_pending") else 1


if __name__ == "__main__":
    sys.exit(main())
