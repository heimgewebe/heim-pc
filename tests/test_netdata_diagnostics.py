"""Regression tests for the actual NixOS-packaged Netdata diagnostic."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "nixos/system/modules/netdata-diagnostics.py"
spec = importlib.util.spec_from_file_location("netdata_diagnostics", SOURCE)
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)

CPU = "sensors.temperature_k10temp-pci-00c3_temp1_Tctl_input"
DISK = "btrfs.device_errors_fixture"
COUNTERS = ["write_errs", "read_errs", "flush_errs", "corruption_errs", "generation_errs"]
NOW = 1800000000


def state():
    return {"schema_version": 1, "active": {}, "counters": {}, "pending": [], "failures": 0}


def counter_key():
    return DISK + ":corruption_errs"


class WatchTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.charts = {
            CPU: {"context": "system.hw.sensor.temperature.input"},
            DISK: {"context": "btrfs.device_errors"},
        }
        self.temp = 90
        self.counter = 334
        self.stale = False
        self.null_last = False
        self.incomplete = False
        self.patches = [
            patch.object(monitor, "request", lambda path: {"charts": self.charts}),
            patch.object(monitor, "alarms", lambda: []),
            patch.object(monitor, "history", self.history),
            patch.object(monitor.time, "time", lambda: NOW),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def history(self, chart, *args, **kwargs):
        age = 100 if self.stale else 0
        if chart == CPU:
            rows = [[NOW - 300 + i * 10 - age,
                     None if self.null_last and i == 30 else self.temp]
                    for i in range(1, 31)]
            return ["time", "input"], rows
        return ["time", *COUNTERS], [[NOW - age, 0, 0, 0, self.counter,
                                      None if self.incomplete else 0]]

    def test_missing_thermal_preserves_episode_and_independent_counter_increase(self):
        s = state()
        self.assertEqual(monitor.poll(s, 1), [])
        self.assertIn("cpu_thermal", s["active"])
        self.temp = 87
        self.assertEqual(monitor.poll(s, 2), [])
        self.assertIn("cpu_thermal", s["active"])
        del self.charts[CPU]
        self.counter = 335
        for i in range(3, 6):
            self.assertEqual(monitor.poll(s, i), ["cpu_tctl_missing"])
        self.assertEqual(s["failures"], 3)
        self.assertIn("cpu_thermal", s["active"])
        self.assertEqual(s["counters"][counter_key()], 335)
        self.assertEqual(sum(e["key"] == "netdata_unavailable" for e in s["pending"]), 1)
        self.assertTrue(any(e["key"] == "btrfs:" + counter_key() for e in s["pending"]))
        self.charts[CPU] = {"context": "system.hw.sensor.temperature.input"}
        self.temp = 80
        self.assertEqual(monitor.poll(s, 6), [])
        self.assertEqual(s["failures"], 0)
        self.assertNotIn("cpu_thermal", s["active"])

    def test_missing_btrfs_does_not_hide_heat(self):
        s = state()
        del self.charts[DISK]
        self.assertEqual(monitor.poll(s, 1), ["btrfs_counters_missing"])
        self.assertIn("cpu_thermal", s["active"])
        self.assertEqual(s["failures"], 1)

    def test_stale_incomplete_and_null_measurements_are_not_success(self):
        s = state()
        self.incomplete = True
        self.assertEqual(monitor.poll(s, 1), ["btrfs_counters_incomplete"])
        self.stale = True
        self.assertEqual(set(monitor.poll(s, 2)),
                         {"cpu_tctl_incomplete_or_stale", "btrfs_counters_stale"})
        self.stale = self.incomplete = False
        self.null_last = True
        self.assertEqual(monitor.poll(s, 3), ["cpu_tctl_incomplete_or_stale"])
        self.assertEqual(s["failures"], 3)
        self.null_last = False
        self.assertEqual(monitor.poll(s, 4), [])
        self.assertEqual(s["failures"], 0)

    def test_both_collectors_missing_raise_one_failure_per_episode(self):
        s = state()
        self.charts.clear()
        for i in range(1, 4):
            self.assertEqual(set(monitor.poll(s, i)),
                             {"cpu_tctl_missing", "btrfs_counters_missing"})
        self.assertEqual(s["failures"], 3)
        self.assertEqual(len(s["pending"]), 1)
        self.assertEqual(s["pending"][0]["key"], "netdata_unavailable")


class DiagnosticStateTests(unittest.TestCase):
    def test_counter_reset_new_increase_has_distinct_event_identity(self):
        s = state()
        for i, value in enumerate([334, 335, 0, 335], 1):
            monitor.advance(s, ({}, False, {counter_key(): value}), i)
        self.assertEqual(len(s["pending"]), 2)
        self.assertNotEqual(s["pending"][0]["event"], s["pending"][1]["event"])

    def test_missing_empty_and_stale_core_metrics(self):
        contexts = ["system.cpu", "system.ram", "system.memory_some_pressure",
                    "system.io_some_pressure", "disk.io", "btrfs.device_errors",
                    "nvidia_smi.gpu_utilization"]
        series = {k: {"context": k, "newest": NOW,
                      "dimensions": {"value": {"latest": 1.0}}} for k in contexts}
        series[CPU] = {"context": "system.hw.sensor.temperature.input", "newest": NOW,
                       "dimensions": {"input": {"latest": 70}}}
        self.assertEqual(monitor.coverage_errors(series, NOW), [])
        del series["system.cpu"]
        series["system.ram"]["dimensions"] = {}
        series["disk.io"]["newest"] = NOW - 91
        self.assertEqual(set(monitor.coverage_errors(series, NOW)),
                         {"coverage:system.cpu", "coverage:system.ram", "coverage:disk.io"})

    def test_empty_noncore_series_marks_snapshot_partial(self):
        chart = "disk.await_fixture"
        metadata = {"context": "disk.await"}
        unit = types.SimpleNamespace(returncode=0, stdout="ActiveState=active\n")
        with patch.object(monitor, "info", return_value={}), \
             patch.object(monitor, "request", return_value={"charts": {chart: metadata}}), \
             patch.object(monitor, "history", return_value=(["time", "reads"], [[NOW, None]])), \
             patch.object(monitor, "coverage_errors", return_value=[]), \
             patch.object(monitor, "alarms", return_value=[]), \
             patch.object(monitor, "podman", return_value={"status": "ok"}), \
             patch.object(monitor.subprocess, "run", return_value=unit):
            result = monitor.snapshot(10)
        self.assertEqual(result["status"], "partial")
        self.assertIn("series:" + chart + ":no_finite_values", result["errors"])


class PublicationRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "state.json"
        self.calls = []
        self.fail = False
        self.queued = []
        self.counter = 1

        def enqueue(**kwargs):
            if self.fail:
                raise OSError("fixture outbox unavailable")
            self.calls.append(kwargs)
            aid = str(len(self.calls))
            self.queued.append({"alert_id": aid, "producer": "netdata_watch"})
            return {"alert": {"alert_id": aid}}

        outbox = types.SimpleNamespace(enqueue_alert=enqueue,
            list_alerts=lambda **kwargs: {"alerts": self.queued[:100], "invalid_receipts": []})
        dispatch = types.SimpleNamespace(TOPIC_PATH=self.root / "missing_topic")
        p = patch.dict(sys.modules, {"grabowski_alert_outbox": outbox,
                                     "grabowski_ntfy_dispatch": dispatch})
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(monitor, "STATE", self.root)
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(monitor, "read_conditions", lambda: (({}, False,
                              {counter_key(): self.counter}), []))
        p.start()
        self.addCleanup(p.stop)

    def load(self):
        return json.loads(self.path.read_text())

    def test_full_backlog_with_new_event_drains_over_successive_polls(self):
        s = state()
        s["counters"][counter_key()] = 0
        s["pending"] = [{"key": "fixture", "event": str(i),
                         "class": "owner_decision", "fields": {}} for i in range(64)]
        self.path.write_text(json.dumps(s))
        result = monitor.watch()
        self.assertEqual(result["status"], "publication_pending")
        self.assertEqual(result["pending_publication_count"], 1)
        self.assertEqual(len(self.calls), 64)
        self.assertEqual(self.load()["counters"][counter_key()], 1)
        result = monitor.watch()
        self.assertEqual(len(self.calls), 65)
        self.assertEqual(self.load()["pending"], [])
        self.assertEqual(result["delivery_blocker"], "ntfy_topic_missing")
        self.assertEqual(len({(c["correlation_key"], c["deduplication_key"]) for c in self.calls}), 65)

    def test_publication_failure_retains_original_event_then_recovers(self):
        s = state()
        s["counters"][counter_key()] = 0
        self.path.write_text(json.dumps(s))
        self.fail = True
        first = monitor.watch()
        self.assertEqual(first["status"], "publication_pending")
        self.assertEqual(first["publication_error"], "OSError")
        pending = self.load()["pending"]
        self.assertEqual(len(pending), 1)
        self.fail = False
        result = monitor.watch()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["deduplication_key"], pending[0]["event"])
        self.assertEqual(self.load()["pending"], [])
        self.assertEqual(result["delivery_blocker"], "ntfy_topic_missing")

    def test_dry_run_has_no_state_or_outbox_effect(self):
        s = state()
        s["counters"][counter_key()] = 0
        self.path.write_text(json.dumps(s))
        before = self.path.read_bytes()
        result = monitor.watch(dry_run=True)
        self.assertEqual(result["status"], "preview")
        self.assertEqual(result["pending_publication_count"], 1)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
