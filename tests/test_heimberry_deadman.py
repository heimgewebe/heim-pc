"""Dead-Man state transitions, no network or production mutation."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts" / "heimberry_deadman.py"
spec = importlib.util.spec_from_file_location("heimberry_deadman", PATH)
assert spec is not None and spec.loader is not None
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)
NOW = datetime(2026, 11, 15, 8, tzinfo=timezone.utc)


class Tests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.state = Path(t.name) / "state.json"
        self.topic = Path(t.name) / "topic"
        self.calls = []
    def sensor(self, kind, age=None):
        return lambda now: {"kind": kind, **({"age_seconds": age} if age is not None else {})}
    def send(self, _topic, kind, reason):
        self.calls.append((kind, reason))
    def step(self, minutes, kind, age=None, *, dry=False, sender=None):
        return watch.run(NOW+timedelta(minutes=minutes), self.state, self.topic,
                         check_only=dry, observer=self.sensor(kind, age),
                         sender=sender or self.send)

    def test_healthy_no_messages(self):
        for x in (0, 5, 10, 30): self.step(x, "healthy", 30)
        self.assertEqual(self.calls, [])

    def test_stale_alert_once_then_recovery(self):
        self.step(0, "stale", 1800)
        self.step(5, "stale", 2100)
        self.step(10, "healthy", 15)
        self.step(15, "healthy", 15)
        self.assertEqual(self.calls, [("ALARM", "stale"), ("RECOVERY", "healthy")])

    def test_transport_problem_needs_20min(self):
        self.step(0, "unobservable")
        self.step(10, "unobservable")
        self.assertFalse(self.calls)
        self.step(21, "unobservable")
        self.assertEqual(self.calls, [("ALARM", "unobservable")])

    def test_check_only_no_effects(self):
        x = self.step(0, "stale", 2400, dry=True)
        self.assertEqual(x["transition"], "ALARM")
        self.assertFalse(self.state.exists())
        self.assertFalse(self.calls)

    def test_send_failure_cannot_mark_acknowledged(self):
        def fail(*args): raise OSError("unreachable")
        with self.assertRaises(RuntimeError):
            self.step(0, "stale", 2400, sender=fail)
        self.assertFalse(self.state.exists())
        self.step(5, "stale", 2700)
        self.assertEqual(self.calls, [("ALARM", "stale")])

    def test_invalid_previous_state_is_preserved(self):
        self.state.write_text("invalid")
        with self.assertRaises(ValueError): watch.load(self.state)
        self.assertEqual(self.state.read_text(), "invalid")

    def test_real_probe_parser_bounded(self):
        class Completed:
            returncode = 0
            def __init__(self, raw): self.stdout = raw.encode()
        with patch.object(watch.subprocess, "run", return_value=Completed('{"checked_at_utc":"2026-11-15T07:59:00Z"}')):
            self.assertEqual(watch.observe(NOW)["kind"], "healthy")
        with patch.object(watch.subprocess, "run", return_value=Completed('{"checked_at_utc":"2026-11-15T07:30:00Z"}')):
            self.assertEqual(watch.observe(NOW)["kind"], "stale")
        with patch.object(watch.subprocess, "run", side_effect=OSError("transport")):
            self.assertEqual(watch.observe(NOW)["kind"], "unobservable")


if __name__ == "__main__":
    unittest.main()
