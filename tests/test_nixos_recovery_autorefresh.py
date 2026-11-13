"""Regression tests for the complete unprivileged NixOS recovery refresh client."""
import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "nixos/system/modules/grabowski-recovery-mcp-refresh.py"
MODULE = ROOT / "nixos/system/modules/grabowski-production.nix"
spec = importlib.util.spec_from_file_location("nixos_recovery_refresh", SCRIPT)
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)
NOW = 1_793_900_000


def current_status():
    return {
        "ready_for_privileged_actions": True,
        "checks": {
            "audit_chain": True,
            "deployment_provenance": True,
            "local_backup_fresh": True,
            "backup_timer_enabled": True,
            "backup_timer_active": True,
            "server_recovery_fresh": True,
            "server_recovery_source_current": True,
            "kill_switch_clear": True,
            "privileged_broker_ready": True,
        },
        "local_backup": {"valid": True, "snapshot_id": "deadbeef"},
        "server_recovery": {
            "valid": True, "snapshot_id": "deadbeef",
            "generated_at_unix": NOW - 60,
        },
        "server_recovery_source_publication": {"current": True},
    }


class DecisionTests(unittest.TestCase):
    def test_valid_recent_proof_is_reused(self):
        self.assertEqual(refresh.decide(current_status(), now=NOW), "skip")

    def test_new_completed_backup_defeats_recent_proof(self):
        status = current_status()
        proof_time = status["server_recovery"]["generated_at_unix"]
        self.assertEqual(
            refresh.decide(status, now=NOW, latest_backup_finished_unix=proof_time + 1),
            "refresh",
        )
        self.assertEqual(
            refresh.decide(status, now=NOW, latest_backup_finished_unix=proof_time),
            "skip",
        )

    def test_new_backup_invalidates_local_marker_even_if_old_canonical_is_intact(self):
        s = current_status()
        s["local_backup"] = {
            "valid": False,
            "error": "NixOS recovery snapshot lacks matching completed backup invocation",
        }
        generated = s["server_recovery"]["generated_at_unix"]
        self.assertEqual(
            refresh.decide(s, now=NOW, latest_backup_finished_unix=generated + 4),
            "refresh",
        )
        # If there was no later successful backup, preserve the old intact
        # recovery proof instead of overwriting it during a failed upload.
        self.assertEqual(
            refresh.decide(s, now=NOW, latest_backup_finished_unix=None),
            "skip",
        )

    def test_refresh_before_24_hour_expiry(self):
        s = current_status()
        s["server_recovery"]["generated_at_unix"] = NOW - 11 * 60 * 60
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")

    def test_unpublished_proof_retriggers_broker_publication(self):
        s = current_status()
        s["server_recovery_source_publication"]["current"] = False
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")

    def test_root_proof_missing_but_native_backup_valid(self):
        s = current_status()
        s["ready_for_privileged_actions"] = False
        s["server_recovery"] = {"valid": False}
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")

    def test_invalid_previous_marker_allows_new_native_backup_probe(self):
        s = current_status()
        s["ready_for_privileged_actions"] = False
        s["checks"]["local_backup_fresh"] = False
        s["checks"]["server_recovery_fresh"] = False
        s["checks"]["server_recovery_source_current"] = False
        s["local_backup"] = {
            "valid": False,
            "snapshot_id": "f30f8e22",
            "error": "NixOS recovery snapshot lacks matching completed backup invocation",
        }
        s["server_recovery"] = {"valid": False, "snapshot_id": "f30f8e22"}
        s["server_recovery_source_publication"] = {"current": False}
        # The old marker cannot attest the new run; root probe validates the
        # new systemd invocation and snapshot before writing a fresh marker.
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")

    def test_failed_or_running_backup_cannot_destroy_intact_old_proof(self):
        for value in (False, None):
            s = current_status()
            s["server_recovery"]["generated_at_unix"] = NOW - 12 * 60 * 60
            s["local_backup"]["valid"] = value
            with self.subTest(value=value):
                self.assertEqual(refresh.decide(s, now=NOW), "skip")

    def test_invalid_marker_still_requires_native_timer_and_rootbroker(self):
        for key in refresh.PREREQUISITE_CHECKS:
            s = current_status()
            s["ready_for_privileged_actions"] = False
            s["checks"][key] = False
            s["local_backup"]["valid"] = False
            s["server_recovery"]["valid"] = False
            with self.subTest(key=key), self.assertRaisesRegex(
                RuntimeError, "rootbroker is not ready"
            ):
                refresh.decide(s, now=NOW)

    def test_unready_timer_rootbroker_or_killswitch_rejected(self):
        for key in refresh.PREREQUISITE_CHECKS:
            s = current_status()
            s["server_recovery"]["generated_at_unix"] = NOW - 12 * 60 * 60
            s["checks"][key] = False
            with self.subTest(key=key), self.assertRaisesRegex(
                RuntimeError, "rootbroker is not ready"
            ):
                refresh.decide(s, now=NOW)

    def test_malformed_evidence_rejected(self):
        for status, now in ((None, NOW), ({}, NOW), (current_status(), True),
                            (current_status(), 0)):
            with self.subTest(value=status, now=now), self.assertRaises(RuntimeError):
                refresh.decide(status, now=now)

    def test_clock_future_proof_is_not_misclassified_as_fresh(self):
        s = current_status()
        s["server_recovery"]["generated_at_unix"] = NOW + 60
        self.assertEqual(refresh.decide(s, now=NOW), "refresh")


class NativeBackupReadTests(unittest.TestCase):
    @staticmethod
    def result(**fields):
        values = {
            "LoadState": "loaded", "ActiveState": "inactive",
            "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
            "ExecMainExitTimestamp": f"@{NOW - 10}",
        }
        values.update(fields)
        return Mock(returncode=0, stdout="\n".join(
            f"{key}={value}" for key, value in values.items()
        ) + "\n")

    def test_completed_backup_timestamp_uses_fixed_readonly_query(self):
        with patch.object(refresh.subprocess, "run", return_value=self.result()) as run:
            self.assertEqual(refresh.latest_completed_backup_unix(now=NOW), NOW - 10)
        args, kwargs = run.call_args
        self.assertEqual(args[0][:5], [
            "/run/current-system/sw/bin/systemctl", "--system",
            "--timestamp=unix", "show", "restic-backups-heim-pc.service",
        ])
        self.assertFalse(kwargs["check"])
        self.assertNotIn("shell", kwargs)

    def test_failed_running_unavailable_and_future_are_not_evidence(self):
        for values in (
            {"ActiveState": "activating"}, {"Result": "exit-code"},
            {"ExecMainStatus": "1"}, {"ExecMainCode": "2"},
            {"ExecMainExitTimestamp": ""}, {"LoadState": "not-found"},
            {"ExecMainExitTimestamp": f"@{NOW+55}"},
        ):
            with self.subTest(fields=values), patch.object(
                refresh.subprocess, "run", return_value=self.result(**values)
            ):
                self.assertIsNone(refresh.latest_completed_backup_unix(now=NOW))
        with patch.object(refresh.subprocess, "run", side_effect=OSError):
            self.assertIsNone(refresh.latest_completed_backup_unix(now=NOW))


class PublishedProofTests(unittest.TestCase):
    @staticmethod
    def valid():
        return {
            "restore_probe_valid": True,
            "repository_check_valid": True,
            "snapshot_id": "abcd1234",
            "root_proof": {"validated": True},
            "canonical_recovery": {"valid": True, "snapshot_id": "abcd1234"},
            "source_recovery": {"valid": True},
            "publication": {"success": True},
        }

    def test_accepts_nixos_proof_without_remote_only_marker_valid(self):
        self.assertEqual(refresh.require_published_proof(self.valid()), "abcd1234")

    def test_missing_root_or_publication_is_rejected(self):
        variants = (
            ("root", "root_proof", None),
            ("canonical", "canonical_recovery", {"valid": False}),
            ("source", "source_recovery", {"valid": False}),
            ("publish", "publication", {"success": False}),
            ("backup", "repository_check_valid", False),
            ("restore", "restore_probe_valid", False),
            ("snapshot", "snapshot_id", "wrong-id"),
        )
        for label, key, value in variants:
            proof = self.valid()
            proof[key] = value
            with self.subTest(kind=label), self.assertRaisesRegex(
                RuntimeError, "canonical publication not proven"
            ):
                refresh.require_published_proof(proof)


class TransportProbeTests(unittest.IsolatedAsyncioTestCase):
    class Session:
        def __init__(self, *results):
            self.results = list(results)
            self.calls = []

        async def call_tool(self, name, arguments, **kwargs):
            self.calls.append((name, arguments, kwargs))
            if not self.results:
                raise AssertionError("unplanned duplicate MCP call")
            return self.results.pop(0)

    @staticmethod
    def begin(challenge="a" * 64):
        return SimpleNamespace(
            isError=False,
            structuredContent={"status": "passed", "output": {
                "challenge_receipt_sha256": challenge,
            }},
        )

    @staticmethod
    def executed(*, target_result=None, error=None, state="executed",
                 status="passed", is_error=False):
        return SimpleNamespace(
            isError=is_error,
            structuredContent={
                "status": status,
                "output": {
                    "state": state,
                    "application_result_observed": status == "passed",
                    "target_result": target_result,
                    "target_error": error,
                },
            },
        )

    async def test_exact_zero_argument_target_has_bound_begin_and_execute(self):
        proof = PublishedProofTests.valid()
        for field in ("structuredContent", "structured_content"):
            with self.subTest(field=field):
                session = self.Session(self.begin(),
                    self.executed(target_result={field: proof}))
                result = await refresh._call(
                    session, "grabowski_recovery_server_probe",
                    timeout=refresh.TOOL_TIMEOUT,
                )
                self.assertEqual(result, proof)
                self.assertEqual(len(session.calls), 2)
                first, last = session.calls
                self.assertEqual([call[0] for call in session.calls],
                                 ["grip_run", "grip_run"])
                for call in (first, last):
                    self.assertEqual(call[1]["name"], "transport-roundtrip")
                    self.assertTrue(call[1]["allow_mutation"])
                    self.assertEqual(call[1]["parameters"]["target_tool_name"],
                                     "grabowski_recovery_server_probe")
                    self.assertEqual(call[1]["parameters"]["target_arguments"], {})
                self.assertEqual(first[1]["parameters"]["action"], "begin")
                self.assertEqual(last[1]["parameters"]["action"], "execute")
                self.assertEqual(last[1]["parameters"]["challenge_receipt_sha256"],
                                 "a" * 64)

    async def test_busy_retry_only_for_exact_target_error(self):
        session = self.Session(self.begin(), self.executed(
            status="failed", state="target_failed",
            error={"type": "RuntimeError",
                   "message": "local recovery repository operation is busy"},
        ))
        with self.assertRaises(refresh.RecoveryRepositoryBusy):
            await refresh._call(session, "grabowski_recovery_server_probe",
                                timeout=refresh.TOOL_TIMEOUT)
        self.assertEqual(len(session.calls), 2)
        failed = self.Session(self.begin(), self.executed(
            status="failed", state="target_failed",
            error={"type": "RuntimeError", "message": "repository integrity failed"},
        ))
        with self.assertRaisesRegex(RuntimeError, "integrity failed"):
            await refresh._call(failed, "grabowski_recovery_server_probe",
                                timeout=refresh.TOOL_TIMEOUT)
        self.assertEqual(len(failed.calls), 2)

    async def test_missing_challenge_or_ambiguous_result_never_retries(self):
        invalid_challenge = self.Session(self.begin(challenge="not a digest"))
        with self.assertRaisesRegex(RuntimeError, "challenge receipt"):
            await refresh._call(invalid_challenge, "grabowski_recovery_server_probe",
                                timeout=refresh.TOOL_TIMEOUT)
        self.assertEqual(len(invalid_challenge.calls), 1)
        for returned in (
            SimpleNamespace(isError=False, structuredContent=None),
            self.executed(target_result={}, is_error=True),
            self.executed(target_result={}),
            self.executed(target_result={"structured_content": None}),
        ):
            with self.subTest(returned=returned):
                session = self.Session(self.begin(), returned)
                with self.assertRaises(RuntimeError):
                    await refresh._call(session, "grabowski_recovery_server_probe",
                                        timeout=refresh.TOOL_TIMEOUT)
                self.assertEqual(len(session.calls), 2)

    async def test_readonly_recovery_status_bypasses_mutating_handshake(self):
        status = current_status()
        session = self.Session(SimpleNamespace(
            isError=False, structuredContent=status))
        self.assertIs(await refresh._call(
            session, "grabowski_recovery_status", timeout=refresh.STATUS_TIMEOUT),
            status)
        self.assertEqual(session.calls[0][0], "grabowski_recovery_status")


class BusyProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_other_worker_published_latest_proof_without_duplicate_probe(self):
        done = current_status()
        done["server_recovery"]["generated_at_unix"] = NOW - 5
        with patch.object(refresh, "_call", new=AsyncMock(side_effect=[
            refresh.RecoveryRepositoryBusy("busy"), done
        ])) as call, patch.object(refresh.asyncio, "sleep",
                                   new=AsyncMock()) as sleep, patch.object(
            refresh, "latest_completed_backup_unix", return_value=NOW - 20
        ), patch.object(refresh.time, "time", return_value=NOW):
            proof, status = await refresh._probe_or_wait(
                object(), deadline=refresh.time.monotonic() + refresh.REFRESH_BUDGET_SECONDS
            )
        self.assertIsNone(proof)
        self.assertIs(status, done)
        self.assertEqual(call.await_count, 2)
        sleep.assert_awaited_once_with(refresh.BUSY_RETRY_INTERVAL_SECONDS)

    async def test_stale_or_unready_concurrent_proof_is_not_accepted(self):
        stale = current_status()
        stale["server_recovery"]["generated_at_unix"] = NOW - 80
        result = {"snapshot_id": "freshabcd"}
        with patch.object(refresh, "_call", new=AsyncMock(side_effect=[
            refresh.RecoveryRepositoryBusy("busy"), stale, result
        ])) as call, patch.object(refresh.asyncio, "sleep",
                                   new=AsyncMock()), patch.object(
            refresh, "latest_completed_backup_unix", return_value=NOW - 20
        ), patch.object(refresh.time, "time", return_value=NOW):
            proof, status = await refresh._probe_or_wait(
                object(), deadline=refresh.time.monotonic() + refresh.REFRESH_BUDGET_SECONDS
            )
        self.assertIs(proof, result)
        self.assertIsNone(status)
        self.assertEqual(call.await_count, 3)

    async def test_busy_exhaustion_fails_closed(self):
        with patch.object(refresh, "BUSY_RETRY_ATTEMPTS", 1), patch.object(
            refresh, "_call", new=AsyncMock(side_effect=[
                refresh.RecoveryRepositoryBusy("busy"), current_status(),
                refresh.RecoveryRepositoryBusy("busy")
            ])
        ), patch.object(refresh.asyncio, "sleep", new=AsyncMock()), patch.object(
            refresh, "latest_completed_backup_unix", return_value=NOW - 20
        ), patch.object(refresh.time, "time", return_value=NOW):
            with self.assertRaisesRegex(RuntimeError, "remains busy"):
                await refresh._probe_or_wait(
                    object(), deadline=refresh.time.monotonic() + refresh.REFRESH_BUDGET_SECONDS
                )

    async def test_late_busy_window_reduces_eventual_probe_timeout(self):
        clock = [100.0]
        deadline = clock[0] + refresh.REFRESH_BUDGET_SECONDS
        calls = []
        result = {"snapshot_id": "freshabcd"}

        async def call(_session, name, *, timeout):
            calls.append((name, timeout.total_seconds(), clock[0]))
            self.assertLess(clock[0], deadline)
            if name == "grabowski_recovery_status":
                clock[0] += 50
                return {}
            if len(calls) == 1:
                # A late lock conflict after a long initial request.
                clock[0] += 2000
                raise refresh.RecoveryRepositoryBusy("busy")
            return result

        async def sleep(seconds):
            clock[0] += seconds

        with patch.object(refresh.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(refresh, "_call", side_effect=call), \
                patch.object(refresh.asyncio, "sleep", side_effect=sleep):
            proof, status = await refresh._probe_or_wait(object(), deadline=deadline)
        self.assertIs(proof, result)
        self.assertIsNone(status)
        self.assertEqual(calls[0][1], refresh.TOOL_TIMEOUT.total_seconds())
        self.assertEqual(calls[-1][1], deadline - clock[0] - 50)
        self.assertLess(calls[-1][1], refresh.TOOL_TIMEOUT.total_seconds())

    async def test_budget_exhaustion_bounds_sleep_status_and_stops_probe(self):
        for remaining in (0, 50, 70, 120):
            with self.subTest(remaining=remaining):
                clock = [100.0]
                deadline = clock[0] + remaining
                calls = []
                sleeps = []

                async def call(_session, name, *, timeout):
                    self.assertLess(clock[0], deadline)
                    seconds = timeout.total_seconds()
                    self.assertLessEqual(seconds, deadline - clock[0])
                    calls.append((name, seconds))
                    if name == "grabowski_recovery_server_probe":
                        raise refresh.RecoveryRepositoryBusy("busy")
                    clock[0] += seconds
                    return {}

                async def sleep(seconds):
                    sleeps.append(seconds)
                    clock[0] += seconds + 10

                with patch.object(refresh.time, "monotonic", side_effect=lambda: clock[0]), \
                        patch.object(refresh, "_call", side_effect=call), \
                        patch.object(refresh.asyncio, "sleep", side_effect=sleep):
                    with self.assertRaisesRegex(RuntimeError, "time budget exhausted"):
                        await refresh._probe_or_wait(object(), deadline=deadline)
                if remaining <= 50:
                    self.assertEqual(calls, [])
                    self.assertEqual(sleeps, [])
                else:
                    self.assertEqual(sleeps, [min(60, remaining - 50)])
                    self.assertEqual(calls, [
                        ("grabowski_recovery_server_probe", remaining - 50),
                        ("grabowski_recovery_status", min(50, remaining - sleeps[0] - 10)),
                    ])

    async def test_other_probe_failures_do_not_trigger_retry(self):
        with patch.object(refresh, "_call", new=AsyncMock(
            side_effect=RuntimeError("repository integrity failed")
        )) as call, patch.object(refresh.asyncio, "sleep",
                                 new=AsyncMock()) as sleep:
            with self.assertRaisesRegex(RuntimeError, "integrity failed"):
                await refresh._probe_or_wait(
                    object(), deadline=refresh.time.monotonic() + refresh.REFRESH_BUDGET_SECONDS
                )
        call.assert_awaited_once()
        sleep.assert_not_awaited()


class DeclarationTests(unittest.TestCase):
    def test_fixed_nonroot_operator_path_is_used(self):
        module = MODULE.read_text()
        self.assertIn('systemd.services."grabowski-recovery-refresh" = lib.mkIf admit', module)
        self.assertIn('systemd.timers."grabowski-recovery-refresh" = lib.mkIf admit', module)
        self.assertIn('User = "alex";', module)
        self.assertIn(
            'ExecStart = "${cfg.operatorPackage}/bin/python3 -I -B '
            '${./grabowski-recovery-mcp-refresh.py}";', module
        )
        self.assertIn('NoNewPrivileges = true;', module)
        self.assertIn('RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" ];', module)
        self.assertIn('CapabilityBoundingSet = [ ];', module)

    def test_two_recovery_opportunities_after_native_backup(self):
        module = MODULE.read_text()
        self.assertIn('OnCalendar = "*-*-* 09,21:15:00";', module)
        self.assertIn('RandomizedDelaySec = "10m";', module)
        self.assertIn('Persistent = true;', module)
        self.assertIn('Unit = "grabowski-recovery-refresh.service";', module)
        self.assertEqual(refresh.REFRESH_AFTER_SECONDS, 11 * 60 * 60)

    def test_only_complete_mcp_publication_method_is_invoked(self):
        source = SCRIPT.read_text()
        self.assertIn('"grabowski_recovery_server_probe"', source)
        self.assertIn('"grabowski_recovery_status"', source)
        self.assertIn('127.0.0.1:18181/mcp', source)
        self.assertIn('"--timestamp=unix"', source)
        self.assertNotIn('shell=True', source)
        self.assertNotIn('sudo ', source)
        self.assertNotIn('restic restore', source)
        self.assertIn('all(v is True for v in after["checks"].values())', source)
        self.assertIn('while isinstance(exc, BaseExceptionGroup)', source)


if __name__ == "__main__":
    unittest.main()