from __future__ import annotations

import fcntl
import json
import os
import signal
import sys
import threading
from contextlib import nullcontext
from pathlib import Path

import pytest

import scripts.managed_nix as managed_nix
import scripts.nixos_day2_activation as executor


REVISION = "1" * 40
LOCK_DIGEST = "2" * 64
CONTROL_DIGEST = "3" * 64
SOURCE_ARTIFACT_DIGEST = "4" * 64
CLOSURE = "/nix/store/11111111111111111111111111111111-nixos-system-heim-pc-26.05"
PRIOR = "/nix/store/22222222222222222222222222222222-nixos-system-heim-pc-26.05-prev"


def _quiescent_killpg(events):
    def killpg(pid, sig):
        events.append(("killpg", pid, sig))
        if sig == 0:
            raise ProcessLookupError

    return killpg


TARGET = "production:heim-pc"
NOW = "2026-10-04T09:00:00Z"


def build_request(*, possible_effects: list[str] | None = None) -> dict:
    return {
        "schema_version": 1,
        "kind": managed_nix.BUILD_REQUEST_KIND,
        "effect_class": "build",
        "repository": "heimgewebe/heim-pc",
        "source_revision": REVISION,
        "control_release_set": {"id": "control-2026-10", "digest": CONTROL_DIGEST},
        "nix_inputs": {"flake.lock": LOCK_DIGEST},
        "budgets": {
            "store_bytes": {"warning": 10_000, "hard": 20_000},
            "cache_bytes": {"warning": 1_000, "hard": 2_000},
            "runtime_seconds": {"warning": 300, "hard": 900},
        },
        "leases": ["nix-store:heim-pc", "repo:heim-pc@" + REVISION],
        "possible_effects": possible_effects or ["kernel", "initrd"],
        "entrypoint": list(managed_nix.CANONICAL_BUILD_ENTRYPOINT),
    }


def build_receipt(*, possible_effects: list[str] | None = None) -> dict:
    return managed_nix.make_build_receipt(
        build_request(possible_effects=possible_effects),
        observed_repository="heimgewebe/heim-pc",
        observed_source_revision=REVISION,
        system_closure=CLOSURE,
        declared_capabilities={"boot": {"uefi": True}},
    )


def activation_authority(receipt: dict, *, mode: str) -> dict:
    return {
        "schema_version": 1,
        "kind": managed_nix.ACTIVATION_AUTHORITY_KIND,
        "effect_class": "activation",
        "mode": mode,
        "source_revision": REVISION,
        "system_closure": CLOSURE,
        "target": TARGET,
        "build_receipt_sha256": managed_nix.sha256_json(receipt),
        "prior_closure": PRIOR,
        "recovery_path": "known-generation-and-rescue-medium",
        "issued_at": "2026-10-04T08:30:00Z",
        "expires_at": "2026-10-04T10:00:00Z",
    }


def activation_plan(receipt: dict, authority: dict) -> dict:
    return managed_nix.validate_activation_authority(
        receipt,
        authority,
        expected_authority_sha256=managed_nix.sha256_json(authority),
        expected_target=TARGET,
        now=NOW,
    )


def persistent_authority(receipt: dict) -> dict:
    prior_state = executor.persistent_state_sha256(
        target=TARGET,
        current_closure=PRIOR,
        profile_closure=PRIOR,
    )
    return {
        "schema_version": 2,
        "kind": managed_nix.PERSISTENT_PROMOTION_AUTHORITY_KIND,
        "effect_class": "persistent-promotion",
        "source_revision": REVISION,
        "source_artifact_sha256": SOURCE_ARTIFACT_DIGEST,
        "system_closure": CLOSURE,
        "target": TARGET,
        "build_receipt_sha256": managed_nix.sha256_json(receipt),
        "control_release_digest": CONTROL_DIGEST,
        "prior_closure": PRIOR,
        "prior_persistent_state_sha256": prior_state,
        "recovery_path": "known-generation-and-rescue-medium",
        "issued_at": "2026-10-04T08:30:00Z",
        "expires_at": "2026-10-04T10:00:00Z",
    }


def persistent_plan(receipt: dict, authority: dict) -> dict:
    return managed_nix.validate_persistent_promotion_authority(
        receipt,
        authority,
        expected_authority_sha256=managed_nix.sha256_json(authority),
        expected_target=TARGET,
        expected_source_artifact_sha256=SOURCE_ARTIFACT_DIGEST,
        expected_prior_closure=PRIOR,
        expected_prior_persistent_state_sha256=authority[
            "prior_persistent_state_sha256"
        ],
        now=NOW,
    )


def write_request(root: Path, request_id: str, receipt: dict, authority: dict, plan: dict) -> None:
    root.mkdir(mode=0o700)
    request = root / request_id
    request.mkdir(mode=0o700)
    for name, value in (
        ("build-receipt.json", receipt),
        ("authority.json", authority),
        ("plan.json", plan),
    ):
        path = request / name
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)


@pytest.fixture
def runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    request_root = tmp_path / "requests"
    trusted_uid = os.geteuid()
    monkeypatch.setattr(executor, "REQUEST_ROOT", request_root)
    monkeypatch.setattr(executor, "TRUSTED_UID", trusted_uid)
    monkeypatch.setattr(executor.os, "geteuid", lambda: 0)
    monkeypatch.setattr(executor, "_utc_now", lambda: NOW)
    monkeypatch.setattr(executor, "_exclusive_lock", lambda: nullcontext())
    monkeypatch.setattr(executor, "_require_executable", lambda path, **_: path)

    state = {"current": PRIOR, "profile": PRIOR}

    def resolve(path: Path, *, label: str) -> str:
        del label
        if path == executor.CURRENT_SYSTEM_LINK:
            return state["current"]
        if path == executor.SYSTEM_PROFILE_LINK:
            return state["profile"]
        raise AssertionError(f"unexpected runtime link {path}")

    monkeypatch.setattr(executor, "_resolve_link", resolve)

    def runner(argv, target_closure):
        del target_closure
        argv = list(argv)
        if "--profile" in argv and "--set" in argv:
            state["profile"] = argv[-1]
            return
        mode = argv[-1]
        closure = str(Path(argv[0]).parents[1])
        if mode in {"test", "switch"}:
            state["current"] = closure
        elif mode == "boot":
            return
        else:
            raise AssertionError(f"unexpected mode {mode}")

    return request_root, state, runner


def bindings(receipt: dict, authority: dict, plan: dict) -> dict[str, str]:
    return {
        "expected_build_receipt_sha256": managed_nix.sha256_json(receipt),
        "expected_authority_sha256": managed_nix.sha256_json(authority),
        "expected_plan_sha256": managed_nix.sha256_json(plan),
        "expected_target": TARGET,
    }


def _future_test_plan(receipt: dict, authority: dict) -> dict:
    plan = dict(activation_plan(receipt, authority))
    plan["mode"] = "test"
    return plan


def _allow_future_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        executor.managed_nix,
        "authorize_activation_plan_execution",
        lambda _build, _authority, plan, **_kwargs: dict(plan),
    )


def _allow_future_promotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_validate = executor.managed_nix.validate_build_receipt

    def non_boot_critical(receipt):
        value = dict(original_validate(receipt))
        value["effect_scope"] = "normal"
        return value

    monkeypatch.setattr(
        executor.managed_nix,
        "validate_build_receipt",
        non_boot_critical,
    )
    monkeypatch.setattr(
        executor.managed_nix,
        "authorize_persistent_promotion_execution",
        lambda _build, _authority, plan, **_kwargs: dict(plan),
    )


def test_current_managed_floor_rejects_test_authority_before_runtime_request(runtime) -> None:
    request_root, state, _runner = runtime
    receipt = build_receipt(possible_effects=["package-set"])
    assert managed_nix.classify_effect(receipt["possible_effects"]) == "normal"
    assert receipt["effect_scope"] == "boot-critical"
    authority = activation_authority(receipt, mode="test")

    with pytest.raises(
        managed_nix.ManagedNixError,
        match="boot-critical activation requires the next-boot path",
    ):
        activation_plan(receipt, authority)

    assert not request_root.exists()
    assert state == {"current": PRIOR, "profile": PRIOR}

def test_boot_critical_persistent_promotion_fails_before_runtime_effect(runtime) -> None:
    request_root, state, runner = runtime
    receipt = build_receipt()
    authority = persistent_authority(receipt)
    plan = persistent_plan(receipt, authority)
    write_request(request_root, "promotion-01", receipt, authority, plan)
    calls: list[list[str]] = []

    def recording_runner(argv, target_closure):
        calls.append(list(argv))
        runner(argv, target_closure)

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="boot-critical persistent promotion requires a successful next-boot successor proof",
    ):
        executor.execute_persistent_promotion(
            request_id="promotion-01",
            expected_source_artifact_sha256=SOURCE_ARTIFACT_DIGEST,
            runner=recording_runner,
            **bindings(receipt, authority, plan),
        )

    assert calls == []
    assert state == {"current": PRIOR, "profile": PRIOR}

def test_next_boot_digest_drift_fails_before_deferred_runtime_path(runtime) -> None:
    request_root, state, runner = runtime
    receipt = build_receipt()
    authority = activation_authority(receipt, mode="next-boot")
    plan = activation_plan(receipt, authority)
    write_request(request_root, "activation-02", receipt, authority, plan)
    calls: list[list[str]] = []

    def recording_runner(argv, target_closure):
        calls.append(list(argv))
        runner(argv, target_closure)

    values = bindings(receipt, authority, plan)
    values["expected_plan_sha256"] = "f" * 64
    with pytest.raises(executor.RuntimeExecutorError, match="externally bound digest"):
        executor.execute_activation(
            request_id="activation-02",
            runner=recording_runner,
            **values,
        )
    assert calls == []
    assert state == {"current": PRIOR, "profile": PRIOR}

def test_next_boot_is_deferred_before_live_state_readback_or_effect(
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_root, state, runner = runtime
    receipt = build_receipt()
    authority = activation_authority(receipt, mode="next-boot")
    plan = activation_plan(receipt, authority)
    write_request(request_root, "activation-03", receipt, authority, plan)
    calls: list[list[str]] = []

    def recording_runner(argv, target_closure):
        calls.append(list(argv))
        runner(argv, target_closure)

    monkeypatch.setattr(
        executor,
        "_require_link_target",
        lambda *_args, **_kwargs: pytest.fail("live state must not be read"),
    )

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="next-boot runtime execution is deferred",
    ):
        executor.execute_activation(
            request_id="activation-03",
            runner=recording_runner,
            **bindings(receipt, authority, plan),
        )

    assert calls == []
    assert state == {"current": PRIOR, "profile": PRIOR}

def test_persistent_state_digest_changes_with_runtime_state() -> None:
    prior = executor.persistent_state_sha256(
        target=TARGET,
        current_closure=PRIOR,
        profile_closure=PRIOR,
    )
    changed_current = executor.persistent_state_sha256(
        target=TARGET,
        current_closure=CLOSURE,
        profile_closure=PRIOR,
    )
    changed_profile = executor.persistent_state_sha256(
        target=TARGET,
        current_closure=PRIOR,
        profile_closure=CLOSURE,
    )
    assert prior != changed_current
    assert prior != changed_profile

def test_request_files_must_be_root_boundary_equivalent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request_root = tmp_path / "requests"
    request_root.mkdir(mode=0o700)
    request = request_root / "activation-05"
    request.mkdir(mode=0o700)
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    (request / "build-receipt.json").symlink_to(target)
    monkeypatch.setattr(executor, "REQUEST_ROOT", request_root)
    monkeypatch.setattr(executor, "TRUSTED_UID", os.geteuid())

    with pytest.raises(executor.RuntimeExecutorError, match="securely open"):
        executor._read_bound_json(request / "build-receipt.json")


def test_non_root_execution_is_rejected_before_request_loading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        executor,
        "_load_request",
        lambda _request_id: pytest.fail("request must not be read"),
    )
    with pytest.raises(executor.RuntimeExecutorError, match="requires root"):
        executor.execute_activation(
            request_id="activation-06",
            expected_build_receipt_sha256="a" * 64,
            expected_authority_sha256="b" * 64,
            expected_plan_sha256="c" * 64,
            expected_target=TARGET,
        )


def test_runtime_contract_keeps_capability_and_observer_boundaries_separate() -> None:
    contract = executor.CONTRACT
    runtime = contract["runtime"]
    assert contract["request"]["request_id_pattern"] == executor.REQUEST_ID_RE.pattern
    assert runtime["source_reevaluation_allowed"] is False
    assert runtime["shell_execution_allowed"] is False
    assert runtime["nix_rebuild_allowed"] is False
    assert runtime["rootbroker_authorization_implemented_here"] is False
    assert runtime["request_staging_implemented_here"] is False
    assert runtime["reboot_implemented_here"] is False
    activation = contract["supported_operations"]["activation"]
    assert activation["executable_modes"] == {"test": "test"}
    assert activation["deferred_modes"] == {
        "next-boot": "requires-reviewed-one-shot-boot-state-contract"
    }
    promotion = contract["supported_operations"]["persistent-promotion"]
    assert promotion["boot_critical_requires_next_boot_successor_proof"] is True
    assert promotion["boot_critical_execution_implemented_here"] is False
    persistent_state = contract["persistent_state"]
    assert persistent_state["kind"] == executor.PERSISTENT_STATE_KIND
    assert persistent_state["algorithm"] == "canonical-json-sha256-v1"
    assert persistent_state["fields"] == [
        "schema_version",
        "kind",
        "target",
        "current_closure",
        "persistent_profile_closure",
    ]
    assert executor.persistent_state_sha256(
        target=TARGET,
        current_closure=PRIOR,
        profile_closure=PRIOR,
    ) == executor._sha256_json(
        {
            "schema_version": 1,
            "kind": executor.PERSISTENT_STATE_KIND,
            "target": TARGET,
            "current_closure": PRIOR,
            "persistent_profile_closure": PRIOR,
        }
    )
    assert contract["execution_receipt"]["final_activation_receipt_established"] is False
    assert (
        contract["execution_receipt"]["independent_runtime_readback_established"]
        is False
    )



def test_run_exact_timeout_terminates_private_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 4242

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return -9

    process = FakeProcess()

    def fake_popen(argv, **kwargs):
        events.append(("popen", list(argv), kwargs["start_new_session"]))
        return process

    def timeout_before_reap(_process, argv):
        raise executor.subprocess.TimeoutExpired(
            list(argv), executor.COMMAND_TIMEOUT_SECONDS
        )

    monkeypatch.setattr(executor.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        executor,
        "_wait_for_process_exit_without_reaping",
        timeout_before_reap,
    )
    monkeypatch.setattr(executor.os, "killpg", _quiescent_killpg(events))

    with pytest.raises(executor.RuntimeExecutorError, match="process group terminated"):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert events[0][0] == "popen"
    assert events[0][2] is True
    assert ("killpg", 4242, executor.signal.SIGKILL) in events
    assert ("wait", None) in events


def test_run_exact_keyboard_interrupt_terminates_private_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 4343

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return -9

    def interrupt_before_reap(_process, _argv):
        raise KeyboardInterrupt()

    monkeypatch.setattr(executor.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(
        executor,
        "_wait_for_process_exit_without_reaping",
        interrupt_before_reap,
    )
    monkeypatch.setattr(executor.os, "killpg", _quiescent_killpg(events))

    with pytest.raises(executor.RuntimeExecutorError, match="interrupted; process group terminated"):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert ("killpg", 4343, executor.signal.SIGKILL) in events
    assert ("wait", None) in events

def test_run_exact_sigterm_during_spawn_is_deferred_until_child_can_be_reaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 4444

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return -9

    process = FakeProcess()

    def fake_popen(*_args, **_kwargs):
        handler = executor.signal.getsignal(executor.signal.SIGTERM)
        assert callable(handler)
        handler(executor.signal.SIGTERM, None)
        return process

    monkeypatch.setattr(executor.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        executor.os,
        "killpg",
        _quiescent_killpg(events),
    )

    with pytest.raises(executor.RuntimeExecutorError, match="interrupted; process group terminated"):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert ("killpg", 4444, executor.signal.SIGKILL) in events
    assert ("wait", None) in events



def test_run_exact_signal_after_wait_is_still_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 4545

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return -9

    def signal_after_exit_observation(_process, _argv):
        handler = executor.signal.getsignal(executor.signal.SIGTERM)
        assert callable(handler)
        handler(executor.signal.SIGTERM, None)
        return 0

    monkeypatch.setattr(executor.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(
        executor,
        "_wait_for_process_exit_without_reaping",
        signal_after_exit_observation,
    )
    monkeypatch.setattr(executor.os, "killpg", _quiescent_killpg(events))

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="interrupted; process group terminated",
    ):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert ("killpg", 4545, executor.signal.SIGKILL) in events
    assert ("wait", None) in events


def test_wait_for_process_exit_observes_without_reaping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 4590

    class Observed:
        si_code = executor.os.CLD_EXITED
        si_status = 7

    def waitid(idtype, pid, flags):
        events.append(("waitid", idtype, pid, flags))
        return Observed()

    monkeypatch.setattr(executor.os, "waitid", waitid)

    result = executor._wait_for_process_exit_without_reaping(
        FakeProcess(),
        ["/nix/store/helper", "switch"],
    )

    assert result == 7
    assert events == [
        (
            "waitid",
            executor.os.P_PID,
            4590,
            executor.os.WEXITED | executor.os.WNOWAIT | executor.os.WNOHANG,
        )
    ]


def test_run_exact_kills_group_before_reaping_nonzero_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 4591

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return 9

    monkeypatch.setattr(
        executor.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FakeProcess(),
    )
    monkeypatch.setattr(
        executor,
        "_wait_for_process_exit_without_reaping",
        lambda _process, _argv: events.append(("observed", 9)) or 9,
    )
    monkeypatch.setattr(executor.os, "killpg", _quiescent_killpg(events))

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="non-zero status 9",
    ):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert events[:4] == [
        ("observed", 9),
        ("killpg", 4591, executor.signal.SIGKILL),
        ("wait", None),
        ("killpg", 4591, 0),
    ]


def test_run_exact_waits_for_process_group_quiescence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []
    group_probes = 0

    class FakeProcess:
        pid = 4646

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return -9

    def timeout_before_reap(_process, argv):
        raise executor.subprocess.TimeoutExpired(
            list(argv), executor.COMMAND_TIMEOUT_SECONDS
        )

    def killpg(pid, sig):
        nonlocal group_probes
        events.append(("killpg", pid, sig))
        if sig == 0:
            group_probes += 1
            if group_probes >= 2:
                raise ProcessLookupError

    monkeypatch.setattr(executor.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(
        executor,
        "_wait_for_process_exit_without_reaping",
        timeout_before_reap,
    )
    monkeypatch.setattr(executor.os, "killpg", killpg)
    monkeypatch.setattr(
        executor.time,
        "sleep",
        lambda seconds: events.append(("sleep", seconds)),
    )

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="timed out; process group terminated",
    ):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert events == [
        ("killpg", 4646, executor.signal.SIGKILL),
        ("wait", None),
        ("killpg", 4646, 0),
        ("sleep", executor.PROCESS_GROUP_QUIESCENCE_POLL_SECONDS),
        ("killpg", 4646, 0),
    ]

def test_process_group_quiescence_retries_uncertain_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []
    probes = 0

    def killpg(pid, sig):
        nonlocal probes
        events.append(("killpg", pid, sig))
        assert sig == 0
        probes += 1
        if probes == 1:
            raise PermissionError("simulated uncertain probe")
        raise ProcessLookupError

    monkeypatch.setattr(executor.os, "killpg", killpg)
    monkeypatch.setattr(
        executor.time,
        "sleep",
        lambda seconds: events.append(("sleep", seconds)),
    )

    executor._wait_for_process_group_quiescence(4848)

    assert events == [
        ("killpg", 4848, 0),
        ("sleep", executor.PROCESS_GROUP_QUIESCENCE_POLL_SECONDS),
        ("killpg", 4848, 0),
    ]


def test_terminate_process_group_requires_quiescence_after_kill_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []
    probes = 0

    class FakeProcess:
        pid = 4949

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return -9

    def killpg(pid, sig):
        nonlocal probes
        events.append(("killpg", pid, sig))
        if sig == executor.signal.SIGKILL:
            raise PermissionError("simulated kill uncertainty")
        probes += 1
        if probes >= 2:
            raise ProcessLookupError

    monkeypatch.setattr(executor.os, "killpg", killpg)
    monkeypatch.setattr(
        executor.time,
        "sleep",
        lambda seconds: events.append(("sleep", seconds)),
    )

    executor._terminate_process_group(FakeProcess())

    assert events == [
        ("killpg", 4949, executor.signal.SIGKILL),
        ("wait", None),
        ("killpg", 4949, 0),
        ("sleep", executor.PROCESS_GROUP_QUIESCENCE_POLL_SECONDS),
        ("killpg", 4949, 0),
    ]


def test_terminate_process_group_uses_quiescence_after_wait_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 5050

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            raise ChildProcessError("simulated wait uncertainty")

    def killpg(pid, sig):
        events.append(("killpg", pid, sig))
        if sig == 0:
            raise ProcessLookupError

    monkeypatch.setattr(executor.os, "killpg", killpg)

    executor._terminate_process_group(FakeProcess())

    assert events == [
        ("killpg", 5050, executor.signal.SIGKILL),
        ("wait", None),
        ("killpg", 5050, 0),
    ]



def test_run_exact_inherits_active_lock_fd_into_real_child(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    real_popen = executor.subprocess.Popen
    lock_path = tmp_path / "activation.lock"
    monkeypatch.setattr(executor, "LOCK_PATH", lock_path)
    real_fstat = executor.os.fstat

    class RootOwnedStat:
        def __init__(self, fd: int) -> None:
            self._stat = real_fstat(fd)

        @property
        def st_uid(self) -> int:
            return 0

        def __getattr__(self, name: str):
            return getattr(self._stat, name)

    monkeypatch.setattr(executor.os, "fstat", lambda fd: RootOwnedStat(fd))
    captured_fd: int | None = None

    def real_child(_argv, **kwargs):
        nonlocal captured_fd
        pass_fds = tuple(kwargs.get("pass_fds", ()))
        assert len(pass_fds) == 1
        captured_fd = pass_fds[0]
        return real_popen(
            [
                sys.executable,
                "-c",
                f"import os; os.fstat({captured_fd})",
            ],
            **kwargs,
        )

    monkeypatch.setattr(executor.subprocess, "Popen", real_child)

    with executor._exclusive_lock():
        active_fd = executor._ACTIVE_LOCK_FD.get()
        assert active_fd is not None
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )
        assert captured_fd == active_fd


def test_posix_inherited_flock_survives_parent_sigkill_until_child_exit(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "activation.lock"
    helper = """
import fcntl
import os
import signal
import subprocess
import sys
import time

lock_path = sys.argv[1]
fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"],
    pass_fds=(fd,),
    close_fds=True,
    start_new_session=True,
)
print(child.pid, flush=True)
os.kill(os.getpid(), signal.SIGKILL)
"""
    parent = executor.subprocess.Popen(
        [sys.executable, "-c", helper, str(lock_path)],
        stdout=executor.subprocess.PIPE,
        stderr=executor.subprocess.PIPE,
        text=True,
    )
    child_pid: int | None = None
    contender_fd: int | None = None
    try:
        assert parent.stdout is not None
        child_pid = int(parent.stdout.readline().strip())
        assert parent.wait(timeout=5) == -signal.SIGKILL

        contender_fd = os.open(lock_path, os.O_RDWR)
        with pytest.raises(BlockingIOError):
            fcntl.flock(contender_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        os.killpg(child_pid, signal.SIGKILL)
        deadline = executor.time.monotonic() + 5
        while True:
            try:
                fcntl.flock(contender_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if executor.time.monotonic() >= deadline:
                    pytest.fail("inherited activation lock was not released after child exit")
                executor.time.sleep(0.01)
    finally:
        if child_pid is not None:
            try:
                os.killpg(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if contender_fd is not None:
            try:
                fcntl.flock(contender_fd, fcntl.LOCK_UN)
            finally:
                os.close(contender_fd)


def test_run_exact_normalizes_inherited_sigchld_ignore_for_real_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = executor.subprocess.Popen
    observed: list[object] = []

    def real_child(_argv, **kwargs):
        observed.append(executor.signal.getsignal(executor.signal.SIGCHLD))
        return real_popen([sys.executable, "-c", "pass"], **kwargs)

    previous = executor.signal.getsignal(executor.signal.SIGCHLD)
    executor.signal.signal(executor.signal.SIGCHLD, executor.signal.SIG_IGN)
    monkeypatch.setattr(executor.subprocess, "Popen", real_child)
    try:
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )
    finally:
        executor.signal.signal(executor.signal.SIGCHLD, previous)

    assert observed == [executor.signal.SIG_DFL]


def test_run_exact_real_sigterm_kills_real_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = executor.subprocess.Popen
    child_pid: int | None = None
    timer: threading.Timer | None = None

    def real_child(_argv, **kwargs):
        nonlocal child_pid, timer
        process = real_popen(
            ["/bin/sh", "-c", "/bin/sleep 30 & /bin/sleep 30"],
            **kwargs,
        )
        child_pid = process.pid
        timer = threading.Timer(
            0.1,
            lambda: os.kill(os.getpid(), signal.SIGTERM),
        )
        timer.start()
        return process

    monkeypatch.setattr(executor.subprocess, "Popen", real_child)
    try:
        with pytest.raises(
            executor.RuntimeExecutorError,
            match="interrupted; process group terminated",
        ):
            executor._run_exact(
                [
                    "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                    "switch",
                ],
                CLOSURE,
            )
    finally:
        if timer is not None:
            timer.join(timeout=2)

    assert child_pid is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(child_pid, 0)


def test_run_exact_quiescent_unknown_exit_becomes_recoverable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 5150
        returncode = None

    monkeypatch.setattr(executor.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(
        executor,
        "_wait_for_process_exit_without_reaping",
        lambda _process, _argv: (_ for _ in ()).throw(
            executor._ProcessTerminationUncertain("simulated missing wait status")
        ),
    )
    monkeypatch.setattr(executor.os, "killpg", _quiescent_killpg(events))

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="process group quiescence; recovery required",
    ):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert events == [("killpg", 5150, 0)]


def test_controlled_termination_covers_hup_and_quit() -> None:
    with executor._controlled_termination() as termination:
        for signum in (executor.signal.SIGHUP, executor.signal.SIGQUIT):
            handler = executor.signal.getsignal(signum)
            assert callable(handler)
            handler(signum, None)
    assert termination.requested is True


def test_run_exact_second_signal_before_cleanup_dispatch_is_deferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []
    cleanup_calls = 0

    class FakeProcess:
        pid = 5151

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return -9

    def first_interrupt(_process, _argv):
        handler = executor.signal.getsignal(executor.signal.SIGTERM)
        assert callable(handler)
        handler(executor.signal.SIGTERM, None)
        raise executor._ExecutorInterrupted()

    original_cleanup = executor._terminate_process_group

    def cleanup_after_second_signal(process):
        nonlocal cleanup_calls
        cleanup_calls += 1
        handler = executor.signal.getsignal(executor.signal.SIGTERM)
        assert callable(handler)
        handler(executor.signal.SIGTERM, None)
        return original_cleanup(process)

    monkeypatch.setattr(executor.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(executor, "_wait_for_process_exit_without_reaping", first_interrupt)
    monkeypatch.setattr(executor, "_terminate_process_group", cleanup_after_second_signal)
    monkeypatch.setattr(executor.os, "killpg", _quiescent_killpg(events))

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="interrupted; process group terminated",
    ):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert cleanup_calls == 1
    assert events == [
        ("killpg", 5151, executor.signal.SIGKILL),
        ("wait", None),
        ("killpg", 5151, 0),
    ]


def test_run_exact_signal_during_success_cleanup_is_not_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 5152

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            return -9

    def killpg(pid, sig):
        events.append(("killpg", pid, sig))
        if sig == executor.signal.SIGKILL:
            handler = executor.signal.getsignal(executor.signal.SIGTERM)
            assert callable(handler)
            handler(executor.signal.SIGTERM, None)
        elif sig == 0:
            raise ProcessLookupError

    monkeypatch.setattr(executor.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(
        executor,
        "_wait_for_process_exit_without_reaping",
        lambda _process, _argv: 0,
    )
    monkeypatch.setattr(executor.os, "killpg", killpg)

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="interrupted; process group terminated",
    ):
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )

    assert events.count(("killpg", 5152, executor.signal.SIGKILL)) == 1


def test_terminate_process_group_is_idempotent_after_reap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[object, ...]] = []

    class FakeProcess:
        pid = 5153
        returncode = None

        def wait(self, timeout=None):
            events.append(("wait", timeout))
            self.returncode = -9
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(executor.os, "killpg", _quiescent_killpg(events))

    executor._terminate_process_group(process)
    executor._terminate_process_group(process)

    assert events == [
        ("killpg", 5153, executor.signal.SIGKILL),
        ("wait", None),
        ("killpg", 5153, 0),
    ]

def test_controlled_termination_handler_is_flag_only_and_restores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous_handlers = (
        executor.signal.getsignal(executor.signal.SIGINT),
        executor.signal.getsignal(executor.signal.SIGTERM),
    )
    monkeypatch.setattr(
        executor.signal,
        "pthread_sigmask",
        lambda *_args, **_kwargs: pytest.fail("pthread_sigmask must not be used"),
    )

    with executor._controlled_termination() as termination:
        handler = executor.signal.getsignal(executor.signal.SIGTERM)
        assert callable(handler)
        handler(executor.signal.SIGTERM, None)
        assert termination.requested is True
        assert termination.signum == executor.signal.SIGTERM

    assert (
        executor.signal.getsignal(executor.signal.SIGINT),
        executor.signal.getsignal(executor.signal.SIGTERM),
    ) == previous_handlers

def test_second_sigterm_before_recovery_dispatch_does_not_abort_recovery(
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_root, state, runner = runtime
    receipt = build_receipt()
    authority = activation_authority(receipt, mode="next-boot")
    plan = _future_test_plan(receipt, authority)
    write_request(request_root, "activation-recovery-entry-signal", receipt, authority, plan)
    _allow_future_activation(monkeypatch)

    original_resolve = executor._resolve_link
    original_recover = executor._recover
    failed = False
    recovery_calls = 0

    def fail_post_readback(path: Path, *, label: str) -> str:
        nonlocal failed
        if (
            not failed
            and path == executor.CURRENT_SYSTEM_LINK
            and state["current"] == CLOSURE
        ):
            failed = True
            raise executor.RuntimeExecutorError("simulated post-effect readback failure")
        return original_resolve(path, label=label)

    def recover_after_second_signal(**kwargs):
        nonlocal recovery_calls
        recovery_calls += 1
        handler = executor.signal.getsignal(executor.signal.SIGTERM)
        assert callable(handler)
        handler(executor.signal.SIGTERM, None)
        return original_recover(**kwargs)

    monkeypatch.setattr(executor, "_resolve_link", fail_post_readback)
    monkeypatch.setattr(executor, "_recover", recover_after_second_signal)

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="prior closure recovery completed",
    ):
        executor.execute_activation(
            request_id="activation-recovery-entry-signal",
            runner=runner,
            **bindings(receipt, authority, plan),
        )

    assert recovery_calls == 1
    assert state == {"current": PRIOR, "profile": PRIOR}

def test_run_exact_preserves_inherited_ignored_termination_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_handlers: list[tuple[object, object]] = []
    previous_handlers = (
        executor.signal.getsignal(executor.signal.SIGINT),
        executor.signal.getsignal(executor.signal.SIGTERM),
    )

    class FakeProcess:
        pid = 4747

        def wait(self, timeout=None):
            assert timeout is None
            return 0

    def fake_popen(*_args, **_kwargs):
        observed_handlers.append(
            (
                executor.signal.getsignal(executor.signal.SIGINT),
                executor.signal.getsignal(executor.signal.SIGTERM),
            )
        )
        return FakeProcess()

    monkeypatch.setattr(executor.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        executor,
        "_wait_for_process_exit_without_reaping",
        lambda _process, _argv: 0,
    )
    monkeypatch.setattr(executor.os, "killpg", _quiescent_killpg([]))

    executor.signal.signal(executor.signal.SIGINT, executor.signal.SIG_IGN)
    executor.signal.signal(executor.signal.SIGTERM, executor.signal.SIG_IGN)
    try:
        executor._run_exact(
            [
                "/nix/store/33333333333333333333333333333333-helper/bin/helper",
                "switch",
            ],
            CLOSURE,
        )
    finally:
        executor.signal.signal(executor.signal.SIGINT, previous_handlers[0])
        executor.signal.signal(executor.signal.SIGTERM, previous_handlers[1])

    assert observed_handlers == [(executor.signal.SIG_IGN, executor.signal.SIG_IGN)]

def test_test_activation_sigterm_after_effect_starts_recovery(
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_root, state, runner = runtime
    receipt = build_receipt()
    authority = activation_authority(receipt, mode="next-boot")
    plan = _future_test_plan(receipt, authority)
    write_request(request_root, "activation-post-effect-signal", receipt, authority, plan)
    _allow_future_activation(monkeypatch)

    original_resolve = executor._resolve_link
    signalled = False

    def signal_before_readback(path: Path, *, label: str) -> str:
        nonlocal signalled
        if (
            not signalled
            and path == executor.CURRENT_SYSTEM_LINK
            and state["current"] == CLOSURE
        ):
            signalled = True
            handler = executor.signal.getsignal(executor.signal.SIGTERM)
            assert callable(handler)
            handler(executor.signal.SIGTERM, None)
        return original_resolve(path, label=label)

    monkeypatch.setattr(executor, "_resolve_link", signal_before_readback)

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="prior closure recovery completed",
    ):
        executor.execute_activation(
            request_id="activation-post-effect-signal",
            runner=runner,
            **bindings(receipt, authority, plan),
        )

    assert state == {"current": PRIOR, "profile": PRIOR}


def test_uncertain_child_termination_does_not_start_activation_recovery(
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_root, state, _runner = runtime
    receipt = build_receipt()
    authority = activation_authority(receipt, mode="next-boot")
    plan = _future_test_plan(receipt, authority)
    write_request(request_root, "activation-uncertain-child", receipt, authority, plan)
    _allow_future_activation(monkeypatch)
    calls = 0

    def uncertain_runner(_argv, _target_closure):
        nonlocal calls
        calls += 1
        state["current"] = CLOSURE
        raise executor._ProcessTerminationUncertain("simulated uncertain termination")

    with pytest.raises(
        executor._ProcessTerminationUncertain,
        match="simulated uncertain termination",
    ):
        executor.execute_activation(
            request_id="activation-uncertain-child",
            runner=uncertain_runner,
            **bindings(receipt, authority, plan),
        )

    assert calls == 1
    assert state["current"] == CLOSURE


def test_uncertain_child_termination_does_not_start_promotion_recovery(
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_root, state, _runner = runtime
    receipt = build_receipt()
    authority = persistent_authority(receipt)
    plan = persistent_plan(receipt, authority)
    write_request(request_root, "promotion-uncertain-child", receipt, authority, plan)
    _allow_future_promotion(monkeypatch)
    calls = 0

    def uncertain_runner(argv, _target_closure):
        nonlocal calls
        calls += 1
        if "--profile" in list(argv):
            state["profile"] = CLOSURE
        raise executor._ProcessTerminationUncertain("simulated uncertain termination")

    with pytest.raises(
        executor._ProcessTerminationUncertain,
        match="simulated uncertain termination",
    ):
        executor.execute_persistent_promotion(
            request_id="promotion-uncertain-child",
            expected_source_artifact_sha256=SOURCE_ARTIFACT_DIGEST,
            runner=uncertain_runner,
            **bindings(receipt, authority, plan),
        )

    assert calls == 1
    assert state["profile"] == CLOSURE


def test_recover_does_not_write_profile_when_profile_is_already_prior(
    runtime,
) -> None:
    _request_root, state, runner = runtime
    calls: list[list[str]] = []

    def tracking_runner(argv, target_closure):
        calls.append(list(argv))
        runner(argv, target_closure)

    executor._recover(
        prior_closure=PRIOR,
        mode="test",
        runner=tracking_runner,
        profile_may_have_changed=True,
    )

    assert state == {"current": PRIOR, "profile": PRIOR}
    assert all("--profile" not in call for call in calls)
    assert calls == [[str(Path(PRIOR) / "bin" / "switch-to-configuration"), "test"]]


def test_recover_stops_after_uncertain_profile_rollback(
    runtime,
) -> None:
    _request_root, state, _runner = runtime
    state["profile"] = CLOSURE
    calls: list[list[str]] = []

    def uncertain_recovery_runner(argv, _target_closure):
        calls.append(list(argv))
        if len(calls) == 1:
            raise executor._ProcessTerminationUncertain(
                "simulated uncertain recovery termination"
            )
        pytest.fail("no second recovery process may start after uncertain termination")

    with pytest.raises(
        executor._ProcessTerminationUncertain,
        match="simulated uncertain recovery termination",
    ):
        executor._recover(
            prior_closure=PRIOR,
            mode="switch",
            runner=uncertain_recovery_runner,
            profile_may_have_changed=True,
        )

    assert len(calls) == 1
    assert "--profile" in calls[0]


def test_test_activation_post_readback_failure_recovers_bound_prior_state(
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_root, state, runner = runtime
    receipt = build_receipt()
    authority = activation_authority(receipt, mode="next-boot")
    plan = _future_test_plan(receipt, authority)
    write_request(request_root, "activation-post-readback", receipt, authority, plan)
    _allow_future_activation(monkeypatch)

    original_resolve = executor._resolve_link
    failed = False

    def flaky_resolve(path: Path, *, label: str) -> str:
        nonlocal failed
        if (
            not failed
            and path == executor.CURRENT_SYSTEM_LINK
            and state["current"] == CLOSURE
        ):
            failed = True
            raise executor.RuntimeExecutorError("simulated post-effect readback failure")
        return original_resolve(path, label=label)

    monkeypatch.setattr(executor, "_resolve_link", flaky_resolve)

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="prior closure recovery completed",
    ):
        executor.execute_activation(
            request_id="activation-post-readback",
            runner=runner,
            **bindings(receipt, authority, plan),
        )

    assert state == {"current": PRIOR, "profile": PRIOR}


def test_persistent_post_readback_failure_recovers_bound_prior_state(
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_root, state, runner = runtime
    receipt = build_receipt()
    authority = persistent_authority(receipt)
    plan = persistent_plan(receipt, authority)
    write_request(request_root, "promotion-post-readback", receipt, authority, plan)
    _allow_future_promotion(monkeypatch)

    original_resolve = executor._resolve_link
    failed = False

    def flaky_resolve(path: Path, *, label: str) -> str:
        nonlocal failed
        if (
            not failed
            and path == executor.CURRENT_SYSTEM_LINK
            and state["current"] == CLOSURE
        ):
            failed = True
            raise executor.RuntimeExecutorError("simulated post-effect readback failure")
        return original_resolve(path, label=label)

    monkeypatch.setattr(executor, "_resolve_link", flaky_resolve)

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="prior closure recovery completed",
    ):
        executor.execute_persistent_promotion(
            request_id="promotion-post-readback",
            expected_source_artifact_sha256=SOURCE_ARTIFACT_DIGEST,
            runner=runner,
            **bindings(receipt, authority, plan),
        )

    assert state == {"current": PRIOR, "profile": PRIOR}


def test_partial_profile_mutation_on_runner_error_is_rolled_back(
    runtime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_root, state, runner = runtime
    receipt = build_receipt()
    authority = persistent_authority(receipt)
    plan = persistent_plan(receipt, authority)
    write_request(request_root, "promotion-partial-profile", receipt, authority, plan)
    _allow_future_promotion(monkeypatch)
    first_profile_call = True

    def partial_runner(argv, target_closure):
        nonlocal first_profile_call
        argv = list(argv)
        if first_profile_call and "--profile" in argv and "--set" in argv:
            first_profile_call = False
            state["profile"] = argv[-1]
            raise executor.RuntimeExecutorError("simulated profile helper failure")
        runner(argv, target_closure)

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="prior closure recovery completed",
    ):
        executor.execute_persistent_promotion(
            request_id="promotion-partial-profile",
            expected_source_artifact_sha256=SOURCE_ARTIFACT_DIGEST,
            runner=partial_runner,
            **bindings(receipt, authority, plan),
        )

    assert state == {"current": PRIOR, "profile": PRIOR}


def test_recover_refuses_completed_claim_when_runtime_readback_is_not_restored(
    runtime,
) -> None:
    _request_root, state, _runner = runtime
    state["current"] = CLOSURE
    state["profile"] = CLOSURE

    with pytest.raises(
        executor.RuntimeExecutorError,
        match="recovery verification failed",
    ):
        executor._recover(
            prior_closure=PRIOR,
            mode="switch",
            runner=lambda _argv, _target: None,
            profile_may_have_changed=True,
        )


def test_main_preserves_inherited_ignored_termination_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[object, ...]] = []

    def fake_execute_activation(**_kwargs):
        observed.append(
            tuple(executor.signal.getsignal(signum) for signum in executor._TERMINATION_SIGNALS)
        )
        return {"schema_version": 1, "result": "executed"}

    monkeypatch.setattr(executor, "execute_activation", fake_execute_activation)
    previous = {
        signum: executor.signal.getsignal(signum)
        for signum in executor._TERMINATION_SIGNALS
    }
    for signum in executor._TERMINATION_SIGNALS:
        executor.signal.signal(signum, executor.signal.SIG_IGN)
    try:
        digest = "a" * 64
        rc = executor.main(
            [
                "execute-activation",
                "--request-id",
                "preserve-ignored-cli",
                "--expected-build-receipt-sha256",
                digest,
                "--expected-authority-sha256",
                digest,
                "--expected-plan-sha256",
                digest,
                "--expected-target",
                TARGET,
            ]
        )
    finally:
        for signum, handler in previous.items():
            executor.signal.signal(signum, handler)

    assert rc == 0
    assert observed == [tuple(executor.signal.SIG_IGN for _ in executor._TERMINATION_SIGNALS)]


def test_main_keeps_flag_only_handler_through_receipt_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes: list[bytes] = []

    class Buffer:
        def write(self, data: bytes) -> int:
            handler = executor.signal.getsignal(executor.signal.SIGTERM)
            assert callable(handler)
            handler(executor.signal.SIGTERM, None)
            writes.append(data)
            return len(data)

        def flush(self) -> None:
            return None

    class Stdout:
        buffer = Buffer()

    monkeypatch.setattr(executor.sys, "stdout", Stdout())
    monkeypatch.setattr(
        executor,
        "execute_activation",
        lambda **_kwargs: {"schema_version": 1, "result": "executed"},
    )

    digest = "a" * 64
    rc = executor.main(
        [
            "execute-activation",
            "--request-id",
            "receipt-window",
            "--expected-build-receipt-sha256",
            digest,
            "--expected-authority-sha256",
            digest,
            "--expected-plan-sha256",
            digest,
            "--expected-target",
            TARGET,
        ]
    )

    assert rc == 0
    assert writes == [b'{"result":"executed","schema_version":1}\n']


def test_runtime_contract_loader_rejects_security_boundary_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mutations = [
        lambda value: value["request"].__setitem__(
            "root", "/run/heim-pc/other-requests"
        ),
        lambda value: value["runtime"].__setitem__(
            "lock_path", "/run/lock/other.lock"
        ),
        lambda value: value["supported_operations"]["activation"].__setitem__(
            "executor_authority", "broad-root"
        ),
        lambda value: value["persistent_state"].__setitem__(
            "algorithm", "unbound"
        ),
        lambda value: value["execution_receipt"].__setitem__(
            "independent_runtime_readback_established", True
        ),
        lambda value: value["forbidden_effects"].remove("reboot"),
    ]
    for index, mutate in enumerate(mutations):
        drifted = json.loads(json.dumps(executor.CONTRACT))
        mutate(drifted)
        contract_path = tmp_path / f"runtime-executor-{index}.json"
        contract_path.write_text(json.dumps(drifted), encoding="utf-8")
        monkeypatch.setattr(executor, "_CONTRACT_PATH", contract_path)
        with pytest.raises(executor.RuntimeExecutorError, match="drifted"):
            executor._load_contract()


def test_nixos_module_installs_executor_only_for_physical_host_profiles() -> None:
    root = Path(__file__).parents[1]
    module = (root / "nixos/system/modules/day2-activation.nix").read_text()
    host = (root / "nixos/system/hosts/heim-pc/default.nix").read_text()
    assert "heim-pc-nixos-activation-executor" in module
    assert "runtime-executor-v1.json" in module
    assert "systemd.tmpfiles.rules" in module
    assert "systemd.services" not in module
    assert "grabowski-privileged-request" not in module
    assert "repositoryRoot" not in module
    assert "managedNixSource = ../../../scripts/managed_nix.py;" in module
    assert "runtimeExecutorContractSource = ../../deployment/runtime-executor-v1.json;" in module
    assert "../../modules/day2-activation.nix" in host
    assert "heimPc.day2Activation.enable = heimPcProfile.physical or false;" in host