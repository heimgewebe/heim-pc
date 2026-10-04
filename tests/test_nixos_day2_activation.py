from __future__ import annotations

import json
import os
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

        def __init__(self) -> None:
            self.wait_calls = 0

        def wait(self, timeout=None):
            self.wait_calls += 1
            events.append(("wait", timeout))
            if self.wait_calls == 1:
                raise executor.subprocess.TimeoutExpired(["executor"], timeout)
            return -9

    process = FakeProcess()

    def fake_popen(argv, **kwargs):
        events.append(("popen", list(argv), kwargs["start_new_session"]))
        return process

    monkeypatch.setattr(executor.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        executor.os,
        "killpg",
        lambda pid, sig: events.append(("killpg", pid, sig)),
    )

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

        def __init__(self) -> None:
            self.wait_calls = 0

        def wait(self, timeout=None):
            self.wait_calls += 1
            events.append(("wait", timeout))
            if self.wait_calls == 1:
                raise KeyboardInterrupt()
            return -9

    monkeypatch.setattr(executor.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(
        executor.os,
        "killpg",
        lambda pid, sig: events.append(("killpg", pid, sig)),
    )

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
        lambda pid, sig: events.append(("killpg", pid, sig)),
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
