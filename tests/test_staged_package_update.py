from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "staged_package_update.py"
SPEC = importlib.util.spec_from_file_location("staged_package_update", SCRIPT)
assert SPEC and SPEC.loader
spu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(spu)


def test_run_strips_caller_apt_config(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv: list[str], **kwargs: object) -> Completed:
        captured.update(kwargs)
        return Completed()

    monkeypatch.setenv("APT_CONFIG", "/tmp/untrusted-apt.conf")
    monkeypatch.setattr(spu.subprocess, "run", fake_run)
    spu._run(["/usr/bin/true"])
    env = captured["env"]
    assert isinstance(env, dict)
    assert "APT_CONFIG" not in env


def test_apt_options_pin_system_sources_and_authenticated_repositories(tmp_path: Path) -> None:
    values = spu._apt_options(tmp_path)[1::2]
    assert "Dir::Etc::sourcelist=/etc/apt/sources.list" in values
    assert "Dir::Etc::sourceparts=/etc/apt/sources.list.d" in values
    assert "APT::Get::AllowUnauthenticated=false" in values
    assert "Acquire::AllowInsecureRepositories=false" in values
    assert "Acquire::AllowDowngradeToInsecureRepositories=false" in values
    assert "Acquire::AllowWeakRepositories=false" in values


def test_source_baseline_includes_active_signed_by_keyrings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gpg = tmp_path / "vendor.gpg"
    asc = tmp_path / "vendor.asc"
    gpg.write_bytes(b"gpg-key")
    asc.write_text("armored-key")
    list_source = tmp_path / "vendor.list"
    list_source.write_text(f"deb [signed-by={gpg}] https://example.invalid stable main\n")
    deb822_source = tmp_path / "vendor.sources"
    deb822_source.write_text(
        "Types: deb\nURIs: https://example.invalid/other\nSuites: stable\n"
        f"Signed-By: {asc}\n"
    )
    patterns = (str(list_source), str(deb822_source))
    monkeypatch.setattr(spu, "APT_SOURCE_FILE_PATTERNS", patterns)
    monkeypatch.setattr(spu, "APT_SOURCE_PATTERNS", patterns)
    records = spu._source_config_records()
    record_paths = {item["path"] for item in records}
    assert str(gpg) in record_paths
    assert str(asc) in record_paths
    baseline = records
    asc.write_text("rotated-armored-key")
    with pytest.raises(spu.PlanError, match="source/key configuration changed"):
        spu._validate_source_config(baseline)


def test_source_baseline_rejects_trusted_yes_bypass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "untrusted.list"
    source.write_text("deb [trusted=yes] https://example.invalid stable main\n")
    patterns = (str(source),)
    monkeypatch.setattr(spu, "APT_SOURCE_FILE_PATTERNS", patterns)
    monkeypatch.setattr(spu, "APT_SOURCE_PATTERNS", patterns)
    with pytest.raises(spu.PlanError, match="trusted=yes"):
        spu._source_config_records()


def test_apt_update_fails_closed_on_any_index_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> dict[str, object]:
        calls.append(argv)
        return {"argv": argv, "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(spu, "_run", fake_run)
    policy = {
        "apt": {
            "enabled": True,
            "max_packages": 10,
            "max_download_bytes": 1024,
            "sensitive_prefixes": [],
        }
    }
    result = spu._stage_apt(tmp_path / "stage", policy, os.geteuid())
    assert result["packages"] == []
    assert calls[0][-3:] == ["-o", "APT::Update::Error-Mode=any", "update"]


def test_parse_apt_simulation_keeps_exact_identity() -> None:
    text = "\n".join(
        [
            "Inst curl [7.81.0-1ubuntu1.25] (7.81.0-1ubuntu1.27 Ubuntu:22.04/jammy-security [amd64])",
            "Inst libssl3:i386 [3.0.2-0ubuntu1.26] (3.0.2-0ubuntu1.29 Ubuntu:22.04/jammy-security [i386])",
            "Conf curl (7.81.0-1ubuntu1.27 Ubuntu:22.04/jammy-security [amd64])",
        ]
    )
    assert spu.parse_apt_simulation(text) == [
        {"name": "curl", "version": "7.81.0-1ubuntu1.27", "arch": "amd64"},
        {"name": "libssl3:i386", "version": "3.0.2-0ubuntu1.29", "arch": "i386"},
    ]


def test_parse_snap_refresh_list_ignores_headers_and_prose() -> None:
    text = """Name Version Rev Size Publisher Notes
core22 20260410 2437 77.6MB canonical** base
gnome-46-2404 0+git.b31ceab 164 644MB canonical** -
"""
    assert spu.parse_snap_refresh_list(text) == [
        {"name": "core22", "version": "20260410", "revision": "2437"},
        {"name": "gnome-46-2404", "version": "0+git.b31ceab", "revision": "164"},
    ]


def test_plan_hash_excludes_only_hash_field() -> None:
    plan = {"schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "x", "value": 7}
    digest = spu._plan_digest(plan)
    plan["plan_sha256"] = digest
    assert spu._plan_digest(plan) == digest
    plan["value"] = 8
    assert spu._plan_digest(plan) != digest


def test_root_commands_are_networkless_and_never_execute_user_code(tmp_path: Path) -> None:
    policy = {
        "staging": {"root_root": "/var/lib/heim-pc/package-update-stages"},
    }
    stage = tmp_path / "stage"
    apt = {
        "packages": [
            {
                "relative_path": "apt/debs/000-curl-amd64-deadbeef.deb",
                "sha256": "a" * 64,
            }
        ]
    }
    snap = {
        "packages": [
            {
                "assert_relative_path": "snap/core22_2437.assert",
                "snap_relative_path": "snap/core22_2437.snap",
            }
        ]
    }
    commands = spu._root_commands("plan-id", stage, policy, apt, snap)
    apt_preflight = commands["apt_apply_preflight_argv"]
    apt_apply = commands["apt_apply_argv"]
    root_debs = "/var/lib/heim-pc/package-update-stages/plan-id/debs"
    assert apt_preflight == [
        "/usr/bin/dpkg", "--simulate", "--force-confold",
        "--install", "--recursive", root_debs,
    ]
    assert apt_apply == [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--collect",
        "--pipe",
        "--unit=heim-pc-package-update-plan-id.service",
        "--property=Type=exec",
        "--property=NoNewPrivileges=no",
        "--property=PrivateTmp=yes",
        "--property=MemoryDenyWriteExecute=no",
        "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "--property=IPAddressDeny=any",
        "--",
        "/usr/bin/dpkg",
        "--force-confold",
        "--install",
        "--recursive",
        root_debs,
    ]
    assert all("staged_package_update.py" not in arg for arg in apt_apply)
    assert all("apt-get" not in arg for arg in apt_apply)
    assert apt_apply[0] == "/usr/bin/systemd-run"
    assert "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK" in apt_apply
    assert "--property=IPAddressDeny=any" in apt_apply
    assert apt_apply[apt_apply.index("--") + 1] == "/usr/bin/dpkg"
    assert commands["snap_apply_argvs"] == [
        ["/usr/bin/snap", "ack", "/var/lib/heim-pc/package-update-stages/plan-id/snaps/core22_2437.assert"],
        ["/usr/bin/snap", "install", "/var/lib/heim-pc/package-update-stages/plan-id/snaps/core22_2437.snap"],
    ]
    assert all("--dangerous" not in argv for argv in commands["snap_apply_argvs"])


def test_dpkg_version_qualifies_multiarch_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> dict[str, object]:
        calls.append(argv)
        return {"argv": argv, "returncode": 0, "stdout": "3.0.2-0ubuntu1.29\n", "stderr": ""}

    monkeypatch.setattr(spu, "_run", fake_run)
    assert spu._dpkg_version("libssl3", "amd64") == "3.0.2-0ubuntu1.29"
    assert calls[-1][-1] == "libssl3:amd64"
    assert spu._dpkg_version("libssl3:i386", "i386") == "3.0.2-0ubuntu1.29"
    assert calls[-1][-1] == "libssl3:i386"


def test_dpkg_version_rejects_ambiguous_multirow_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        spu,
        "_run",
        lambda argv, **kwargs: {"argv": argv, "returncode": 0, "stdout": "1.0\n1.0\n", "stderr": ""},
    )
    assert spu._dpkg_version("libssl3", "amd64") is None


def test_policy_rejects_dangerous_snap(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy["snap"]["allow_dangerous"] = True
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="allow_dangerous"):
        spu.load_policy(path)


def test_policy_requires_broker_network_isolation(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy["safety"]["privileged_broker_network_must_remain_blocked"] = False
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="privileged_broker_network_must_remain_blocked"):
        spu.load_policy(path)


def test_policy_requires_read_only_handoff_guard(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy["safety"]["require_broker_read_only_handoff"] = False
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="require_broker_read_only_handoff"):
        spu.load_policy(path)


def test_policy_requires_recursive_dpkg_apply_guard(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy["safety"]["require_dpkg_recursive_apply"] = False
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="require_dpkg_recursive_apply"):
        spu.load_policy(path)


def test_handoff_root_must_be_below_declared_broker_bind() -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    assert spu._expand_runtime_root(policy, 1000) == Path(
        "/home/alex/repos/.heim-pc-worktrees/.package-update-handoff"
    )
    policy["staging"]["runtime_root"] = "/run/user/1000/heim-pc-package-updates"
    with pytest.raises(spu.PolicyError, match="broker_bind_root"):
        spu._expand_runtime_root(policy, 1000)


def test_effective_broker_bind_reset_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    output = """[Service]
BindReadOnlyPaths=/one /stale
[Service]
BindReadOnlyPaths=
BindReadOnlyPaths=-/home/alex/repos/.heim-pc-worktrees /other
"""
    monkeypatch.setattr(
        spu,
        "_run",
        lambda argv: {"argv": argv, "returncode": 0, "stdout": output, "stderr": ""},
    )
    assert spu._effective_broker_read_only_bindings() == [
        Path("/home/alex/repos/.heim-pc-worktrees"),
        Path("/other"),
    ]


def test_exact_confirmation_required() -> None:
    plan = {"schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "x"}
    plan["plan_sha256"] = spu._plan_digest(plan)
    spu._validate_confirmation(plan, plan["plan_sha256"])
    with pytest.raises(spu.PlanError, match="confirmation"):
        spu._validate_confirmation(plan, "0" * 64)


def test_postflight_rejects_policy_drift(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy, sort_keys=True))
    stage = tmp_path / "stage"
    stage.mkdir()
    plan = {
        "schema_version": 1,
        "kind": spu.PLAN_KIND,
        "plan_id": "policy-drift",
        "policy_path": str(policy_path),
        "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": []},
        "snap": {"packages": []},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    policy["postflight"]["system_services"] = []
    policy_path.write_text(json.dumps(policy, sort_keys=True))
    plan_path = _write_plan(tmp_path, plan)
    with pytest.raises(spu.PlanError, match="policy changed after planning"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))


def _write_plan(tmp_path: Path, plan: dict[str, object]) -> Path:
    path = tmp_path / (str(plan["plan_id"]) + ".json")
    path.write_text(json.dumps(plan, sort_keys=True))
    return path


def test_postflight_mismatch_writes_receipt_and_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage"
    stage.mkdir()
    plan: dict[str, object] = {
        "schema_version": 1,
        "kind": spu.PLAN_KIND,
        "plan_id": "mismatch",
        "policy_path": str(policy_path.resolve()),
        "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": [{"name": "curl", "arch": "amd64", "version": "wanted"}]},
        "snap": {"packages": []},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    monkeypatch.setattr(spu, "_dpkg_version", lambda name, arch=None: "actual")
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(
        spu,
        "_run",
        lambda argv, **kwargs: {"argv": argv, "returncode": 0, "stdout": "gpu-ok\n", "stderr": ""},
    )
    with pytest.raises(spu.PlanError, match="postflight target mismatch"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))
    receipt = json.loads((stage / "postflight.json").read_text())
    assert receipt["all_apt_matched"] is False
    assert receipt["all_snap_matched"] is True


def test_postflight_inactive_service_writes_receipt_and_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-service"
    stage.mkdir()
    plan: dict[str, object] = {
        "schema_version": 1,
        "kind": spu.PLAN_KIND,
        "plan_id": "service-mismatch",
        "policy_path": str(policy_path.resolve()),
        "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": []},
        "snap": {"packages": []},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    monkeypatch.setattr(
        spu, "_service_state",
        lambda unit, user: "inactive" if unit == "docker.service" else "active",
    )
    monkeypatch.setattr(
        spu, "_run",
        lambda argv, **kwargs: {"argv": argv, "returncode": 0, "stdout": "gpu-ok\n", "stderr": ""},
    )
    with pytest.raises(spu.PlanError, match="service health mismatch"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))
    receipt = json.loads((stage / "postflight.json").read_text())
    assert receipt["all_system_services_active"] is False
    assert receipt["all_user_services_active"] is True
    assert receipt["nvidia_smi_ok"] is True


def test_postflight_nvidia_failure_writes_receipt_and_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-nvidia"
    stage.mkdir()
    plan: dict[str, object] = {
        "schema_version": 1,
        "kind": spu.PLAN_KIND,
        "plan_id": "nvidia-mismatch",
        "policy_path": str(policy_path.resolve()),
        "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": []},
        "snap": {"packages": []},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(
        spu, "_run",
        lambda argv, **kwargs: {"argv": argv, "returncode": 1, "stdout": "", "stderr": "gpu failed"},
    )
    with pytest.raises(spu.PlanError, match="NVIDIA health mismatch"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))
    receipt = json.loads((stage / "postflight.json").read_text())
    assert receipt["all_system_services_active"] is True
    assert receipt["all_user_services_active"] is True
    assert receipt["nvidia_smi_ok"] is False
    assert receipt["nvidia_smi"] is None


def test_root_artifact_expectations_bind_destinations() -> None:
    plan = {
        "root_commands": {"root_stage": "/var/lib/heim-pc/package-update-stages/p"},
        "apt": {"packages": [{"relative_path": "apt/debs/a.deb", "sha256": "1" * 64}]},
        "snap": {
            "packages": [
                {
                    "assert_relative_path": "snap/a.assert",
                    "assert_sha256": "2" * 64,
                    "snap_relative_path": "snap/a.snap",
                    "snap_sha256": "3" * 64,
                }
            ]
        },
    }
    assert spu._artifact_expectations(plan) == {
        "/var/lib/heim-pc/package-update-stages/p/debs/a.deb": "1" * 64,
        "/var/lib/heim-pc/package-update-stages/p/snaps/a.assert": "2" * 64,
        "/var/lib/heim-pc/package-update-stages/p/snaps/a.snap": "3" * 64,
    }
