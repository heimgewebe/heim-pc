from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "nixos_storage_rehearsal.py"
SPEC = importlib.util.spec_from_file_location("nixos_storage_rehearsal", SCRIPT)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

NOW = datetime(2026, 9, 5, 0, 30, 0, tzinfo=timezone.utc)


def _digest(value: dict, field: str) -> dict:
    result = copy.deepcopy(value)
    material = {key: item for key, item in result.items() if key != field}
    result[field] = m.sha256_json(material)
    return result


def target_evidence(**target_overrides):
    target = {
        "path": "/dev/loop7",
        "device_kind": "loop",
        "device_identity": "loop:/var/tmp/heim-pc-t005.img:12345",
        "size_bytes": 32 * 1024**3,
        "backing_file": "/var/tmp/heim-pc-t005.img",
        "blank": True,
        "mounted": False,
        "has_partition_table": False,
        "has_filesystem_signatures": False,
    }
    target.update(target_overrides)
    value = {
        "schema_version": 1,
        "kind": m.TARGET_KIND,
        "source": "fresh-block-device-readback",
        "observed_at": "2026-09-05T00:29:30Z",
        "target": target,
        "production": {
            "root_backing_devices": ["/dev/mapper/cryptroot", "/dev/nvme9n1"],
            "mounted_devices": ["/dev/nvme9n1p1", "/dev/nvme9n1p2"],
            "device_identities": ["production-root-eui-001"],
        },
        "evidence_sha256": "0" * 64,
    }
    return _digest(value, "evidence_sha256")


def sandbox_authority(evidence=None, **overrides):
    evidence = evidence or target_evidence()
    preflight = m.validate_target_evidence(evidence, now=NOW)
    value = {
        "schema_version": 1,
        "kind": m.AUTHORITY_KIND,
        "source_task": m.EXECUTOR_TASK,
        "run_id": "BUR-RUN-T003-DISPOSABLE-001",
        "resource": m.SANDBOX_RESOURCE,
        "exclusive": True,
        "target_path": preflight["target_path"],
        "target_identity": preflight["device_identity"],
        "production_exclusion_sha256": preflight["production_exclusion_sha256"],
        "observed_at": "2026-09-05T00:29:40Z",
        "expires_at": "2026-09-05T00:40:00Z",
        "receipt_sha256": "0" * 64,
    }
    value.update(overrides)
    return _digest(value, "receipt_sha256")


def topology_readback(evidence=None, authority=None):
    evidence = evidence or target_evidence()
    authority = authority or sandbox_authority(evidence)
    plan = m.compile_effect_plan(evidence, authority, now=NOW)
    partitions = [
        {
            "number": 1,
            "role": "efi-system-partition",
            "label": "EFI",
            "type_guid": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
            "device": "/dev/loop7p1",
            "size_bytes": 1024 * 1024**2,
        },
        {
            "number": 2,
            "role": "recovery-surface",
            "label": "RECOVERY",
            "type_guid": "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
            "device": "/dev/loop7p2",
            "size_bytes": 4096 * 1024**2,
        },
        {
            "number": 3,
            "role": "encrypted-system",
            "label": "NIXOS_CRYPT",
            "type_guid": "CA7D7CCB-63ED-4C53-861C-1742536059CC",
            "device": "/dev/loop7p3",
            "size_bytes": 27 * 1024**3,
        },
    ]
    value = {
        "schema_version": 1,
        "kind": m.READBACK_KIND,
        "source": "independent-runtime-readback",
        "observed_at": "2026-09-05T00:29:55Z",
        "target_path": "/dev/loop7",
        "plan_sha256": plan["plan_sha256"],
        "gpt": {"partition_table": "gpt", "partitions": partitions},
        "luks": {
            "version": 2,
            "container_device": "/dev/loop7p3",
            "mapper_name": "nixos-rehearsal-crypt",
            "unlocked": True,
        },
        "btrfs": {
            "label": "NIXOS_SYSTEM",
            "device": "/dev/mapper/nixos-rehearsal-crypt",
            "subvolumes": ["@root", "@nix", "@persist", "@home", "@data", "@containers"],
            "mounts": {
                "/": "@root",
                "/nix": "@nix",
                "/persist": "@persist",
                "/home": "@home",
                "/var/lib/heim-pc-data": "@data",
                "/var/lib/containers": "@containers",
            },
            "sandbox_mounts": m._sandbox_mounts(m.load_contract()),
        },
        "efi": {
            "device": "/dev/loop7p1",
            "filesystem": "vfat",
            "sandbox_mountpoint": m.EFI_MOUNT,
        },
        "recovery": {
            "device": "/dev/loop7p2",
            "filesystem": "ext4",
            "surface_present": True,
            "sandbox_mountpoint": m.RECOVERY_MOUNT,
        },
        "readback_sha256": "0" * 64,
    }
    return _digest(value, "readback_sha256")


def recovery_evidence():
    domains = {}
    for index, name in enumerate(m.load_contract()["recovery_evidence_domains"], start=1):
        domains[name] = {
            "status": "verified",
            "source": "off-host",
            "observed_at": "2026-09-04T23:00:00Z",
            "evidence_sha256": f"{index:064x}",
            "independence": {
                "network_required": False,
                "production_system_ssd_required": False,
                "grabowski_required": False,
                "bureau_required": False,
            },
        }
    value = {
        "schema_version": 1,
        "kind": m.RECOVERY_KIND,
        "observed_at": "2026-09-04T23:00:00Z",
        "domains": domains,
        "evidence_sha256": "0" * 64,
    }
    return _digest(value, "evidence_sha256")


def test_contract_is_digest_bound_and_exact_topology():
    contract = m.load_contract()
    assert m.sha256_json(json.loads(m.CONTRACT_PATH.read_text())) == m.CONTRACT_SHA256
    assert contract["topology"]["partition_table"] == "gpt"
    assert [item["role"] for item in contract["topology"]["partitions"]] == [
        "efi-system-partition",
        "recovery-surface",
        "encrypted-system",
    ]
    assert contract["topology"]["luks"]["version"] == 2
    assert [item["name"] for item in contract["topology"]["btrfs"]["subvolumes"]] == [
        "@root", "@nix", "@persist", "@home", "@data", "@containers"
    ]


def test_runtime_effect_boundary_belongs_to_t003():
    boundary = m.load_contract()["runtime_effect_boundary"]
    assert boundary["executor_task"] == "HEIM-PC-NIXOS-MIGRATION-V1-T003"
    assert boundary["exclusive_resource"] == "service.heim-pc-nixos-storage-rehearsal-sandbox"
    assert boundary["repository_task_may_execute"] is False
    assert boundary["effect_plan_execution_authorized"] is False
    assert boundary["requires_break_glass_runtime_authority"] is True


def test_fresh_blank_loop_target_is_admitted():
    result = m.validate_target_evidence(target_evidence(), now=NOW)
    assert result["status"] == "admitted-disposable-blank-target"
    assert result["target_path"] == "/dev/loop7"
    assert result["production_effects_authorized"] is False


@pytest.mark.parametrize(
    "override, message",
    [
        ({"blank": False}, "not explicitly blank"),
        ({"mounted": True}, "mounted"),
        ({"has_partition_table": True}, "partition table"),
        ({"has_filesystem_signatures": True}, "filesystem signatures"),
        ({"size_bytes": 8 * 1024**3}, "too small"),
    ],
)
def test_nonblank_or_unsafe_target_is_rejected(override, message):
    with pytest.raises(m.RehearsalError, match=message):
        m.validate_target_evidence(target_evidence(**override), now=NOW)


def test_stale_target_evidence_is_rejected():
    value = target_evidence()
    value["observed_at"] = "2026-09-04T23:00:00Z"
    value = _digest(value, "evidence_sha256")
    with pytest.raises(m.RehearsalError, match="stale"):
        m.validate_target_evidence(value, now=NOW)


@pytest.mark.parametrize(
    "path, kind",
    [("/dev/loopback", "loop"), ("/dev/loop7p1", "loop"), ("/dev/nbdfoo", "nbd"), ("/dev/nbd3p1", "nbd")],
)
def test_disposable_target_requires_exact_whole_device_name(path, kind):
    value = target_evidence(path=path, device_kind=kind)
    with pytest.raises(m.RehearsalError, match="whole-device kind"):
        m.validate_target_evidence(value, now=NOW)


def test_physical_nvme_cannot_be_a_disposable_target():
    value = target_evidence(path="/dev/nvme8n1", device_kind="nvme")
    with pytest.raises(m.RehearsalError, match="loop or nbd"):
        m.validate_target_evidence(value, now=NOW)


def test_target_matching_production_backing_is_rejected():
    value = target_evidence()
    value["production"]["root_backing_devices"].append("/dev/loop7")
    value = _digest(value, "evidence_sha256")
    with pytest.raises(m.RehearsalError, match="productive root backing"):
        m.validate_target_evidence(value, now=NOW)


def test_target_matching_production_identity_is_rejected():
    value = target_evidence()
    value["production"]["device_identities"].append(value["target"]["device_identity"])
    value = _digest(value, "evidence_sha256")
    with pytest.raises(m.RehearsalError, match="production device identity"):
        m.validate_target_evidence(value, now=NOW)


def test_plan_requires_exact_exclusive_t003_authority():
    evidence = target_evidence()
    authority = sandbox_authority(evidence, exclusive=False)
    with pytest.raises(m.RehearsalError, match="not exclusive"):
        m.compile_effect_plan(evidence, authority, now=NOW)


def test_authority_target_mismatch_is_rejected():
    evidence = target_evidence()
    authority = sandbox_authority(evidence, target_path="/dev/loop8")
    with pytest.raises(m.RehearsalError, match="target path mismatch"):
        m.compile_effect_plan(evidence, authority, now=NOW)


def test_effect_plan_is_argv_only_and_never_authorizes_execution():
    evidence = target_evidence()
    plan = m.compile_effect_plan(evidence, sandbox_authority(evidence), now=NOW)
    assert plan["execution_authorized"] is False
    assert plan["production_effects_authorized"] is False
    assert plan["requires_runtime_executor_reauthentication"] is True
    assert plan["runtime_executor_task"] == m.EXECUTOR_TASK
    effects = [item["effect"] for item in plan["commands"]]
    assert {
        "partition-table",
        "partition-table-reread",
        "udev-settle",
        "luks-format",
        "btrfs-filesystem",
        "efi-surface-mount",
        "recovery-surface-mount",
        "btrfs-subvolume-create",
        "btrfs-subvolume-mount",
    }.issubset(effects)
    mounted_subvolumes = [
        item for item in plan["commands"] if item["effect"] == "btrfs-subvolume-mount"
    ]
    assert len(mounted_subvolumes) == 6
    sandbox_mounts = m._sandbox_mounts(m.load_contract())
    assert {item["subvolume"] for item in mounted_subvolumes} == set(sandbox_mounts)
    assert {item["argv"][-1] for item in mounted_subvolumes} == set(sandbox_mounts.values())
    for command in plan["commands"]:
        assert isinstance(command["argv"], list)
        assert command["argv"]
        assert command["argv"][0] not in {"sh", "bash", "sudo"}
    secret_commands = [item for item in plan["commands"] if "secret_input" in item]
    assert secret_commands
    assert all(item["secret_input"] == "stdin" for item in secret_commands)
    assert all("password" not in " ".join(item["argv"]).lower() for item in secret_commands)


def test_plan_digest_is_stable_across_revalidation_clock():
    evidence = target_evidence()
    authority = sandbox_authority(evidence)
    later = NOW + timedelta(seconds=45)

    first = m.compile_effect_plan(evidence, authority, now=NOW)
    second = m.compile_effect_plan(evidence, authority, now=later)

    assert first["target_preflight"]["age_seconds"] != second["target_preflight"]["age_seconds"]
    assert first["plan_sha256"] == second["plan_sha256"]

    # A readback produced for the original plan must remain bound when it is
    # independently validated a little later, while all evidence is still fresh.
    result = m.validate_topology_readback(
        topology_readback(evidence, authority), evidence, authority, now=later
    )
    assert result["status"] == "passed"


def test_topology_readback_passes_only_exact_contract():
    evidence = target_evidence()
    authority = sandbox_authority(evidence)
    result = m.validate_topology_readback(
        topology_readback(evidence, authority), evidence, authority, now=NOW
    )
    assert result["status"] == "passed"
    assert result["independent_readback"] is True
    assert result["production_effects_authorized"] is False


def test_topology_readback_rejects_missing_data_subvolume():
    evidence = target_evidence()
    authority = sandbox_authority(evidence)
    value = topology_readback(evidence, authority)
    value["btrfs"]["subvolumes"].remove("@data")
    value = _digest(value, "readback_sha256")
    with pytest.raises(m.RehearsalError, match="subvolume"):
        m.validate_topology_readback(value, evidence, authority, now=NOW)


def test_topology_readback_rejects_sandbox_mount_drift():
    evidence = target_evidence()
    authority = sandbox_authority(evidence)
    value = topology_readback(evidence, authority)
    value["btrfs"]["sandbox_mounts"]["@data"] = "/mnt/wrong-data"
    value = _digest(value, "readback_sha256")
    with pytest.raises(m.RehearsalError, match="sandbox mount"):
        m.validate_topology_readback(value, evidence, authority, now=NOW)


def test_topology_readback_rejects_efi_surface_drift():
    evidence = target_evidence()
    authority = sandbox_authority(evidence)
    value = topology_readback(evidence, authority)
    value["efi"]["filesystem"] = "ext4"
    value = _digest(value, "readback_sha256")
    with pytest.raises(m.RehearsalError, match="EFI surface"):
        m.validate_topology_readback(value, evidence, authority, now=NOW)


def test_topology_readback_rejects_partition_type_drift():
    evidence = target_evidence()
    authority = sandbox_authority(evidence)
    value = topology_readback(evidence, authority)
    value["gpt"]["partitions"][2]["type_guid"] = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
    value = _digest(value, "readback_sha256")
    with pytest.raises(m.RehearsalError, match="partition topology"):
        m.validate_topology_readback(value, evidence, authority, now=NOW)


def test_topology_readback_rejects_luks_version_drift():
    evidence = target_evidence()
    authority = sandbox_authority(evidence)
    value = topology_readback(evidence, authority)
    value["luks"]["version"] = 1
    value = _digest(value, "readback_sha256")
    with pytest.raises(m.RehearsalError, match="LUKS2"):
        m.validate_topology_readback(value, evidence, authority, now=NOW)


def test_recovery_evidence_requires_all_independent_offhost_domains():
    result = m.validate_recovery_evidence(recovery_evidence(), now=NOW)
    assert result["status"] == "passed"
    assert set(result["domains"]) == set(m.load_contract()["recovery_evidence_domains"])
    reconstruction = result["reconstruction"]
    assert reconstruction["network_required"] is False
    assert reconstruction["production_system_ssd_required"] is False
    assert reconstruction["grabowski_required"] is False
    assert reconstruction["bureau_required"] is False


def test_recovery_evidence_rejects_missing_domain():
    value = recovery_evidence()
    value["domains"].pop("luks-recovery-material")
    value = _digest(value, "evidence_sha256")
    with pytest.raises(m.RehearsalError, match="incomplete"):
        m.validate_recovery_evidence(value, now=NOW)


def test_recovery_evidence_rejects_online_dependency():
    value = recovery_evidence()
    value["domains"]["offline-source-lock-trust"]["independence"]["network_required"] = True
    value = _digest(value, "evidence_sha256")
    with pytest.raises(m.RehearsalError, match="not offline"):
        m.validate_recovery_evidence(value, now=NOW)


def test_repository_harness_has_no_process_execution_primitive():
    source = SCRIPT.read_text()
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert "subprocess" not in imports
    assert "asyncio.subprocess" not in imports
    forbidden_calls = {"system", "popen", "spawn", "exec", "eval"}
    calls = {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))
    }
    assert not forbidden_calls.intersection(calls)


def test_harness_does_not_hardcode_historical_production_device_identity():
    source = SCRIPT.read_text() + m.CONTRACT_PATH.read_text()
    assert "SN850X" not in source
    assert "/dev/nvme0n1" not in source
    assert "historical nvme0n1" not in source

def test_partition_argv_is_compiled_from_contract_values():
    evidence = target_evidence()
    plan = m.compile_effect_plan(evidence, sandbox_authority(evidence), now=NOW)
    contract = m.load_contract()
    partition_commands = {
        item["partition_role"]: item["argv"]
        for item in plan["commands"]
        if "partition_role" in item
    }
    for partition in contract["topology"]["partitions"]:
        argv = partition_commands[partition["role"]]
        assert f"--typecode={partition['number']}:{partition['type_guid']}" in argv
        assert f"--change-name={partition['number']}:{partition['label']}" in argv
        size = partition["size"]
        expected_end = f"+{size['value']}MiB" if size["kind"] == "fixed_mib" else "0"
        assert f"--new={partition['number']}:0:{expected_end}" in argv


def test_plan_declares_same_luks_secret_binding_and_teardown():
    evidence = target_evidence()
    plan = m.compile_effect_plan(evidence, sandbox_authority(evidence), now=NOW)
    secret_commands = [item for item in plan["commands"] if "secret_binding" in item]
    assert {item["effect"] for item in secret_commands} == {"luks-format", "luks-open"}
    assert {item["secret_binding"] for item in secret_commands} == {"luks-key-v1"}
    assert plan["teardown_required"] is True
    assert plan["teardown_commands"][-1]["effect"] == "luks-close"
    assert all(item["argv"][0] in {"umount", "cryptsetup"} for item in plan["teardown_commands"])


def test_topology_readback_rejects_fixed_partition_size_drift():
    evidence = target_evidence()
    authority = sandbox_authority(evidence)
    value = topology_readback(evidence, authority)
    value["gpt"]["partitions"][0]["size_bytes"] += 1024**2
    value = _digest(value, "readback_sha256")
    with pytest.raises(m.RehearsalError, match="partition size"):
        m.validate_topology_readback(value, evidence, authority, now=NOW)


def test_recovery_evidence_rejects_stale_outer_or_domain_timestamp():
    stale_now = datetime(2026, 9, 20, 0, 30, 0, tzinfo=timezone.utc)
    with pytest.raises(m.RehearsalError, match="stale"):
        m.validate_recovery_evidence(recovery_evidence(), now=stale_now)

    value = recovery_evidence()
    value["observed_at"] = "2026-09-05T00:00:00Z"
    value["domains"]["backup-coverage"]["observed_at"] = "2026-08-01T00:00:00Z"
    value = _digest(value, "evidence_sha256")
    with pytest.raises(m.RehearsalError, match="backup-coverage.*stale"):
        m.validate_recovery_evidence(value, now=NOW)


def test_canonical_contract_digest_ignores_json_whitespace(tmp_path, monkeypatch):
    contract = m.load_contract()
    alternate = tmp_path / "contract.json"
    alternate.write_text(json.dumps(contract, ensure_ascii=False, separators=(",", ":")))
    monkeypatch.setattr(m, "CONTRACT_PATH", alternate)
    assert m.load_contract() == contract
