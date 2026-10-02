from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "nixos_critical_user_data_offline_inventory.py"
spec = importlib.util.spec_from_file_location("nixos_critical_user_data_offline_inventory", MODULE)
offline = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(offline)

REVISION = "a" * 40
TARGET = "/dev/disk/by-id/nvme-SYNTHETIC_TARGET_0001"
SOURCE = "/dev/disk/by-id/nvme-SYNTHETIC_FALLBACK_0002"
PUBLIC = json.loads((ROOT / "nixos/production/contract-v1.json").read_text(encoding="utf-8"))


def private_identity():
    public_payload = json.dumps(
        PUBLIC, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_storage_identity",
        "source_revision": REVISION,
        "public_contract_sha256": hashlib.sha256(public_payload).hexdigest(),
        "target_identity": {
            "exact_by_id": TARGET,
            "exact_serial": "SYNTH-TARGET-SERIAL",
            "exact_wwn": "eui.synthetic-target",
            "preimage": {
                "partition_table": "gpt",
                "gpt_disk_guid": "44444444-4444-4444-8444-444444444444",
                "logical_sector_size": 512,
                "signatures": [
                    {"type": "gpt", "uuid": None},
                    {"type": "PMBR", "uuid": None},
                ],
                "partitions": [
                    {
                        "number": 1,
                        "size_bytes": 1073741824,
                        "start_sector": 2048,
                        "partuuid": "aaaaaaaa-1111-4111-8111-111111111111",
                        "type_guid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                        "partlabel": "NIXOS2_EFI",
                        "fstype": "vfat",
                        "uuid": "SYN-TARGET-EFI",
                        "signatures": [{"type": "vfat", "uuid": "SYN-TARGET-EFI"}],
                    },
                    {
                        "number": 2,
                        "size_bytes": 4294967296,
                        "start_sector": 2099200,
                        "partuuid": "bbbbbbbb-2222-4222-8222-222222222222",
                        "type_guid": "0fc63daf-8483-4772-8e79-3d69d8477de4",
                        "partlabel": "NIXOS2_RECOVERY",
                        "fstype": "ext4",
                        "uuid": "SYN-TARGET-RECOVERY",
                        "signatures": [{"type": "ext4", "uuid": "SYN-TARGET-RECOVERY"}],
                    },
                    {
                        "number": 3,
                        "size_bytes": 3995417255424,
                        "start_sector": 10487808,
                        "partuuid": "cccccccc-3333-4333-8333-333333333333",
                        "type_guid": "ca7d7ccb-63ed-4c53-861c-1742536059cc",
                        "partlabel": "NIXOS2_CRYPT",
                        "fstype": "",
                        "uuid": "",
                        "signatures": [],
                    },
                ],
            },
        },
        "protected_disks": [{
            "role": "popos-fallback",
            "by_id": SOURCE,
            "serial": "SYNTH-FALLBACK-SERIAL",
            "wwn": "eui.synthetic-fallback",
            "verified_by_id_aliases": [],
            "partition_table_fingerprint": [
                {"number": 1, "partuuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", "uuid": "SYN1-0001"},
                {"number": 2, "partuuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2", "uuid": "SYN2-0002"},
                {"number": 3, "partuuid": "cccccccc-cccc-4ccc-8ccc-ccccccccccc3", "uuid": "SYNTH-ROOT-UUID"},
                {"number": 4, "partuuid": "dddddddd-dddd-4ddd-8ddd-ddddddddddd4", "uuid": "SYNTH-SWAP-UUID"},
            ],
        }],
        "topology": {
            "partitions": [
                {"number": 1, "partuuid": "11111111-1111-4111-8111-111111111111"},
                {"number": 2, "partuuid": "22222222-2222-4222-8222-222222222222"},
                {"number": 3, "partuuid": "33333333-3333-4333-8333-333333333333"},
            ],
        },
    }


def bound_contract(tmp_path: Path):
    identity = tmp_path / "private-storage-identity.env"
    identity.write_text(json.dumps(private_identity()) + "\n", encoding="utf-8")
    identity.chmod(0o600)
    return offline.load_bound_contract(ROOT, identity, REVISION)


def source_tree(contract):
    protected = contract["protected_disks"][0]
    parts = protected["partition_table_fingerprint"]
    return {
        "path": "/dev/nvme9n1",
        "type": "disk",
        "size": protected["size_bytes"],
        "model": protected["model"],
        "serial": protected["serial"],
        "wwn": protected["wwn"],
        "tran": "nvme",
        "mountpoints": [None],
        "children": [
            {
                "path": f"/dev/nvme9n1p{item['number']}",
                "type": "part",
                "partn": item["number"],
                "size": item["size_bytes"],
                "fstype": item["fstype"],
                "partuuid": item["partuuid"],
                "uuid": item["uuid"],
                "mountpoints": [None],
            }
            for item in parts
        ],
    }


def test_bound_contract_uses_revision_bound_private_popos_authority(tmp_path):
    contract = bound_contract(tmp_path)
    assert contract["protected_disks"][0]["role"] == "popos-fallback"
    assert contract["protected_disks"][0]["by_id"] == SOURCE
    root = offline._protected_root_partition(contract)
    assert root["number"] == 3
    assert root["partuuid"] == "cccccccc-cccc-4ccc-8ccc-ccccccccccc3"


def test_private_identity_revision_mismatch_fails_closed(tmp_path):
    identity = private_identity()
    identity["source_revision"] = "b" * 40
    path = tmp_path / "private-storage-identity.env"
    path.write_text(json.dumps(identity) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(offline.OfflineInventoryError, match="rejected"):
        offline.load_bound_contract(ROOT, path, REVISION)


def test_source_tree_requires_exact_private_identity_and_unmounted_partitions(tmp_path):
    contract = bound_contract(tmp_path)
    valid = source_tree(contract)
    observed = offline._validate_source_tree(contract, Path("/dev/nvme9n1"), valid)
    assert observed["root_partition"] == "/dev/nvme9n1p3"
    assert observed["root_partuuid"] == "cccccccc-cccc-4ccc-8ccc-ccccccccccc3"
    assert observed["devices"][-1] == "/dev/nvme9n1"

    mounted = source_tree(contract)
    mounted["children"][2]["mountpoints"] = ["/legacy"]
    with pytest.raises(offline.OfflineInventoryError, match="mounted"):
        offline._validate_source_tree(contract, Path("/dev/nvme9n1"), mounted)

    nested_mounted = source_tree(contract)
    nested_mounted["children"][2]["children"] = [
        {"type": "crypt", "mountpoints": ["/legacy"]}
    ]
    with pytest.raises(offline.OfflineInventoryError, match="mounted device alias"):
        offline._validate_source_tree(
            contract, Path("/dev/nvme9n1"), nested_mounted
        )

    wrong_serial = source_tree(contract)
    wrong_serial["serial"] = "OTHER"
    with pytest.raises(offline.OfflineInventoryError, match="identity mismatch"):
        offline._validate_source_tree(contract, Path("/dev/nvme9n1"), wrong_serial)


def test_evidence_must_be_ext4_removable_usb():
    partition = {
        "path": "/dev/sdz1",
        "type": "part",
        "fstype": "ext4",
        "label": offline.EVIDENCE_LABEL,
        "mountpoints": [None],
    }
    parent = {
        "path": "/dev/sdz",
        "type": "disk",
        "tran": "usb",
        "rm": 1,
        "mountpoints": [None],
    }
    assert offline._validate_evidence_trees(
        Path("/dev/sdz1"), partition, Path("/dev/sdz"), parent
    ) == {"partition": "/dev/sdz1", "parent_disk": "/dev/sdz"}

    mounted_parent = dict(parent)
    mounted_parent["children"] = [
        {"path": "/dev/sdz2", "type": "part", "mountpoints": ["/mnt/other"]}
    ]
    with pytest.raises(offline.OfflineInventoryError, match="mounted descendant"):
        offline._validate_evidence_trees(
            Path("/dev/sdz1"), partition, Path("/dev/sdz"), mounted_parent
        )

    parent["tran"] = "nvme"
    with pytest.raises(offline.OfflineInventoryError, match="removable USB"):
        offline._validate_evidence_trees(
            Path("/dev/sdz1"), partition, Path("/dev/sdz"), parent
        )


def test_start_fence_is_create_only(tmp_path):
    offline._create_start_fence(tmp_path, REVISION)
    payload = json.loads((tmp_path / "start-attempt.json").read_text())
    assert payload["source_revision"] == REVISION
    assert payload["critical_user_data_contract_sha256"] == offline.EXPECTED_CRITICAL_SCOPE_SHA256
    with pytest.raises(offline.OfflineInventoryError, match="already attempted"):
        offline._create_start_fence(tmp_path, REVISION)


def test_plan_never_authorizes_production_effects():
    plan = offline._plan(
        expected_revision=REVISION,
        evidence={"partition": "/dev/sdz1", "parent_disk": "/dev/sdz"},
        source={
            "source_by_id": SOURCE,
            "disk": "/dev/nvme9n1",
            "root_partition": "/dev/nvme9n1p3",
            "root_partuuid": "cccccccc-cccc-4ccc-8ccc-ccccccccccc3",
        },
    )
    assert plan["production_effects_authorized"] is False
    assert "source-block-devices-set-read-only" in plan["effects"]
    assert "create-only-result-on-removable-evidence-volume" in plan["effects"]

def authority(revision: str = REVISION):
    return {
        "schema_version": 1,
        "kind": offline.AUTHORITY_KIND,
        "operation": "source-inventory",
        "live_source_revision": revision,
        "critical_user_data_contract_sha256": offline.EXPECTED_CRITICAL_SCOPE_SHA256,
        "allow_source_read_only_transition": True,
        "allow_inventory_result_write": True,
        "production_cutover_authorized": False,
    }


def test_offline_authority_is_exact_and_never_authorizes_cutover():
    value = authority()
    assert offline._validate_authority(value, REVISION) == value
    with pytest.raises(offline.OfflineInventoryError, match="authority is invalid"):
        offline._validate_authority(dict(value, production_cutover_authorized=True), REVISION)
    with pytest.raises(offline.OfflineInventoryError, match="authority is invalid"):
        offline._validate_authority(value, "b" * 40)


def test_private_identity_public_contract_digest_mismatch_fails_closed(tmp_path):
    value = private_identity()
    value["public_contract_sha256"] = "0" * 64
    identity = tmp_path / "private-storage-identity.json"
    identity.write_text(json.dumps(value) + "\n", encoding="utf-8")
    identity.chmod(0o600)
    with pytest.raises(offline.OfflineInventoryError, match="rejected"):
        offline.load_bound_contract(ROOT, identity, REVISION)


def test_source_partition_number_ambiguity_fails_closed(tmp_path):
    contract = bound_contract(tmp_path)
    tree = source_tree(contract)
    tree["children"][1]["partn"] = tree["children"][0]["partn"]
    with pytest.raises(offline.OfflineInventoryError, match="duplicated"):
        offline._validate_source_tree(contract, Path("/dev/nvme9n1"), tree)


def test_wrong_popos_root_role_fails_closed(tmp_path):
    contract = bound_contract(tmp_path)
    for item in contract["protected_disks"][0]["partition_table_fingerprint"]:
        if item.get("role") == "popos-root":
            item["role"] = "not-popos-root"
    with pytest.raises(offline.OfflineInventoryError, match="root partition is ambiguous"):
        offline._protected_root_partition(contract)


def target_tree(contract):
    target = contract["target_identity"]
    return {
        "path": "/dev/nvme8n1",
        "type": "disk",
        "size": target["exact_size_bytes"],
        "model": target["exact_model"],
        "serial": target["exact_serial"],
        "wwn": target["exact_wwn"],
        "tran": "nvme",
        "mountpoints": [None],
        "children": [],
    }


def test_nixos_target_must_match_private_identity_and_be_unmounted(tmp_path):
    contract = bound_contract(tmp_path)
    valid = target_tree(contract)
    assert offline._validate_target_tree(
        contract, Path("/dev/nvme8n1"), valid
    )["disk"] == "/dev/nvme8n1"

    wrong = target_tree(contract)
    wrong["serial"] = "WRONG"
    with pytest.raises(offline.OfflineInventoryError, match="target live disk identity"):
        offline._validate_target_tree(contract, Path("/dev/nvme8n1"), wrong)

    mounted = target_tree(contract)
    mounted["children"] = [{"mountpoints": ["/nixos"], "type": "part"}]
    with pytest.raises(offline.OfflineInventoryError, match="mounted descendant"):
        offline._validate_target_tree(contract, Path("/dev/nvme8n1"), mounted)

    nested_mounted = target_tree(contract)
    nested_mounted["children"] = [{
        "mountpoints": [None],
        "type": "part",
        "children": [{"mountpoints": ["/nixos"], "type": "crypt"}],
    }]
    with pytest.raises(offline.OfflineInventoryError, match="mounted descendant"):
        offline._validate_target_tree(
            contract, Path("/dev/nvme8n1"), nested_mounted
        )


@pytest.mark.parametrize("which", ["source", "target"])
def test_evidence_disk_must_differ_from_source_and_nixos_target(which):
    evidence = {"parent_disk": "/dev/sdz"}
    source = {"disk": "/dev/nvme9n1"}
    target = {"disk": "/dev/nvme8n1"}
    if which == "source":
        evidence["parent_disk"] = source["disk"]
    else:
        evidence["parent_disk"] = target["disk"]
    with pytest.raises(offline.OfflineInventoryError, match="aliases"):
        offline._validate_evidence_independence(evidence, source, target)


def test_source_and_target_cannot_resolve_to_same_disk():
    with pytest.raises(offline.OfflineInventoryError, match="resolves to the NixOS target"):
        offline._validate_evidence_independence(
            {"parent_disk": "/dev/sdz"},
            {"disk": "/dev/nvme9n1"},
            {"disk": "/dev/nvme9n1"},
        )


def test_setro_readback_failure_fails_and_never_uses_setrw(monkeypatch):
    calls = []

    class Result:
        def __init__(self, stdout=""):
            self.stdout = stdout

    def fake_run(argv, timeout=20):
        calls.append(list(argv))
        if argv[:2] == ["blockdev", "--getro"]:
            return Result("0\n")
        return Result("")

    monkeypatch.setattr(offline, "_run", fake_run)
    source = {
        "disk": "/dev/nvme9n1",
        "devices": ["/dev/nvme9n1p1", "/dev/nvme9n1p3", "/dev/nvme9n1"],
    }
    with pytest.raises(offline.OfflineInventoryError, match="read-only source state"):
        offline._set_source_readonly(source)
    flat = [token for call in calls for token in call]
    assert "--setrw" not in flat
    assert calls[0] == ["blockdev", "--setro", "/dev/nvme9n1"]


def _copy_payload(tmp_path: Path) -> Path:
    root = tmp_path / "payload"
    (root / "nixos/production").mkdir(parents=True)
    (root / "scripts").mkdir()
    for rel in [
        "nixos/production/critical-user-data-contract-v1.json",
        "nixos/production/critical-user-home-data-contract-v1.json",
        "scripts/nixos_critical_user_data_inventory.py",
        "scripts/nixos_critical_data_inventory.py",
    ]:
        source = ROOT / rel
        target = root / rel
        target.write_bytes(source.read_bytes())
    return root


def test_all_inventory_pins_match_authoritative_source():
    critical = ROOT / "nixos/production/critical-user-data-contract-v1.json"
    home = ROOT / "nixos/production/critical-user-home-data-contract-v1.json"
    root_scanner = ROOT / "scripts/nixos_critical_user_data_inventory.py"
    aggregate = ROOT / "scripts/nixos_critical_data_inventory.py"
    assert hashlib.sha256(critical.read_bytes()).hexdigest() == offline.EXPECTED_CRITICAL_SCOPE_SHA256
    assert hashlib.sha256(home.read_bytes()).hexdigest() == offline.EXPECTED_HOME_CONTRACT_SHA256
    assert hashlib.sha256(root_scanner.read_bytes()).hexdigest() == offline.EXPECTED_ROOT_SCANNER_SHA256
    assert hashlib.sha256(aggregate.read_bytes()).hexdigest() == offline.EXPECTED_AGGREGATE_SCANNER_SHA256


@pytest.mark.parametrize(
    ("relative", "message"),
    [
        ("nixos/production/critical-user-data-contract-v1.json", "critical-user-data contract digest mismatch"),
        ("nixos/production/critical-user-home-data-contract-v1.json", "home inventory contract digest mismatch"),
        ("scripts/nixos_critical_user_data_inventory.py", "root inventory implementation digest mismatch"),
        ("scripts/nixos_critical_data_inventory.py", "aggregate inventory implementation digest mismatch"),
    ],
)
def test_pinned_payload_digest_mismatch_fails_before_scanner_execution(
    tmp_path, relative, message
):
    payload = _copy_payload(tmp_path)
    path = payload / relative
    path.write_bytes(path.read_bytes() + b"\n# synthetic mismatch\n")
    with pytest.raises(offline.OfflineInventoryError, match=message):
        offline._verified_inventory(payload)


def test_failure_fence_is_create_only_and_disables_automatic_retry(tmp_path):
    offline._record_failure_fence(tmp_path, REVISION, "first failure")
    failure = tmp_path / offline.FAILURE_FILENAME
    first = json.loads(failure.read_text())
    assert first["automatic_retry_authorized"] is False
    assert first["production_effects_authorized"] is False
    offline._record_failure_fence(tmp_path, REVISION, "second failure")
    assert json.loads(failure.read_text()) == first


def test_scanner_failure_cannot_be_retried_in_same_boot(tmp_path, monkeypatch):
    state = tmp_path / "state"
    evidence_mount = tmp_path / "evidence"
    evidence_mount.mkdir()
    calls = {"observe_evidence": 0}

    def fake_observe_evidence():
        calls["observe_evidence"] += 1
        return {"partition": "/dev/sdz1", "parent_disk": "/dev/sdz"}

    def fake_mount_ro(device, mountpoint, fstype, options):
        Path(mountpoint).mkdir(parents=True, exist_ok=True)
        if Path(mountpoint).name == offline.SOURCE_MOUNT_NAME:
            (Path(mountpoint) / "home/alex").mkdir(parents=True, exist_ok=True)

    def fake_run(argv, timeout=20):
        class Result:
            stdout = ""
        return Result()

    monkeypatch.setattr(offline.os, "geteuid", lambda: 0)
    monkeypatch.setattr(offline, "observe_evidence", fake_observe_evidence)
    monkeypatch.setattr(offline, "_mount_ro", fake_mount_ro)
    monkeypatch.setattr(offline, "_umount", lambda _path: None)
    monkeypatch.setattr(offline, "_run", fake_run)
    monkeypatch.setattr(offline, "_read_json_regular", lambda *_a, **_k: authority())
    monkeypatch.setattr(offline, "load_bound_contract", lambda *_a, **_k: {"synthetic": True})
    monkeypatch.setattr(
        offline,
        "observe_source",
        lambda _c: {
            "disk": "/dev/nvme9n1",
            "devices": ["/dev/nvme9n1", "/dev/nvme9n1p3"],
            "source_by_id": SOURCE,
            "root_partition": "/dev/nvme9n1p3",
            "root_partuuid": "cccccccc-cccc-4ccc-8ccc-ccccccccccc3",
        },
    )
    monkeypatch.setattr(
        offline,
        "observe_target",
        lambda _c: {"disk": "/dev/nvme8n1", "target_by_id": TARGET},
    )
    monkeypatch.setattr(offline, "_validate_evidence_independence", lambda *_a: None)
    monkeypatch.setattr(offline, "_set_source_readonly", lambda _s: None)
    monkeypatch.setattr(
        offline,
        "_verified_inventory",
        lambda _root: (_ for _ in ()).throw(
            offline.OfflineInventoryError("synthetic scanner failure")
        ),
    )

    args = type(
        "Args",
        (),
        {
            "payload_root": ROOT,
            "state_dir": state,
            "evidence_mount": evidence_mount,
            "expected_source_revision": REVISION,
            "apply": True,
        },
    )()
    with pytest.raises(offline.OfflineInventoryError, match="synthetic scanner failure"):
        offline.run(args)
    assert calls["observe_evidence"] == 1
    with pytest.raises(offline.OfflineInventoryError, match="already attempted"):
        offline.run(args)
    assert calls["observe_evidence"] == 1


def test_success_output_has_correct_sha_and_is_create_only(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    mount_calls = []

    class Result:
        stdout = ""

    def fake_run(argv, timeout=20):
        mount_calls.append(list(argv))
        return Result()

    monkeypatch.setattr(offline, "_run", fake_run)
    result = {
        "schema_version": 1,
        "kind": "heim_pc.critical_user_data_aggregate_inventory.v1",
        "scope": "critical-user-data",
        "authoritative_inventory": True,
        "production_effects_authorized": False,
        "member_count": 1,
        "inventory_sha256": "a" * 64,
    }
    source = {
        "source_by_id": SOURCE,
        "root_partuuid": "cccccccc-cccc-4ccc-8ccc-ccccccccccc3",
    }
    receipt = offline._write_success(
        evidence, result, source_revision=REVISION, source=source
    )
    output = evidence / offline.RESULT_DIRNAME
    payload = (output / offline.RESULT_FILENAME).read_bytes()
    expected_sha = hashlib.sha256(payload).hexdigest()
    assert (output / offline.RESULT_SHA_FILENAME).read_text().strip() == expected_sha
    assert receipt["result_file_sha256"] == expected_sha
    assert receipt["aggregate_inventory_sha256"] == "a" * 64
    assert receipt["production_effects_authorized"] is False
    assert mount_calls[0][2].startswith("remount,rw")
    assert mount_calls[-1][2].startswith("remount,ro")
    with pytest.raises(offline.OfflineInventoryError, match="already exists"):
        offline._write_success(
            evidence, result, source_revision=REVISION, source=source
        )


def test_runner_contains_no_source_write_or_cutover_commands():
    source = MODULE.read_text()
    forbidden = [
        "--setrw",
        "mkfs",
        "wipefs",
        "sgdisk",
        "parted",
        "nixos-install",
        "switch-to-configuration",
        "bootctl install",
        "efibootmgr",
    ]
    for token in forbidden:
        assert token not in source
    assert 'options="ro,noload,nodev,nosuid,noexec"' in source
    assert '"remount,bind,ro,nodev,nosuid,noexec"' in source
