import hashlib
import io
import tarfile
import importlib.util
import json
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "nixos_production_install.py"
spec = importlib.util.spec_from_file_location("nixos_production_install", MODULE_PATH)
prod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(prod)

SEAGATE = "/dev/disk/by-id/nvme-SYNTHETIC_TARGET_0001"
WD = "/dev/disk/by-id/nvme-SYNTHETIC_FALLBACK_0002"
REVISION = "a" * 40
SYSTEM_PATH = "/nix/store/" + "0" * 32 + "-nixos-system-heim-pc-26.05-test"
NIX_VOLUME = "heim-pc-nixos-production-" + REVISION[:12]
CLOSURE_PATH_INFO = {
    SYSTEM_PATH: {"narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "narSize": 123, "references": []},
}
CLOSURE = prod.closure_manifest_metadata(CLOSURE_PATH_INFO)
ARTIFACT = {
    "schema_version": 1,
    "kind": "heim_pc.nixos_production_install_artifact",
    "source_revision": REVISION,
    "system_path": SYSTEM_PATH,
    "nix_volume": NIX_VOLUME,
    "nix_image": prod.PINNED_NIX_IMAGE,
    "profile": "heim-pc-storage-target",
    "source_authority": "proof-only",
    "source_bundle_sha256": "b" * 64,
    **CLOSURE,
}
MERGED_ARTIFACT = dict(ARTIFACT, source_authority="merged-main")
MANAGED_POLICY_SHA256 = "c" * 64
SYNTHETIC_ARTIFACT_PATH = Path("/tmp/heim-pc-synthetic-install-artifact.json")


def managed_receipt(artifact):
    return {
        "schema_version": 1,
        "kind": prod.MANAGED_BUILD_RECEIPT_KIND,
        "status": "success",
        "returncode": 0,
        "tool": "nix",
        "profile": "nixos-production-prepare",
        "managed_plan_sha256": "1" * 64,
        "managed_policy_sha256": MANAGED_POLICY_SHA256,
        "managed_receipt_sha256": "2" * 64,
        "artifact_file_sha256": "3" * 64,
        "artifact_json_sha256": prod.sha256_json(artifact),
        "source_revision": artifact["source_revision"],
        "docker_volume": artifact["nix_volume"],
        "store_root": "/home/alex/.cache/heim-pc/managed-builds/nix/" + "1" * 64 + "/nix-store",
        "system_closure": artifact["system_path"],
        "closure_manifest_sha256": artifact["closure_manifest_sha256"],
        "closure_path_count": artifact["closure_path_count"],
        "store_stop_threshold_bytes": 64 * 1024 * 1024 * 1024,
        "store_hard_limit_bytes": 90 * 1024 * 1024 * 1024,
        "store_max_observed_bytes": 1024,
        "store_budget_stop_triggered": False,
        "store_scan_error_detected": False,
        "runtime_timeout_triggered": False,
        "container_cleanup_verified": True,
        "lifecycle_fence_cleared": True,
    }


def managed_attestation_verification(artifact, receipt=None):
    selected_receipt = receipt or managed_receipt(artifact)
    semantic_identity = {field: artifact[field] for field in prod.INDEPENDENT_REBUILD_MATCH_FIELDS}
    return {
        "schema_version": 1,
        "kind": prod.MANAGED_BUILD_ATTESTATION_KIND,
        "artifact_sha256": selected_receipt["artifact_file_sha256"],
        "attestation_bundle_sha256": "6" * 64,
        "verifier_argv_sha256": "7" * 64,
        "predicate_sha256": "8" * 64,
        "independent_artifact_sha256": "9" * 64,
        "independent_receipt_sha256": "a" * 64,
        "independent_managed_receipt_sha256": "b" * 64,
        "managed_policy_sha256": MANAGED_POLICY_SHA256,
        "semantic_identity_sha256": prod.sha256_json(semantic_identity),
        "verified_attestation_count": 1,
    }


PARTUUIDS = [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
]
PUBLIC_CONTRACT = json.loads((ROOT / "nixos" / "production" / "contract-v1.json").read_text())
PRIVATE_IDENTITY = {
    "schema_version": 1,
    "kind": prod.storage_identity.PRIVATE_IDENTITY_KIND,
    "source_revision": REVISION,
    "public_contract_sha256": prod.storage_identity.sha256_json(PUBLIC_CONTRACT),
    "target_identity": {
        "exact_by_id": SEAGATE,
        "exact_serial": "SYNTH-TARGET-SERIAL",
        "exact_wwn": "eui.synthetic-target",
    },
    "protected_disks": [{
        "role": "popos-fallback",
        "by_id": WD,
        "serial": "SYNTH-FALLBACK-SERIAL",
        "wwn": "eui.synthetic-fallback",
        "verified_by_id_aliases": ["/dev/disk/by-id/nvme-SYNTHETIC_FALLBACK_ALIAS"],
        "partition_table_fingerprint": [
            {"number": 1, "partuuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", "uuid": "SYN1-0001"},
            {"number": 2, "partuuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2", "uuid": "SYN2-0002"},
            {"number": 3, "partuuid": "cccccccc-cccc-4ccc-8ccc-ccccccccccc3", "uuid": "SYNTH-ROOT-UUID"},
            {"number": 4, "partuuid": "dddddddd-dddd-4ddd-8ddd-ddddddddddd4", "uuid": "SYNTH-SWAP-UUID"},
        ],
    }],
    "topology": {
        "partitions": [
            {"number": number, "partuuid": partuuid}
            for number, partuuid in enumerate(PARTUUIDS, 1)
        ],
    },
}
CONTRACT = prod.storage_identity.bind_contract(
    PUBLIC_CONTRACT, PRIVATE_IDENTITY, expected_revision=REVISION
)


def observation():
    return {
        "target": {
            "requested_path": SEAGATE,
            "resolved_path": "/dev/nvme0n1",
            "model": "Seagate ZP4000GP304001",
            "serial": "SYNTH-TARGET-SERIAL",
            "wwn": "eui.synthetic-target",
            "size_bytes": 4000787030016,
            "transport": "nvme",
            "filesystem": None,
            "partition_table": None,
            "gpt_disk_guid": "",
            "logical_sector_size": 512,
            "mountpoints": [],
            "mounted": False,
            "signatures": [],
            "partitions": [],
        },
        "protected": {
            "requested_path": WD,
            "resolved_path": "/dev/nvme1n1",
            "model": "WD_BLACK SN850X 2000GB",
            "serial": "SYNTH-FALLBACK-SERIAL",
            "wwn": "eui.synthetic-fallback",
            "size_bytes": 2000398934016,
            "transport": "nvme",
            "filesystem": None,
            "partition_table": "gpt",
            "gpt_disk_guid": "99999999-9999-4999-8999-999999999999",
            "logical_sector_size": 512,
            "mountpoints": ["/boot/efi", "/recovery", "/"],
            "mounted": True,
            "signatures": [],
            "partitions": [
                {"number": 1, "path": "/dev/nvme1n1p1", "size_bytes": 1071644160, "start_sector": 2048, "end_sector": 2095102, "partuuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", "type_guid": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "partlabel": "ESP", "partflags": "0x0", "fstype": "vfat", "uuid": "SYN1-0001"},
                {"number": 2, "path": "/dev/nvme1n1p2", "size_bytes": 4294966784, "start_sector": 2095103, "end_sector": 10483709, "partuuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2", "type_guid": "0fc63daf-8483-4772-8e79-3d69d8477de4", "partlabel": "RECOVERY", "partflags": "0x0", "fstype": "vfat", "uuid": "SYN2-0002"},
                {"number": 3, "path": "/dev/nvme1n1p3", "size_bytes": 1990733157888, "start_sector": 10483710, "end_sector": 3898634408, "partuuid": "cccccccc-cccc-4ccc-8ccc-ccccccccccc3", "type_guid": "0fc63daf-8483-4772-8e79-3d69d8477de4", "partlabel": "POP_ROOT", "partflags": "0x0", "fstype": "ext4", "uuid": "SYNTH-ROOT-UUID"},
                {"number": 4, "path": "/dev/nvme1n1p4", "size_bytes": 4294966784, "start_sector": 3898634409, "end_sector": 3907023015, "partuuid": "dddddddd-dddd-4ddd-8ddd-ddddddddddd4", "type_guid": "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "partlabel": "SWAP", "partflags": "0x0", "fstype": "swap", "uuid": "SYNTH-SWAP-UUID"},
            ],
        },
        "root_source": "/dev/nvme1n1p3",
        "efi_source": "/dev/nvme1n1p1",
    }


def plan(obs=None, artifact=None, receipt=None):
    selected_artifact = artifact or ARTIFACT
    selected_receipt = receipt or managed_receipt(selected_artifact)
    verification = (
        managed_attestation_verification(selected_artifact, selected_receipt)
        if selected_artifact["source_authority"] == "merged-main" else None
    )
    return prod.compile_plan(
        obs or observation(),
        install_artifact=selected_artifact,
        install_artifact_path=SYNTHETIC_ARTIFACT_PATH,
        managed_build_receipt=selected_receipt,
        managed_policy_sha256=MANAGED_POLICY_SHA256,
        flake_source="/srv/exact-source",
        contract=CONTRACT,
        managed_build_attestation_verification=verification,
    )


def mock_trusted_build_gate(monkeypatch, compiled, events=None):
    log = events if events is not None else []
    docker_state = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_docker_quiesce_state",
        "service_active": True,
        "socket_active": True,
        "running_container_ids": ["1" * 64, "2" * 64, "3" * 64],
        "running_pid_count": 3,
    }
    image = compiled["sealed_nix_image"]
    seal = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_build_seal",
        "seal_root": str(Path(image).parent),
        "image": image,
        "loop_device": "/dev/loop99",
        "mountpoint": "/nix",
        "immutable_image": True,
        "closure_manifest_sha256": compiled["install_artifact"]["closure_manifest_sha256"],
    }
    archive = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_pinned_verifier_archive",
        "path": compiled["verifier_image_archive"],
        "archive_sha256": "9" * 64,
        "image_id": compiled["install_artifact"]["nix_image"],
        "image_tag": prod.PINNED_NIX_IMAGE_TAG,
        "layer_count": 1,
    }
    verification = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_root_only_seal_verification",
        "namespace": compiled["containerd_verifier_namespace"],
        "archive_sha256": archive["archive_sha256"],
        "image_id": compiled["install_artifact"]["nix_image"],
        "closure_manifest_sha256": compiled["install_artifact"]["closure_manifest_sha256"],
        "closure_path_count": compiled["install_artifact"]["closure_path_count"],
    }
    monkeypatch.setattr(prod, "verify_host_nix_root_absent", lambda: log.append("nix-root-absent"))
    monkeypatch.setattr(prod, "prepare_verifier_image_archive", lambda _plan, _artifact: log.append("archive-create") or archive)
    monkeypatch.setattr(prod, "validate_verifier_image_archive", lambda *args, **kwargs: log.append("archive-verify") or archive)
    monkeypatch.setattr(prod, "stop_docker_for_apply", lambda: log.append("docker-stop") or docker_state)
    monkeypatch.setattr(prod, "verify_docker_quiesced", lambda: log.append("docker-quiesced"))
    monkeypatch.setattr(prod, "create_sealed_nix_store", lambda _plan, _artifact: log.append("seal-create") or seal)
    monkeypatch.setattr(prod, "verify_sealed_nix_structure", lambda _artifact, _seal=None: log.append("seal-structure"))
    monkeypatch.setattr(prod, "verify_sealed_nix_with_containerd", lambda *_args: log.append("containerd-verify") or verification)
    monkeypatch.setattr(prod, "cleanup_verifier_image_archive", lambda _metadata: log.append("archive-cleanup"))
    monkeypatch.setattr(prod, "cleanup_sealed_nix_store", lambda _seal: log.append("seal-cleanup"))
    monkeypatch.setattr(prod, "restore_docker_after_apply", lambda _state: log.append("docker-restore"))
    return log


def test_contract_is_bound_to_physical_seagate_and_protected_wd():
    contract = CONTRACT
    target = contract["target_identity"]
    assert target["exact_by_id"] == SEAGATE
    assert target["exact_model"] == "Seagate ZP4000GP304001"
    assert target["exact_serial"] == "SYNTH-TARGET-SERIAL"
    assert target["exact_wwn"] == "eui.synthetic-target"
    assert target["exact_size_bytes"] == 4000787030016
    assert target["kernel_name_authoritative"] is False
    assert contract["protected_disks"][0]["by_id"] == WD
    assert len(contract["protected_disks"][0]["partition_table_fingerprint"]) == 4


def test_public_contract_contains_no_private_hardware_identifiers():
    prod.storage_identity.validate_public_contract(PUBLIC_CONTRACT)
    forbidden = prod.storage_identity.FORBIDDEN_PUBLIC_IDENTITY_KEYS

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                assert key not in forbidden
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(PUBLIC_CONTRACT)


def test_private_identity_file_is_mode_revision_and_public_digest_bound(tmp_path):
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(PRIVATE_IDENTITY))
    path.chmod(0o600)
    loaded = prod.load_contract(path, expected_revision=REVISION)
    assert loaded["target_identity"]["exact_by_id"] == SEAGATE
    assert loaded["identity_binding"]["source_revision"] == REVISION

    wrong_revision = dict(PRIVATE_IDENTITY, source_revision="b" * 40)
    path.write_text(json.dumps(wrong_revision))
    with pytest.raises(prod.ProductionInstallError, match="identity contract rejected"):
        prod.load_contract(path, expected_revision=REVISION)

    wrong_digest = dict(PRIVATE_IDENTITY, public_contract_sha256="0" * 64)
    path.write_text(json.dumps(wrong_digest))
    with pytest.raises(prod.ProductionInstallError, match="identity contract rejected"):
        prod.load_contract(path, expected_revision=REVISION)

    path.write_text(json.dumps(PRIVATE_IDENTITY))
    path.chmod(0o644)
    with pytest.raises(prod.ProductionInstallError, match="identity contract rejected"):
        prod.load_contract(path, expected_revision=REVISION)


def test_valid_preflight_binds_root_and_efi_to_protected_wd():
    result = prod.validate_preflight(observation(), CONTRACT)
    assert result["target"]["requested_path"] == SEAGATE
    assert result["protected"]["requested_path"] == WD
    assert result["protected"]["root_source"] == "/dev/nvme1n1p3"
    assert result["protected"]["efi_source"] == "/dev/nvme1n1p1"


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("model", "wrong-model"),
        ("serial", "wrong-serial"),
        ("wwn", "eui.wrong"),
        ("size_bytes", 4000787030015),
        ("transport", "sata"),
    ],
)
def test_target_identity_mismatch_is_rejected(field, wrong):
    obs = observation()
    obs["target"][field] = wrong
    with pytest.raises(prod.ProductionInstallError, match="target identity mismatch"):
        prod.validate_preflight(obs, CONTRACT)


def test_kernel_name_cannot_be_target_authority():
    obs = observation()
    obs["target"]["requested_path"] = "/dev/nvme0n1"
    with pytest.raises(prod.ProductionInstallError, match="exact contract by-id"):
        prod.validate_preflight(obs, CONTRACT)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda target: target.update(mounted=True, mountpoints=["/mnt/wrong"]),
        lambda target: target.update(partitions=[{"number": 1}]),
        lambda target: target.update(partition_table="gpt"),
        lambda target: target.update(filesystem="ext4"),
        lambda target: target.update(signatures=[{"type": "gpt"}]),
    ],
)
def test_nonblank_or_mounted_target_is_rejected(mutation):
    obs = observation()
    mutation(obs["target"])
    with pytest.raises(prod.ProductionInstallError):
        prod.validate_preflight(obs, CONTRACT)


def test_target_protected_alias_collision_is_rejected():
    obs = observation()
    obs["target"]["resolved_path"] = "/dev/nvme1n1"
    with pytest.raises(prod.ProductionInstallError, match="alias collision"):
        prod.validate_preflight(obs, CONTRACT)


@pytest.mark.parametrize(
    ("key", "wrong"),
    [("root_source", "/dev/nvme0n1p3"), ("efi_source", "/dev/nvme0n1p1")],
)
def test_root_and_efi_must_be_on_protected_wd(key, wrong):
    obs = observation()
    obs[key] = wrong
    with pytest.raises(prod.ProductionInstallError):
        prod.validate_preflight(obs, CONTRACT)


def test_protected_partition_fingerprint_mismatch_is_rejected():
    obs = observation()
    obs["protected"]["partitions"][2]["partuuid"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(prod.ProductionInstallError, match="fingerprint mismatch"):
        prod.validate_preflight(obs, CONTRACT)



def test_protected_filesystem_signature_mismatch_is_rejected():
    obs = observation()
    obs["protected"]["partitions"][0]["uuid"] = "DEAD-BEEF"
    with pytest.raises(prod.ProductionInstallError, match="fingerprint mismatch"):
        prod.validate_preflight(obs, CONTRACT)

def test_plan_has_exact_partition_guids_and_never_mutates_wd():
    compiled = plan()
    commands = compiled["commands"]
    partition_commands = [item for item in commands if any(str(arg).startswith("--partition-guid=") for arg in item["argv"])]
    assert len(partition_commands) == 3
    for expected, command in zip(PARTUUIDS, partition_commands):
        assert f"--partition-guid={partition_commands.index(command)+1}:{expected}" in command["argv"]
        assert command["argv"][-1] == SEAGATE
    mutating_argv = [arg for item in commands for arg in item["argv"]]
    assert WD not in mutating_argv
    assert "/dev/nvme0n1" not in mutating_argv
    assert "/dev/nvme1n1" not in mutating_argv
    assert "efibootmgr" not in mutating_argv


def test_filesystem_and_luks_commands_use_target_derived_partition_by_ids():
    compiled = plan()
    by_effect = {item["effect"]: item for item in compiled["commands"]}
    assert f"{SEAGATE}-part1" in by_effect["efi-filesystem"]["argv"]
    assert f"{SEAGATE}-part2" in by_effect["recovery-filesystem"]["argv"]
    crypt = f"{SEAGATE}-part3"
    assert crypt in by_effect["luks-format"]["argv"]
    assert crypt in by_effect["luks-open"]["argv"]
    assert f"/dev/disk/by-partuuid/{PARTUUIDS[0]}" not in by_effect["efi-filesystem"]["argv"]
    assert by_effect["luks-format"]["secret_binding"] == "luks-passphrase-v1"
    assert by_effect["luks-open"]["secret_binding"] == "luks-passphrase-v1"
    assert compiled["partition_binding_verification_required"] is True


def test_nixos_install_uses_exact_sealed_artifact_without_docker_in_apply():
    compiled = plan()
    install = next(item for item in compiled["commands"] if item["effect"] == "nixos-install")
    assert install["argv"] == [
        "/usr/bin/env",
        f"PATH={SYSTEM_PATH}/sw/bin:{prod.TRUSTED_PATH}",
        f"{SYSTEM_PATH}/sw/bin/nixos-install",
        "--root",
        "/mnt",
        "--system",
        SYSTEM_PATH,
        "--no-channel-copy",
        "--no-root-password",
    ]
    assert compiled["install_artifact"] == ARTIFACT
    assert compiled["source_revision"] == REVISION
    assert compiled["source_authority"] == "proof-only"
    assert compiled["host_nix_root"] == "/nix"
    assert compiled["trusted_build_seal_required"] is False
    assert compiled["docker_quiesce_required"] is False
    assert "docker" not in install["argv"]


def test_confirmation_is_bound_to_exact_plan_digest():
    compiled = plan()
    exact = prod.confirmation_for(compiled)
    assert exact == f"{prod.CONFIRM_PREFIX}{compiled['plan_sha256']}"
    prod.validate_confirmation(compiled, exact)
    with pytest.raises(prod.ProductionInstallError, match="exact plan digest"):
        prod.validate_confirmation(compiled, prod.CONFIRM_PREFIX + "0" * 64)


def test_execute_plan_rejects_wrong_confirmation_before_any_effect(monkeypatch, tmp_path):
    compiled = plan()
    touched = []
    monkeypatch.setattr(prod, "_run", lambda *args, **kwargs: touched.append(args) or (_ for _ in ()).throw(AssertionError("effect reached")))
    with pytest.raises(prod.ProductionInstallError, match="exact plan digest"):
        prod.execute_plan(compiled, contract=CONTRACT, confirmation="wrong", credential_hash_file=tmp_path / "unused")
    assert touched == []


def test_apply_promotion_authority_reads_canonical_github_main(monkeypatch):
    calls = []
    class Result:
        stdout = (REVISION + "\trefs/heads/main\n").encode()
        returncode = 0
        stderr = b""
    monkeypatch.setattr(prod, "_run", lambda argv, **kwargs: calls.append(argv) or Result())
    prod.verify_promoted_main_revision(REVISION)
    assert calls == [["git", "ls-remote", "--exit-code", prod.CANONICAL_MAIN_REMOTE, "refs/heads/main"]]


def test_apply_promotion_authority_rejects_non_main_revision(monkeypatch):
    class Result:
        stdout = (("b" * 40) + "\trefs/heads/main\n").encode()
        returncode = 0
        stderr = b""
    monkeypatch.setattr(prod, "_run", lambda argv, **kwargs: Result())
    with pytest.raises(prod.ProductionInstallError, match="current canonical GitHub main"):
        prod.verify_promoted_main_revision(REVISION)


def test_invalid_artifact_source_revision_is_rejected():
    artifact = dict(ARTIFACT, source_revision="main")
    with pytest.raises(prod.ProductionInstallError, match="40-hex"):
        plan(artifact=artifact)


def test_install_artifact_rejects_unpinned_image_volume_or_closure_metadata():
    with pytest.raises(prod.ProductionInstallError, match="pinned image"):
        prod.validate_install_artifact(dict(ARTIFACT, nix_image="sha256:" + "0" * 64))
    with pytest.raises(prod.ProductionInstallError, match="nix_volume"):
        prod.validate_install_artifact(dict(ARTIFACT, nix_volume="nix"))
    with pytest.raises(prod.ProductionInstallError, match="closure manifest"):
        prod.validate_install_artifact(dict(ARTIFACT, closure_manifest_sha256="wrong"))
    with pytest.raises(prod.ProductionInstallError, match="closure path count"):
        prod.validate_install_artifact(dict(ARTIFACT, closure_path_count=0))


def test_btrfs_tools_run_directly_from_exact_sealed_closure_without_docker():
    compiled = plan()
    by_effect = {}
    for item in compiled["commands"]:
        by_effect.setdefault(item["effect"], item)
    mkfs = by_effect["btrfs-filesystem"]["argv"]
    assert mkfs[:3] == [
        "/usr/bin/env",
        f"PATH={SYSTEM_PATH}/sw/bin:{prod.TRUSTED_PATH}",
        f"{SYSTEM_PATH}/sw/bin/mkfs.btrfs",
    ]
    assert mkfs[-1] == "/dev/mapper/heimpc-nixos-crypt"
    subvol = by_effect["btrfs-subvolume-create"]["argv"]
    assert subvol[:3] == [
        "/usr/bin/env",
        f"PATH={SYSTEM_PATH}/sw/bin:{prod.TRUSTED_PATH}",
        f"{SYSTEM_PATH}/sw/bin/btrfs",
    ]
    assert all("docker" not in item["argv"] for item in compiled["commands"])
    assert compiled["sealed_nix_image"].startswith("/var/lib/heim-pc/nixos-production-seals/")


def test_success_receipt_redacts_target_authority():
    compiled = plan(artifact=MERGED_ARTIFACT)
    post = compiled["preflight"]["protected"]
    receipt = prod._success_receipt(
        plan=compiled, artifact=MERGED_ARTIFACT, source_revision=REVISION, post=post,
        completed_effects=["synthetic"], nvram_before="a" * 64, nvram_after="a" * 64,
    )
    encoded = json.dumps(receipt, sort_keys=True)
    assert compiled["target_authority"] not in encoded
    assert "target_authority" not in receipt
    assert receipt["private_target_authority_redacted"] is True
    assert receipt["target_authority_sha256"] == hashlib.sha256(
        compiled["target_authority"].encode("utf-8")
    ).hexdigest()


def test_firstboot_staging_is_source_and_hash_bound_and_private(tmp_path):
    (tmp_path / "persist").mkdir(mode=0o755)
    password_hash = ("$y$j9T$" + "A" * 21 + "." + "$" + "B" * 43 + "\n").encode("ascii")
    receipt = prod.stage_firstboot_credentials(mount_root=str(tmp_path), source_revision=REVISION, hash_bytes=password_hash)
    secret = tmp_path / "persist" / "secrets" / "heim-pc" / "first-boot" / "alex-password-hash"
    authority = tmp_path / "persist" / "secrets" / "heim-pc" / "first-boot" / "alex-password-bootstrap-authority"
    assert secret.read_bytes() == password_hash
    assert secret.stat().st_mode & 0o777 == 0o600
    assert authority.stat().st_mode & 0o777 == 0o600
    digest = hashlib.sha256(password_hash).hexdigest()
    assert authority.read_text() == (
        "schema_version=1\n"
        "user=alex\n"
        "action=initialize-password\n"
        f"source_revision={REVISION}\n"
        f"password_hash_sha256={digest}\n"
    )
    assert receipt == {"schema_version": 1, "source_revision": REVISION, "password_hash_sha256": digest, "staged": True}
    assert all(marker not in json.dumps(receipt) for marker in ("secret_path", "authority_path", "alex-password-hash", "first-boot"))


def test_firstboot_staging_refuses_existing_secret(tmp_path):
    persist = tmp_path / "persist"
    secret_dir = persist / "secrets" / "heim-pc" / "first-boot"
    secret_dir.mkdir(parents=True)
    (secret_dir / "alex-password-hash").write_text("do-not-overwrite")
    password_hash = ("$y$j9T$" + "A" * 21 + "." + "$" + "B" * 43 + "\n").encode("ascii")
    with pytest.raises(prod.ProductionInstallError, match="refuses existing"):
        prod.stage_firstboot_credentials(mount_root=str(tmp_path), source_revision=REVISION, hash_bytes=password_hash)


def test_plan_summary_is_constant_and_never_echoes_plan_payload():
    summary = prod.plan_summary({"secret": "super-secret-material", "private": {"device": "hidden"}})
    assert summary == {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_plan_summary",
        "execution_authorized": False,
        "private_plan_redacted": True,
        "private_hardware_identity_redacted": True,
    }
    assert "super-secret-material" not in json.dumps(summary)
    assert "hidden" not in json.dumps(summary)


def test_plan_contains_no_secret_material():
    serialized = json.dumps(plan())
    assert "passphrase" not in serialized.lower() or "luks-passphrase-v1" in serialized
    assert "$y$j9T$" not in serialized


def test_main_never_surfaces_exception_text(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(prod, "load_install_artifact", lambda _path: ARTIFACT)
    monkeypatch.setattr(prod, "verify_source", lambda *args, **kwargs: REVISION)
    monkeypatch.setattr(prod, "managed_policy_sha256_for_source", lambda *_args: MANAGED_POLICY_SHA256)
    monkeypatch.setattr(
        prod, "load_managed_build_receipt",
        lambda *args, **kwargs: managed_receipt(ARTIFACT),
    )
    monkeypatch.setattr(
        prod, "load_contract",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            prod.ProductionInstallError("super-secret-material")
        ),
    )
    assert prod.main([
        "--install-artifact", str(tmp_path / "unused.json"),
        "--identity-contract", str(tmp_path / "private-identity.json"),
    ]) == 2
    captured = capsys.readouterr()
    assert captured.err == "nixos production install blocked by a safety check\n"
    assert "super-secret-material" not in captured.err


def test_main_distinguishes_post_mutation_alarm_without_exception_text(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(prod, "load_install_artifact", lambda _path: ARTIFACT)
    monkeypatch.setattr(prod, "managed_policy_sha256_for_source", lambda *_args: MANAGED_POLICY_SHA256)
    monkeypatch.setattr(
        prod, "load_managed_build_receipt",
        lambda *args, **kwargs: managed_receipt(ARTIFACT),
    )
    monkeypatch.setattr(prod, "load_contract", lambda *args, **kwargs: CONTRACT)
    monkeypatch.setattr(prod, "observe_live", lambda _contract: observation())
    monkeypatch.setattr(prod, "verify_source", lambda *args, **kwargs: REVISION)
    monkeypatch.setattr(prod, "verify_promoted_main_revision", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_no_hidden_target_signatures", lambda *_args: None)
    compiled = plan()
    monkeypatch.setattr(prod, "compile_plan", lambda *args, **kwargs: compiled)
    monkeypatch.setattr(
        prod,
        "execute_plan",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            prod.PostMutationInstallError("protected-fallback-changed")
        ),
    )
    assert prod.main([
        "--install-artifact", str(tmp_path / "unused.json"),
        "--identity-contract", str(tmp_path / "private-identity.json"),
        "--apply",
        "--credential-hash-file", str(tmp_path / "credential.hash"),
    ]) == 3
    captured = capsys.readouterr()
    assert captured.err == prod.POST_MUTATION_PUBLIC_MESSAGES["protected-fallback-changed"] + "\n"
    assert "super-secret-material" not in captured.err


def test_main_redacts_success_receipt_payload(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(prod, "load_install_artifact", lambda _path: ARTIFACT)
    monkeypatch.setattr(prod, "managed_policy_sha256_for_source", lambda *_args: MANAGED_POLICY_SHA256)
    monkeypatch.setattr(
        prod, "load_managed_build_receipt",
        lambda *args, **kwargs: managed_receipt(ARTIFACT),
    )
    monkeypatch.setattr(prod, "load_contract", lambda *args, **kwargs: CONTRACT)
    monkeypatch.setattr(prod, "observe_live", lambda _contract: observation())
    monkeypatch.setattr(prod, "verify_source", lambda *args, **kwargs: REVISION)
    monkeypatch.setattr(prod, "verify_promoted_main_revision", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_no_hidden_target_signatures", lambda *_args: None)
    compiled = plan()
    monkeypatch.setattr(prod, "compile_plan", lambda *args, **kwargs: compiled)
    monkeypatch.setattr(
        prod,
        "execute_plan",
        lambda *args, **kwargs: {"secret": "super-secret-material"},
    )
    assert prod.main([
        "--install-artifact", str(tmp_path / "unused.json"),
        "--identity-contract", str(tmp_path / "private-identity.json"),
        "--apply",
        "--credential-hash-file", str(tmp_path / "credential.hash"),
    ]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_completed",
        "private_receipt_redacted": True,
    }
    assert "super-secret-material" not in captured.out
    assert "super-secret-material" not in captured.err


def test_managed_build_receipt_rejects_noncanonical_store_root():
    receipt = managed_receipt(ARTIFACT)
    receipt["store_root"] = "/tmp/user-controlled-nix-store"
    with pytest.raises(prod.ProductionInstallError, match="does not authorize"):
        prod.validate_managed_build_receipt(
            receipt, ARTIFACT, expected_policy_sha256=MANAGED_POLICY_SHA256
        )


def test_production_plan_requires_root_seal_and_docker_quiesce_only_for_merged_main():
    proof = plan()
    production = plan(artifact=MERGED_ARTIFACT)
    assert proof["trusted_build_seal_required"] is False
    assert proof["docker_quiesce_required"] is False
    assert production["trusted_build_seal_required"] is True
    assert production["docker_quiesce_required"] is True
    assert production["host_nix_root"] == "/nix"
    assert production["sealed_nix_image"].startswith(
        "/var/lib/heim-pc/nixos-production-seals/" + REVISION + "-"
    )


def test_stop_docker_quiesces_service_socket_and_binds_running_containers(monkeypatch):
    states = {
        "docker.service": [True, False],
        "docker.socket": [True, False],
    }
    container_ids = ["a" * 64, "b" * 64]
    calls = []
    monkeypatch.setattr(prod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(prod, "_systemd_active", lambda unit: states[unit].pop(0))
    monkeypatch.setattr(prod, "_running_docker_container_ids", lambda: container_ids)
    monkeypatch.setattr(
        prod,
        "_running_docker_container_pids",
        lambda ids: [111, 222] if ids == container_ids else [],
    )
    monkeypatch.setattr(prod, "_process_exists", lambda _pid: False)
    monkeypatch.setattr(prod, "_moby_shim_pids", lambda: [])

    class Result:
        returncode = 0
        stdout = b""
        stderr = b""

    monkeypatch.setattr(prod, "_run", lambda argv, **kwargs: calls.append(argv) or Result())
    state = prod.stop_docker_for_apply()
    assert calls == [["systemctl", "stop", "docker.socket", "docker.service"]]
    assert state == {
        "schema_version": 1,
        "kind": "heim_pc.nixos_docker_quiesce_state",
        "service_active": True,
        "socket_active": True,
        "running_container_ids": container_ids,
        "running_pid_count": 2,
    }


def test_failed_docker_quiesce_restores_pre_apply_state(monkeypatch):
    activity = {
        "docker.service": iter([True, True, True]),
        "docker.socket": iter([True, True]),
    }
    calls = []
    monkeypatch.setattr(prod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(prod, "_systemd_active", lambda unit: next(activity[unit]))
    monkeypatch.setattr(prod, "_running_docker_container_ids", lambda: [])
    monkeypatch.setattr(prod, "_running_docker_container_pids", lambda _ids: [])
    monkeypatch.setattr(prod, "_moby_shim_pids", lambda: [])

    class Result:
        returncode = 0
        stdout = b""
        stderr = b""

    monkeypatch.setattr(prod, "_run", lambda argv, **kwargs: calls.append(argv) or Result())
    with pytest.raises(prod.ProductionInstallError, match="did not become inactive"):
        prod.stop_docker_for_apply()
    assert ["systemctl", "start", "docker.socket"] in calls
    assert ["systemctl", "start", "docker.service"] in calls


def test_restore_docker_restarts_missing_pre_apply_containers_and_verifies(monkeypatch):
    first = "a" * 64
    second = "b" * 64
    inventories = iter([[first], [first, second]])
    calls = []
    monkeypatch.setattr(prod, "_running_docker_container_ids", lambda: next(inventories))
    monkeypatch.setattr(prod, "_systemd_active", lambda _unit: True)

    class Result:
        returncode = 0
        stdout = b""
        stderr = b""

    monkeypatch.setattr(prod, "_run", lambda argv, **kwargs: calls.append(argv) or Result())
    prod.restore_docker_after_apply({
        "schema_version": 1,
        "kind": "heim_pc.nixos_docker_quiesce_state",
        "service_active": True,
        "socket_active": True,
        "running_container_ids": [first, second],
        "running_pid_count": 2,
    })
    assert ["docker", "start", second] in calls
    assert calls[:2] == [
        ["systemctl", "start", "docker.socket"],
        ["systemctl", "start", "docker.service"],
    ]


def test_restore_docker_fails_closed_when_pre_apply_container_stays_down(monkeypatch):
    first = "a" * 64
    second = "b" * 64
    inventories = iter([[first], [first]])
    calls = []
    monkeypatch.setattr(prod, "_running_docker_container_ids", lambda: next(inventories))
    monkeypatch.setattr(prod, "_systemd_active", lambda _unit: True)

    class Result:
        returncode = 0
        stdout = b""
        stderr = b""

    monkeypatch.setattr(prod, "_run", lambda argv, **kwargs: calls.append(argv) or Result())
    with pytest.raises(prod.ProductionInstallError, match="container state restore"):
        prod.restore_docker_after_apply({
            "schema_version": 1,
            "kind": "heim_pc.nixos_docker_quiesce_state",
            "service_active": True,
            "socket_active": True,
            "running_container_ids": [first, second],
            "running_pid_count": 2,
        })
    assert ["docker", "start", second] in calls


def test_docker_container_inventory_rejects_short_or_duplicate_ids():
    with pytest.raises(prod.ProductionInstallError, match="inventory is invalid"):
        prod._validate_docker_container_ids(["short"])
    with pytest.raises(prod.ProductionInstallError, match="inventory is invalid"):
        prod._validate_docker_container_ids(["a" * 64, "a" * 64])


def test_verify_docker_quiesced_rejects_surviving_moby_shim(monkeypatch):
    monkeypatch.setattr(prod, "_systemd_active", lambda _unit: False)
    monkeypatch.setattr(prod, "_moby_shim_pids", lambda: [2767])
    with pytest.raises(prod.ProductionInstallError, match="shim appeared"):
        prod.verify_docker_quiesced()


def test_sealed_tool_argv_uses_exact_attested_store_path_and_no_shell():
    argv = prod._sealed_tool_argv(
        MERGED_ARTIFACT, "nixos-install", ["--root", "/mnt", "--system", SYSTEM_PATH]
    )
    assert argv[:3] == [
        "/usr/bin/env",
        f"PATH={SYSTEM_PATH}/sw/bin:{prod.TRUSTED_PATH}",
        f"{SYSTEM_PATH}/sw/bin/nixos-install",
    ]
    assert "sh" not in argv
    assert "bash" not in argv
    assert "docker" not in argv


def test_seal_cleanup_keeps_image_immutable_if_unmount_is_uncertain(monkeypatch, tmp_path):
    base = tmp_path / "heim-pc" / "nixos-production-seals"
    root = base / (REVISION + "-" + "1" * 16)
    image = root / "nix.squashfs"
    root.mkdir(parents=True)
    image.write_bytes(b"seal")
    fake_nix = tmp_path / "nix"
    (fake_nix / "store").mkdir(parents=True)
    monkeypatch.setattr(prod, "SEALED_NIX_BASE", base)
    monkeypatch.setattr(prod, "HOST_NIX_ROOT", fake_nix)
    monkeypatch.setattr(prod, "_mountpoint_is_mounted", lambda _path: True)
    calls = []

    class Result:
        def __init__(self, returncode):
            self.returncode = returncode
            self.stdout = b""
            self.stderr = b""

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["/usr/bin/umount", str(fake_nix)]:
            return Result(1)
        return Result(0)

    monkeypatch.setattr(prod, "_run", fake_run)
    seal = {
        "seal_root": str(root),
        "image": str(image),
        "loop_device": "/dev/loop7",
    }
    with pytest.raises(prod.ProductionInstallError, match="teardown"):
        prod.cleanup_sealed_nix_store(seal)
    assert ["/usr/bin/chattr", "-i", str(image)] not in calls
    assert image.exists()


def _write_synthetic_verifier_archive(path, *, config_bytes, config_name, repo_tag=None):
    layer_digest = hashlib.sha256(b"synthetic-layer").hexdigest()
    layer_name = f"blobs/sha256/{layer_digest}"
    manifest = [{
        "Config": config_name,
        "RepoTags": [repo_tag or prod.PINNED_NIX_IMAGE_TAG],
        "Layers": [layer_name],
    }]
    entries = {
        "manifest.json": json.dumps(manifest, separators=(",", ":")).encode(),
        config_name: config_bytes,
        layer_name: b"synthetic-layer",
    }
    with tarfile.open(path, "w") as tar:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o400
            tar.addfile(info, io.BytesIO(payload))
    path.chmod(0o400)


def _pretend_root_owned_archive(monkeypatch, path):
    real_lstat = prod.Path.lstat
    def fake_lstat(self):
        if self == path:
            return type("Stat", (), {
                "st_mode": stat.S_IFREG | 0o400,
                "st_uid": 0,
                "st_gid": 0,
                "st_nlink": 1,
            })()
        return real_lstat(self)
    monkeypatch.setattr(prod.Path, "lstat", fake_lstat)


def test_verifier_archive_config_digest_is_exact_pinned_image_authority(monkeypatch, tmp_path):
    config = {
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(b"synthetic-layer").hexdigest()]},
        "config": {"User": "0:0"},
    }
    config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(config_bytes).hexdigest()
    pinned = "sha256:" + digest
    artifact = dict(ARTIFACT, nix_image=pinned)
    monkeypatch.setattr(prod, "PINNED_NIX_IMAGE", pinned)
    archive = tmp_path / "verifier.tar"
    _write_synthetic_verifier_archive(
        archive, config_bytes=config_bytes, config_name=f"blobs/sha256/{digest}"
    )
    _pretend_root_owned_archive(monkeypatch, archive)
    result = prod.validate_verifier_image_archive(archive, artifact)
    assert result["image_id"] == pinned
    assert result["layer_count"] == 1


def test_verifier_archive_rejects_config_bytes_not_matching_pinned_image(monkeypatch, tmp_path):
    authorized_config = json.dumps({
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(b"synthetic-layer").hexdigest()]},
    }, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(authorized_config).hexdigest()
    pinned = "sha256:" + digest
    artifact = dict(ARTIFACT, nix_image=pinned)
    monkeypatch.setattr(prod, "PINNED_NIX_IMAGE", pinned)
    archive = tmp_path / "verifier.tar"
    tampered = json.dumps({
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(b"synthetic-layer").hexdigest()]},
        "config": {"Env": ["TAMPERED=1"]},
    }, sort_keys=True, separators=(",", ":")).encode()
    _write_synthetic_verifier_archive(
        archive, config_bytes=tampered, config_name=f"blobs/sha256/{digest}"
    )
    _pretend_root_owned_archive(monkeypatch, archive)
    with pytest.raises(prod.ProductionInstallError, match="config digest mismatch"):
        prod.validate_verifier_image_archive(archive, artifact)


def test_root_only_containerd_verifier_argv_is_readonly_and_plan_bounded():
    compiled = plan(artifact=MERGED_ARTIFACT)
    namespace = compiled["containerd_verifier_namespace"]
    assert namespace == "heim-pc-nixos-verify-" + compiled["managed_build_receipt"]["artifact_file_sha256"][:16]
    argv = prod._containerd_nix_run_argv(
        namespace,
        namespace + "-info",
        ["path-info", "--json", "--recursive", SYSTEM_PATH],
    )
    assert argv[:4] == [
        "/usr/bin/ctr", "--address", "/run/containerd/containerd.sock", "--namespace"
    ]
    assert "--read-only" in argv
    assert "type=bind,src=/nix,dst=/subject/nix,options=rbind:ro" in argv
    assert "type=tmpfs,dst=/tmp,options=nosuid:nodev:mode=1777" in argv
    assert "docker.io/nixos/nix:2.35.2" in argv
    assert "/nix/var/nix/profiles/default/bin/nix" in argv
    assert prod.READONLY_NIX_STORE in argv
    assert "--net-host" not in argv
    assert "--cni" not in argv


def test_structural_seal_verifier_never_executes_nix(monkeypatch, tmp_path):
    fake_nix = tmp_path / "nix"
    (fake_nix / "store").mkdir(parents=True)
    (fake_nix / "var").mkdir()
    root = tmp_path / "resolved-root"
    root.mkdir()
    executable = tmp_path / "executable"
    executable.write_text("x")
    executable.chmod(0o755)
    service = tmp_path / "service"
    service.write_text("x")
    monkeypatch.setattr(prod, "HOST_NIX_ROOT", fake_nix)
    monkeypatch.setattr(
        prod,
        "_sealed_mount_record",
        lambda _path: {"target": str(fake_nix), "source": "/dev/loop7", "fstype": "squashfs", "options": "ro"},
    )
    def resolve(path):
        value = str(path)
        if value.endswith("heim-pc-firstboot-credentials.service"):
            return service
        if "/sw/bin/" in value:
            return executable
        return root
    monkeypatch.setattr(prod, "_resolve_inside_sealed_store", resolve)
    monkeypatch.setattr(prod, "_verify_immutable_image", lambda _path: None)
    monkeypatch.setattr(
        prod,
        "_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("structural verifier must not execute commands")),
    )
    seal_root = prod.SEALED_NIX_BASE / (REVISION + "-" + "1" * 16)
    seal = {
        "kind": "heim_pc.nixos_production_build_seal",
        "seal_root": str(seal_root),
        "image": str(seal_root / "nix.squashfs"),
        "loop_device": "/dev/loop7",
        "mountpoint": str(fake_nix),
        "closure_manifest_sha256": ARTIFACT["closure_manifest_sha256"],
    }
    prod.verify_sealed_nix_structure(ARTIFACT, seal)


def test_plan_binds_root_only_verifier_archive_and_namespace():
    compiled = plan(artifact=MERGED_ARTIFACT)
    digest = compiled["managed_build_receipt"]["artifact_file_sha256"]
    assert compiled["verifier_image_archive"] == (
        f"/var/lib/heim-pc/nixos-production-verifiers/{REVISION}-{digest[:16]}.docker.tar"
    )
    assert compiled["containerd_verifier_namespace"] == f"heim-pc-nixos-verify-{digest[:16]}"


def test_post_mutation_alarm_codes_are_closed_and_non_secret():
    with pytest.raises(ValueError, match="unknown post-mutation alarm code"):
        prod.PostMutationInstallError("super-secret-material")
    assert all("secret" not in message.lower() for message in prod.POST_MUTATION_PUBLIC_MESSAGES.values())


def test_failed_first_destructive_command_becomes_post_mutation_alarm(monkeypatch, tmp_path):
    compiled = plan(artifact=MERGED_ARTIFACT)
    monkeypatch.setattr(prod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(prod, "verify_source", lambda *args, **kwargs: REVISION)
    monkeypatch.setattr(prod, "verify_managed_build_binding", lambda *args, **kwargs: compiled["managed_build_receipt"])
    monkeypatch.setattr(prod, "verify_promoted_main_revision", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_install_artifact_environment", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_scratch_state", lambda *_args: None)
    monkeypatch.setattr(prod, "validate_preflight", lambda *_args: compiled["preflight"])
    monkeypatch.setattr(prod, "verify_no_hidden_target_signatures", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_partuuid_namespace_clear", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_partlabel_namespace_clear", lambda *_args: None)
    monkeypatch.setattr(prod, "read_credential_hash", lambda *_args: b"hash\n")
    monkeypatch.setattr(prod.getpass, "getpass", lambda *args, **kwargs: "passphrase")
    monkeypatch.setattr(prod, "efi_nvram_digest", lambda: "a" * 64)
    monkeypatch.setattr(prod, "validate_protected_state", lambda *_args: compiled["preflight"]["protected"])
    monkeypatch.setattr(prod, "_mountpoint_is_mounted", lambda _path: False)
    gate_events = mock_trusted_build_gate(monkeypatch, compiled)

    first_argv = compiled["commands"][0]["argv"]

    class Result:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(argv, *, input_bytes=None, check=True):
        if argv == first_argv:
            raise prod.ProductionInstallError("private command detail")
        return Result()

    monkeypatch.setattr(prod, "_run", fake_run)
    with pytest.raises(prod.PostMutationInstallError) as exc:
        prod.execute_plan(
            compiled,
            contract=CONTRACT,
            confirmation=prod.confirmation_for(compiled),
            credential_hash_file=tmp_path / "credential.hash",
            observer=lambda _contract: observation(),
        )
    assert exc.value.code == "apply-failed-after-mutation-attempt"
    assert "private command detail" not in prod.POST_MUTATION_PUBLIC_MESSAGES[exc.value.code]
    assert gate_events[:9] == [
        "nix-root-absent",
        "archive-create",
        "docker-stop",
        "docker-quiesced",
        "archive-verify",
        "seal-create",
        "docker-quiesced",
        "seal-structure",
        "containerd-verify",
    ]
    assert gate_events[-2:] == ["seal-cleanup", "docker-restore"]


def test_run_uses_fixed_trusted_environment(monkeypatch):
    captured = {}

    class Result:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return Result()

    monkeypatch.setattr(prod.subprocess, "run", fake_run)
    prod._run(["cryptsetup", "--version"])
    assert captured["env"]["PATH"] == prod.TRUSTED_PATH
    assert captured["env"]["HOME"] == "/"
    assert set(captured["env"]) == {"PATH", "LC_ALL", "LANG", "HOME", "SYSTEMD_COLORS"}


def test_run_with_sensitive_stdin_never_surfaces_command_stderr(monkeypatch):
    class Result:
        returncode = 1
        stdout = b""
        stderr = b"the-secret-must-never-be-logged"

    monkeypatch.setattr(prod.subprocess, "run", lambda *args, **kwargs: Result())
    with pytest.raises(prod.ProductionInstallError, match="sensitive stdin; stderr withheld") as exc:
        prod._run(["cryptsetup", "luksFormat"], input_bytes=b"the-secret-must-never-be-logged")
    assert "the-secret-must-never-be-logged" not in str(exc.value)


def test_plan_teardown_always_attempts_stage_mount_cleanup():
    compiled = plan()
    assert compiled["teardown_commands"][0] == {
        "effect": "unmount-stage",
        "argv": ["umount", prod.BTRFS_STAGE_ROOT],
    }


def test_persist_mount_must_be_encrypted_btrfs_subvolume(monkeypatch):
    class Result:
        stdout = b"/dev/mapper/heimpc-nixos-crypt btrfs /@persist\n"

    calls = []
    monkeypatch.setattr(prod, "_run", lambda argv: calls.append(argv) or Result())
    prod.verify_persist_mount(prod.MOUNT_ROOT, "/dev/mapper/heimpc-nixos-crypt")
    assert calls[0][-1] == f"{prod.MOUNT_ROOT}/persist"


def test_persist_mount_rejects_wrong_source_or_subvolume(monkeypatch):
    class Result:
        stdout = b"/dev/nvme1n1p3 ext4 /\n"

    monkeypatch.setattr(prod, "_run", lambda argv: Result())
    with pytest.raises(prod.ProductionInstallError, match="encrypted @persist"):
        prod.verify_persist_mount(prod.MOUNT_ROOT, "/dev/mapper/heimpc-nixos-crypt")


def test_hidden_signature_check_accepts_empty_wipefs_result(monkeypatch):
    class Result:
        stdout = b'{"signatures": []}'

    calls = []
    monkeypatch.setattr(prod, "_run", lambda argv: calls.append(argv) or Result())
    prod.verify_no_hidden_target_signatures(SEAGATE)
    assert calls == [["wipefs", "--no-act", "--json", SEAGATE]]


def test_hidden_signature_check_rejects_any_signature(monkeypatch):
    class Result:
        stdout = b'{"signatures": [{"type": "gpt"}]}'

    monkeypatch.setattr(prod, "_run", lambda argv: Result())
    with pytest.raises(prod.ProductionInstallError, match="wipefs found signatures"):
        prod.verify_no_hidden_target_signatures(SEAGATE)


def test_closure_manifest_metadata_is_canonical_and_reference_order_independent():
    dependency = "/nix/store/" + "1" * 32 + "-dependency"
    payload_a = {
        SYSTEM_PATH: {"narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "narSize": 123, "references": [dependency]},
        dependency: {"narHash": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", "narSize": 45, "references": []},
    }
    payload_b = {dependency: payload_a[dependency], SYSTEM_PATH: payload_a[SYSTEM_PATH]}
    assert prod.closure_manifest_metadata(payload_a) == prod.closure_manifest_metadata(payload_b)
    assert prod.closure_manifest_metadata(payload_a)["closure_path_count"] == 2


def test_partuuid_namespace_must_be_clear_before_partitioning(monkeypatch):
    blocked = f"/dev/disk/by-partuuid/{PARTUUIDS[1]}"
    monkeypatch.setattr(prod.os.path, "lexists", lambda path: path == blocked)
    with pytest.raises(prod.ProductionInstallError, match="already exists before partitioning"):
        prod.verify_partuuid_namespace_clear(CONTRACT)


def test_partlabel_namespace_must_be_clear_before_partitioning(monkeypatch):
    blocked = f"/dev/disk/by-partlabel/{PUBLIC_CONTRACT['topology']['partitions'][1]['label']}"
    monkeypatch.setattr(prod.os.path, "lexists", lambda path: path == blocked)
    with pytest.raises(prod.ProductionInstallError, match="PARTLABEL already exists before partitioning"):
        prod.verify_partlabel_namespace_clear(CONTRACT)


def _post_partition_target():
    target = observation()["target"]
    target["partition_table"] = "gpt"
    target["partitions"] = [
        {
            "number": number,
            "path": f"/dev/nvme0n1p{number}",
            "partuuid": partuuid,
            "partlabel": PUBLIC_CONTRACT["topology"]["partitions"][number - 1]["label"],
        }
        for number, partuuid in enumerate(PARTUUIDS, 1)
    ]
    return target


def test_target_partition_bindings_reject_partuuid_alias_outside_seagate(monkeypatch):
    target = _post_partition_target()
    aliases = {}
    for number, partuuid in enumerate(PARTUUIDS, 1):
        resolved = f"/dev/nvme0n1p{number}"
        aliases[f"{SEAGATE}-part{number}"] = resolved
        aliases[f"/dev/disk/by-partuuid/{partuuid}"] = resolved
        aliases[f"/dev/disk/by-partlabel/{PUBLIC_CONTRACT['topology']['partitions'][number - 1]['label']}"] = resolved
    monkeypatch.setattr(prod, "_disk_observation", lambda authority: target)
    monkeypatch.setattr(prod.os.path, "islink", lambda path: path in aliases)
    monkeypatch.setattr(prod.os.path, "realpath", lambda path: aliases.get(path, path))
    prod.verify_target_partition_bindings(CONTRACT)
    aliases[f"/dev/disk/by-partuuid/{PARTUUIDS[0]}"] = "/dev/nvme9n1p1"
    with pytest.raises(prod.ProductionInstallError, match="PARTUUID alias points outside"):
        prod.verify_target_partition_bindings(CONTRACT)


def test_target_partition_bindings_reject_partlabel_alias_outside_seagate(monkeypatch):
    target = _post_partition_target()
    aliases = {}
    for number, partuuid in enumerate(PARTUUIDS, 1):
        resolved = f"/dev/nvme0n1p{number}"
        label = PUBLIC_CONTRACT["topology"]["partitions"][number - 1]["label"]
        aliases[f"{SEAGATE}-part{number}"] = resolved
        aliases[f"/dev/disk/by-partuuid/{partuuid}"] = resolved
        aliases[f"/dev/disk/by-partlabel/{label}"] = resolved
    monkeypatch.setattr(prod, "_disk_observation", lambda authority: target)
    monkeypatch.setattr(prod.os.path, "islink", lambda path: path in aliases)
    monkeypatch.setattr(prod.os.path, "realpath", lambda path: aliases.get(path, path))
    prod.verify_target_partition_bindings(CONTRACT)
    first_label = PUBLIC_CONTRACT["topology"]["partitions"][0]["label"]
    aliases[f"/dev/disk/by-partlabel/{first_label}"] = "/dev/nvme9n1p1"
    with pytest.raises(prod.ProductionInstallError, match="PARTLABEL alias points outside"):
        prod.verify_target_partition_bindings(CONTRACT)


def test_readonly_nix_verifier_uses_pinned_image_binary_and_separate_subject_store():
    argv = prod._nix_volume_argv(ARTIFACT, ["store", "verify", "--no-trust", SYSTEM_PATH])
    assert f"{NIX_VOLUME}:/subject/nix:ro" in argv
    assert "-v" in argv
    assert f"{NIX_VOLUME}:/nix" not in argv
    assert argv[argv.index("--entrypoint") + 1] == "/nix/var/nix/profiles/default/bin/nix"
    assert argv[argv.index("--store") + 1] == prod.READONLY_NIX_STORE
    assert prod.READONLY_NIX_FEATURES in argv


def test_install_artifact_environment_recomputes_and_verifies_closure(monkeypatch):
    calls = []

    class Result:
        def __init__(self, stdout=b""):
            self.stdout = stdout
            self.returncode = 0
            self.stderr = b""

    def fake_run(argv, *, input_bytes=None, check=True):
        calls.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return Result(json.dumps([{
                "Id": prod.PINNED_NIX_IMAGE,
                "RepoTags": [prod.PINNED_NIX_IMAGE_TAG],
                "RepoDigests": [prod.PINNED_NIX_IMAGE_REF],
            }]).encode())
        if "path-info" in argv:
            return Result(json.dumps(CLOSURE_PATH_INFO).encode())
        return Result()

    monkeypatch.setattr(prod, "_run", fake_run)
    prod.verify_install_artifact_environment(ARTIFACT)
    verifier = next(argv for argv in calls if "store" in argv and "verify" in argv and "--no-trust" in argv)
    assert f"{NIX_VOLUME}:/subject/nix:ro" in verifier
    assert verifier[verifier.index("--store") + 1] == prod.READONLY_NIX_STORE
    with pytest.raises(prod.ProductionInstallError, match="closure metadata"):
        prod.verify_install_artifact_environment(dict(ARTIFACT, closure_manifest_sha256="0" * 64))


def test_attestation_verify_argv_pins_exact_artifact_repository_workflow_source_and_runner(tmp_path):
    artifact_path = (tmp_path / "artifact.json").resolve()
    bundle_path = (tmp_path / "artifact.managed-build-attestation.json").resolve()
    argv = prod.managed_build_attestation_verify_argv(artifact_path, bundle_path, REVISION)
    assert argv == [
        "/usr/bin/gh", "attestation", "verify", str(artifact_path),
        "--repo", "heimgewebe/heim-pc",
        "--bundle", str(bundle_path),
        "--signer-workflow", "heimgewebe/heim-pc/.github/workflows/nixos-production-build-attest.yml",
        "--signer-digest", REVISION,
        "--source-digest", REVISION,
        "--source-ref", "refs/heads/main",
        "--predicate-type", "https://heimgewebe.local/attestations/nixos-independent-managed-build/v1",
        "--deny-self-hosted-runners",
        "--format", "json",
    ]


def test_attestation_verifier_requires_nonempty_verified_json(tmp_path):
    artifact = (tmp_path / "artifact.json").resolve()
    bundle = (tmp_path / "bundle.json").resolve()
    artifact.write_text("{}\n", encoding="utf-8")
    bundle.write_text("{}\n", encoding="utf-8")

    class Result:
        def __init__(self, stdout):
            self.stdout = stdout

    artifact_value = dict(MERGED_ARTIFACT)
    artifact.write_text(json.dumps(artifact_value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    semantic_identity = {field: artifact_value[field] for field in prod.INDEPENDENT_REBUILD_MATCH_FIELDS}
    predicate = {
        "schema_version": 1,
        "kind": prod.MANAGED_BUILD_ATTESTATION_PREDICATE_KIND,
        "candidate_artifact_sha256": artifact_sha,
        "independent_artifact_sha256": "9" * 64,
        "independent_receipt_sha256": "a" * 64,
        "independent_managed_receipt_sha256": "b" * 64,
        "managed_policy_sha256": MANAGED_POLICY_SHA256,
        "semantic_identity_sha256": prod.sha256_json(semantic_identity),
        "excluded_nonsemantic_fields": ["source_bundle_sha256"],
    }
    output = json.dumps([{
        "verificationResult": {"statement": {"predicate": predicate}}
    }]).encode()
    summary = prod.verify_managed_build_attestation(
        artifact, bundle, REVISION, expected_policy_sha256=MANAGED_POLICY_SHA256,
        runner=lambda _argv: Result(output),
    )
    assert summary["verified_attestation_count"] == 1
    assert summary["artifact_sha256"] == artifact_sha
    assert summary["attestation_bundle_sha256"] == hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert summary["independent_managed_receipt_sha256"] == "b" * 64
    assert summary["managed_policy_sha256"] == MANAGED_POLICY_SHA256
    with pytest.raises(prod.ProductionInstallError, match="no unique verified attestation"):
        prod.verify_managed_build_attestation(
            artifact, bundle, REVISION, expected_policy_sha256=MANAGED_POLICY_SHA256,
            runner=lambda _argv: Result(b"[]"),
        )
    with pytest.raises(prod.ProductionInstallError, match="invalid JSON"):
        prod.verify_managed_build_attestation(
            artifact, bundle, REVISION, expected_policy_sha256=MANAGED_POLICY_SHA256,
            runner=lambda _argv: Result(b"not-json"),
        )
    forged = dict(predicate, managed_policy_sha256="f" * 64)
    forged_output = json.dumps([{
        "verificationResult": {"statement": {"predicate": forged}}
    }]).encode()
    with pytest.raises(prod.ProductionInstallError, match="does not bind current artifact"):
        prod.verify_managed_build_attestation(
            artifact, bundle, REVISION, expected_policy_sha256=MANAGED_POLICY_SHA256,
            runner=lambda _argv: Result(forged_output),
        )


def test_independent_rebuild_validates_remote_managed_success_and_semantic_identity(monkeypatch, tmp_path):
    candidate_path = (tmp_path / "candidate.json").resolve()
    independent_path = (tmp_path / "independent.json").resolve()
    candidate = dict(MERGED_ARTIFACT)
    independent = dict(MERGED_ARTIFACT)
    independent["source_bundle_sha256"] = "9" * 64
    candidate_path.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    independent_path.write_text(json.dumps(independent, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt = managed_receipt(independent)
    receipt["artifact_file_sha256"] = hashlib.sha256(independent_path.read_bytes()).hexdigest()
    receipt_path = prod.managed_build_receipt_path(independent_path)
    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    receipt_path.chmod(0o600)
    monkeypatch.setattr(prod, "managed_policy_sha256_for_source", lambda _source: MANAGED_POLICY_SHA256)

    result = prod.verify_independent_rebuild_candidate(
        candidate_path, independent_path, flake_source="/synthetic/source"
    )
    assert result["candidate_artifact_sha256"] == hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    assert result["independent_receipt_sha256"] == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    assert result["excluded_nonsemantic_fields"] == ["source_bundle_sha256"]

    changed = dict(independent)
    changed["closure_manifest_sha256"] = "8" * 64
    independent_path.write_text(json.dumps(changed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(prod.ProductionInstallError, match="closure_manifest_sha256"):
        prod.verify_independent_rebuild_candidate(
            candidate_path, independent_path, flake_source="/synthetic/source"
        )


def test_merged_main_plan_requires_independent_attestation():
    receipt = managed_receipt(MERGED_ARTIFACT)
    with pytest.raises(prod.ProductionInstallError, match="requires independent managed-build attestation"):
        prod.compile_plan(
            observation(), install_artifact=MERGED_ARTIFACT,
            install_artifact_path=SYNTHETIC_ARTIFACT_PATH,
            managed_build_receipt=receipt,
            managed_policy_sha256=MANAGED_POLICY_SHA256,
            flake_source="/srv/exact-source", contract=CONTRACT,
        )
    compiled = plan(artifact=MERGED_ARTIFACT, receipt=receipt)
    assert compiled["managed_build_attestation_required"] is True
    assert compiled["managed_build_attestation_verification"]["artifact_sha256"] == receipt["artifact_file_sha256"]


def test_proof_only_plan_does_not_claim_production_attestation():
    compiled = plan()
    assert compiled["managed_build_attestation_required"] is False
    assert compiled["managed_build_attestation_verification"] is None
    assert compiled["managed_build_attestation_sha256"] is None


def test_production_attestation_workflow_independently_rebuilds_local_candidate():
    workflow = (ROOT / ".github" / "workflows" / "nixos-production-build-attest.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "artifact_b64:" in workflow
    assert "pull_request:" not in workflow
    assert "runs-on: ubuntu-latest" in workflow
    assert "id-token: write" in workflow
    assert "attestations: write" in workflow
    assert "artifact-metadata: write" not in workflow
    assert "python3 scripts/nixos_production_prepare.py" in workflow
    assert "--source-authority merged-main" in workflow
    assert "verify_independent_rebuild_candidate" in workflow
    assert "subject-path: ${{ runner.temp }}/candidate-install-artifact.json" in workflow
    assert "predicate-type: https://heimgewebe.local/attestations/nixos-independent-managed-build/v1" in workflow
    assert "predicate-path: ${{ runner.temp }}/independent-managed-rebuild-predicate.json" in workflow
    assert "nixos/nix@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c" in workflow
    assert "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d" in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "self-hosted" not in workflow
    assert "remote-install-artifact.json" in workflow


def test_managed_build_receipt_is_plan_bound_and_rejects_failed_evidence():
    receipt = managed_receipt(ARTIFACT)
    compiled = plan(receipt=receipt)
    assert compiled["managed_build_receipt_sha256"] == prod.sha256_json(receipt)
    assert compiled["managed_policy_sha256"] == MANAGED_POLICY_SHA256
    for field, value in (
        ("artifact_json_sha256", "f" * 64),
        ("managed_policy_sha256", "e" * 64),
        ("store_budget_stop_triggered", True),
        ("store_scan_error_detected", True),
        ("runtime_timeout_triggered", True),
        ("container_cleanup_verified", False),
        ("lifecycle_fence_cleared", False),
    ):
        changed = dict(receipt)
        changed[field] = value
        with pytest.raises(prod.ProductionInstallError):
            plan(receipt=changed)


def test_load_managed_build_receipt_binds_exact_artifact_file(monkeypatch, tmp_path):
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_text(json.dumps(ARTIFACT, sort_keys=True) + "\n", encoding="utf-8")
    receipt = managed_receipt(ARTIFACT)
    receipt["artifact_file_sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    receipt_path = prod.managed_build_receipt_path(artifact_path)
    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    receipt_path.chmod(0o600)
    loaded = prod.load_managed_build_receipt(
        receipt_path, ARTIFACT, expected_policy_sha256=MANAGED_POLICY_SHA256, artifact_path=artifact_path
    )
    assert loaded == receipt
    artifact_path.write_text(json.dumps(dict(ARTIFACT, source_bundle_sha256="d" * 64)) + "\n", encoding="utf-8")
    with pytest.raises(prod.ProductionInstallError, match="artifact file digest mismatch"):
        prod.load_managed_build_receipt(
            receipt_path, ARTIFACT, expected_policy_sha256=MANAGED_POLICY_SHA256, artifact_path=artifact_path
        )


def test_filesystem_labels_are_separate_bounded_and_gpt_labels_stay_unchanged():
    compiled = plan()
    by_effect = {item["effect"]: item for item in compiled["commands"]}
    efi_label = by_effect["efi-filesystem"]["argv"][4]
    recovery_label = by_effect["recovery-filesystem"]["argv"][3]
    assert efi_label == PUBLIC_CONTRACT["topology"]["partitions"][0]["filesystem_label"]
    assert recovery_label == PUBLIC_CONTRACT["topology"]["partitions"][1]["filesystem_label"]
    assert len(efi_label) <= 11
    assert len(recovery_label) <= 16
    partition_argv = [
        item["argv"] for item in compiled["commands"] if item["effect"].startswith("partition-")
    ]
    assert any("--change-name=1:HEIMPC_NIXOS_EFI" in argv for argv in partition_argv)
    assert any("--change-name=2:HEIMPC_NIXOS_RECOVERY" in argv for argv in partition_argv)


def test_public_contract_rejects_oversized_filesystem_labels():
    value = json.loads(json.dumps(PUBLIC_CONTRACT))
    value["topology"]["partitions"][0]["filesystem_label"] = "ABCDEFGHIJKL"
    with pytest.raises(prod.storage_identity.IdentityContractError, match="FAT 11-character"):
        prod.storage_identity.validate_public_contract(value)
    value = json.loads(json.dumps(PUBLIC_CONTRACT))
    value["topology"]["partitions"][1]["filesystem_label"] = "A" * 17
    with pytest.raises(prod.storage_identity.IdentityContractError, match="ext4 16-character"):
        prod.storage_identity.validate_public_contract(value)


def test_private_target_partuuid_must_be_a_canonical_gpt_guid():
    identity = json.loads(json.dumps(PRIVATE_IDENTITY))
    identity["topology"]["partitions"][0]["partuuid"] = "not-a-guid"
    with pytest.raises(prod.storage_identity.IdentityContractError, match="private target PARTUUID"):
        prod.storage_identity.bind_contract(PUBLIC_CONTRACT, identity, expected_revision=REVISION)


def test_proof_only_artifact_can_plan_but_cannot_apply(monkeypatch, tmp_path):
    compiled = plan()
    touched = []
    monkeypatch.setattr(prod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(prod, "verify_managed_build_binding", lambda *args, **kwargs: compiled["managed_build_receipt"])
    monkeypatch.setattr(prod, "_run", lambda *args, **kwargs: touched.append(args) or None)
    with pytest.raises(prod.ProductionInstallError, match="merged-main"):
        prod.execute_plan(
            compiled,
            contract=CONTRACT,
            confirmation=prod.confirmation_for(compiled),
            credential_hash_file=tmp_path / "unused",
        )
    assert touched == []


def test_artifact_authority_changes_plan_hash():
    proof = plan(artifact=ARTIFACT)
    merged = plan(artifact=MERGED_ARTIFACT)
    assert proof["source_authority"] == "proof-only"
    assert merged["source_authority"] == "merged-main"
    assert proof["install_artifact_sha256"] != merged["install_artifact_sha256"]
    assert proof["plan_sha256"] != merged["plan_sha256"]


def test_complete_live_wd_gpt_is_part_of_pre_post_fingerprint():
    before = prod.validate_preflight(observation(), CONTRACT)["protected"]
    assert before["gpt_disk_guid"] == "99999999-9999-4999-8999-999999999999"
    assert before["partition_table_fingerprint"][0]["start_sector"] == 2048
    assert before["partition_table_fingerprint"][0]["type_guid"] == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
    assert before["partition_table_fingerprint"][0]["partlabel"] == "ESP"
    assert before["partition_table_fingerprint"][0]["partflags"] == "0x0"
    changed = observation()
    changed["protected"]["partitions"][0]["start_sector"] += 1
    after = prod.validate_preflight(changed, CONTRACT)["protected"]
    assert prod.protected_fingerprint(before) != prod.protected_fingerprint(after)


def test_findmnt_uses_first_only_and_canonicalizes_by_uuid(monkeypatch):
    calls = []

    class Result:
        stdout = b"/dev/disk/by-uuid/SYNTH\n"

    monkeypatch.setattr(prod, "_run", lambda argv: calls.append(argv) or Result())
    monkeypatch.setattr(prod.os.path, "realpath", lambda path: "/dev/nvme1n1p3")
    assert prod._findmnt("/") == "/dev/nvme1n1p3"
    assert "--first-only" in calls[0]


def test_verified_protected_aliases_are_rebound_live(monkeypatch):
    aliases = {
        WD: "/dev/nvme1n1",
        "/dev/disk/by-id/nvme-SYNTHETIC_FALLBACK_ALIAS": "/dev/nvme1n1",
    }
    monkeypatch.setattr(prod.os.path, "realpath", lambda path: aliases.get(path, path))
    monkeypatch.setattr(prod.os.path, "islink", lambda path: path in aliases)
    prod._verify_protected_by_id_aliases(CONTRACT)
    aliases["/dev/disk/by-id/nvme-SYNTHETIC_FALLBACK_ALIAS"] = "/dev/nvme9n1"
    with pytest.raises(prod.ProductionInstallError, match="alias no longer resolves"):
        prod._verify_protected_by_id_aliases(CONTRACT)


def test_teardown_nonzero_is_recorded_but_later_cleanup_still_runs(monkeypatch):
    commands = [
        {"effect": "unmount", "argv": ["umount", "/mnt/a"]},
        {"effect": "unmount", "argv": ["umount", "/mnt/b"]},
    ]
    calls = []

    class Result:
        def __init__(self, returncode):
            self.returncode = returncode
            self.stdout = b""
            self.stderr = b""

    monkeypatch.setattr(prod, "_mountpoint_is_mounted", lambda _path: True)
    monkeypatch.setattr(
        prod,
        "_run",
        lambda argv, check=False: calls.append(argv) or Result(32 if argv[-1] == "/mnt/a" else 0),
    )
    failures, error = prod._attempt_teardown(commands, "heimpc-nixos-crypt")
    assert calls == [["umount", "/mnt/a"], ["umount", "/mnt/b"]]
    assert failures == ["unmount"]
    assert error is None


def test_already_unmounted_stage_is_proven_clean_without_spurious_umount(monkeypatch):
    calls = []
    monkeypatch.setattr(prod, "_mountpoint_is_mounted", lambda _path: False)
    monkeypatch.setattr(prod, "_run", lambda argv, check=False: calls.append(argv))
    failures, error = prod._attempt_teardown(
        [{"effect": "unmount-stage", "argv": ["umount", prod.BTRFS_STAGE_ROOT]}],
        "heimpc-nixos-crypt",
    )
    assert calls == []
    assert failures == []
    assert error is None


def test_credential_staging_failure_uses_dedicated_post_mutation_alarm(monkeypatch, tmp_path):
    compiled = plan(artifact=MERGED_ARTIFACT)
    monkeypatch.setattr(prod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(prod, "verify_source", lambda *args, **kwargs: REVISION)
    monkeypatch.setattr(prod, "verify_managed_build_binding", lambda *args, **kwargs: compiled["managed_build_receipt"])
    monkeypatch.setattr(prod, "verify_promoted_main_revision", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_install_artifact_environment", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_scratch_state", lambda *_args: None)
    monkeypatch.setattr(prod, "validate_preflight", lambda *_args: compiled["preflight"])
    monkeypatch.setattr(prod, "verify_no_hidden_target_signatures", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_partuuid_namespace_clear", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_partlabel_namespace_clear", lambda *_args: None)
    monkeypatch.setattr(prod, "read_credential_hash", lambda *_args: b"hash\n")
    monkeypatch.setattr(prod.getpass, "getpass", lambda *args, **kwargs: "passphrase")
    monkeypatch.setattr(prod, "efi_nvram_digest", lambda: "a" * 64)
    monkeypatch.setattr(prod, "verify_target_partition_bindings", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_installed_target", lambda *_args: None)
    monkeypatch.setattr(prod, "verify_persist_mount", lambda *_args: None)
    monkeypatch.setattr(prod, "_attempt_teardown", lambda *args, **kwargs: ([], None))
    monkeypatch.setattr(prod, "_mountpoint_is_mounted", lambda _path: False)
    monkeypatch.setattr(
        prod,
        "stage_firstboot_credentials",
        lambda **kwargs: (_ for _ in ()).throw(prod.ProductionInstallError("private staging detail")),
    )
    monkeypatch.setattr(prod, "validate_protected_state", lambda *_args: compiled["preflight"]["protected"])
    mock_trusted_build_gate(monkeypatch, compiled)

    class Result:
        returncode = 0
        stdout = b""
        stderr = b""

    monkeypatch.setattr(prod, "_run", lambda *args, **kwargs: Result())
    with pytest.raises(prod.PostMutationInstallError) as exc:
        prod.execute_plan(
            compiled,
            contract=CONTRACT,
            confirmation=prod.confirmation_for(compiled),
            credential_hash_file=tmp_path / "credential.hash",
            observer=lambda _contract: observation(),
        )
    assert exc.value.code == "credential-staging-incomplete"


def test_private_plan_is_explicit_create_only_and_stdout_summary_is_redacted(tmp_path):
    compiled = plan()
    target = tmp_path / "plan.json"
    prod.write_private_plan(target, compiled)
    assert target.stat().st_mode & 0o777 == 0o600
    assert json.loads(target.read_text()) == compiled
    with pytest.raises(prod.ProductionInstallError, match="overwrite"):
        prod.write_private_plan(target, compiled)
    summary = json.dumps(prod.plan_summary(compiled), sort_keys=True)
    assert "SYNTH-TARGET-SERIAL" not in summary
    assert SEAGATE not in summary
    assert WD not in summary
    assert prod.plan_summary(compiled)["private_hardware_identity_redacted"] is True
