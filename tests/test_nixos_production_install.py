import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "nixos_production_install.py"
spec = importlib.util.spec_from_file_location("nixos_production_install", MODULE_PATH)
prod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(prod)

SEAGATE = "/dev/disk/by-id/nvme-Seagate_ZP4000GP304001_7VS01DX7"
WD = "/dev/disk/by-id/nvme-eui.e8238fa6bf530001001b448b4d59e756"
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
    "source_bundle_sha256": "b" * 64,
    **CLOSURE,
}
PARTUUIDS = [
    "fef423b1-cb0d-4594-a272-c203cb003779",
    "6da3e5b4-6693-49d4-a7c5-1a4b13effcf1",
    "b2fdb842-ba91-4482-880f-ef02065c6af1",
]


def observation():
    return {
        "target": {
            "requested_path": SEAGATE,
            "resolved_path": "/dev/nvme0n1",
            "model": "Seagate ZP4000GP304001",
            "serial": "7VS01DX7",
            "wwn": "eui.6479a7716f000a39",
            "size_bytes": 4000787030016,
            "transport": "nvme",
            "filesystem": None,
            "partition_table": None,
            "mountpoints": [],
            "mounted": False,
            "signatures": [],
            "partitions": [],
        },
        "protected": {
            "requested_path": WD,
            "resolved_path": "/dev/nvme1n1",
            "model": "WD_BLACK SN850X 2000GB",
            "serial": "25025T802519",
            "wwn": "eui.e8238fa6bf530001001b448b4d59e756",
            "size_bytes": 2000398934016,
            "transport": "nvme",
            "filesystem": None,
            "partition_table": "gpt",
            "mountpoints": ["/boot/efi", "/recovery", "/"],
            "mounted": True,
            "signatures": [],
            "partitions": [
                {"number": 1, "path": "/dev/nvme1n1p1", "size_bytes": 1071644160, "partuuid": "f16edce1-0366-4188-9f67-bd21bd022010", "fstype": "vfat", "uuid": "78FD-6130"},
                {"number": 2, "path": "/dev/nvme1n1p2", "size_bytes": 4294966784, "partuuid": "bf96afc8-02a9-452d-beba-94979a014add", "fstype": "vfat", "uuid": "78FD-60C8"},
                {"number": 3, "path": "/dev/nvme1n1p3", "size_bytes": 1990733157888, "partuuid": "3124b879-382d-47b0-90c7-b84a9fd8ff9e", "fstype": "ext4", "uuid": "d25d44aa-5334-4b9d-9cc2-2475e9123776"},
                {"number": 4, "path": "/dev/nvme1n1p4", "size_bytes": 4294966784, "partuuid": "b9f8924f-5909-4b0d-ad92-cd339e4c5c43", "fstype": "swap", "uuid": "098646bf-5717-4810-8ebc-468f6f387bba"},
            ],
        },
        "root_source": "/dev/nvme1n1p3",
        "efi_source": "/dev/nvme1n1p1",
    }


def plan(obs=None, artifact=None):
    return prod.compile_plan(
        obs or observation(),
        install_artifact=artifact or ARTIFACT,
        flake_source="/srv/exact-source",
    )


def test_contract_is_bound_to_physical_seagate_and_protected_wd():
    contract = prod.load_contract()
    target = contract["target_identity"]
    assert target["exact_by_id"] == SEAGATE
    assert target["exact_model"] == "Seagate ZP4000GP304001"
    assert target["exact_serial"] == "7VS01DX7"
    assert target["exact_wwn"] == "eui.6479a7716f000a39"
    assert target["exact_size_bytes"] == 4000787030016
    assert target["kernel_name_authoritative"] is False
    assert contract["protected_disks"][0]["by_id"] == WD
    assert len(contract["protected_disks"][0]["partition_table_fingerprint"]) == 4


def test_valid_preflight_binds_root_and_efi_to_protected_wd():
    result = prod.validate_preflight(observation())
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
        prod.validate_preflight(obs)


def test_kernel_name_cannot_be_target_authority():
    obs = observation()
    obs["target"]["requested_path"] = "/dev/nvme0n1"
    with pytest.raises(prod.ProductionInstallError, match="exact contract by-id"):
        prod.validate_preflight(obs)


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
        prod.validate_preflight(obs)


def test_target_protected_alias_collision_is_rejected():
    obs = observation()
    obs["target"]["resolved_path"] = "/dev/nvme1n1"
    with pytest.raises(prod.ProductionInstallError, match="alias collision"):
        prod.validate_preflight(obs)


@pytest.mark.parametrize(
    ("key", "wrong"),
    [("root_source", "/dev/nvme0n1p3"), ("efi_source", "/dev/nvme0n1p1")],
)
def test_root_and_efi_must_be_on_protected_wd(key, wrong):
    obs = observation()
    obs[key] = wrong
    with pytest.raises(prod.ProductionInstallError):
        prod.validate_preflight(obs)


def test_protected_partition_fingerprint_mismatch_is_rejected():
    obs = observation()
    obs["protected"]["partitions"][2]["partuuid"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(prod.ProductionInstallError, match="fingerprint mismatch"):
        prod.validate_preflight(obs)



def test_protected_filesystem_signature_mismatch_is_rejected():
    obs = observation()
    obs["protected"]["partitions"][0]["uuid"] = "DEAD-BEEF"
    with pytest.raises(prod.ProductionInstallError, match="fingerprint mismatch"):
        prod.validate_preflight(obs)

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


def test_nixos_install_uses_exact_offline_artifact_without_host_nix():
    compiled = plan()
    install = next(item for item in compiled["commands"] if item["effect"] == "nixos-install")
    assert install["argv"] == [
        "docker",
        "run",
        "--rm",
        "--privileged",
        "--network",
        "none",
        "-v",
        f"{NIX_VOLUME}:/nix",
        "-v",
        f"{prod.MOUNT_ROOT}:/mnt",
        "--entrypoint",
        f"{SYSTEM_PATH}/sw/bin/nixos-install",
        prod.PINNED_NIX_IMAGE,
        "--root",
        "/mnt",
        "--system",
        SYSTEM_PATH,
        "--no-channel-copy",
        "--no-root-password",
    ]
    assert compiled["install_artifact"] == ARTIFACT
    assert compiled["source_revision"] == REVISION
    assert compiled["efi_variables_must_remain_untouched"] is True
    assert compiled["execution_authorized"] is False


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
        prod.execute_plan(compiled, confirmation="wrong", credential_hash_file=tmp_path / "unused")
    assert touched == []


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


def test_btrfs_tools_also_run_from_exact_artifact():
    compiled = plan()
    by_effect = {}
    for item in compiled["commands"]:
        by_effect.setdefault(item["effect"], item)
    mkfs = by_effect["btrfs-filesystem"]["argv"]
    assert mkfs[:7] == ["docker", "run", "--rm", "--privileged", "--network", "none", "-v"]
    assert f"{NIX_VOLUME}:/nix:ro" in mkfs
    assert f"{SYSTEM_PATH}/sw/bin/mkfs.btrfs" in mkfs
    subvol = by_effect["btrfs-subvolume-create"]["argv"]
    assert f"{SYSTEM_PATH}/sw/bin/btrfs" in subvol
    assert f"{prod.BTRFS_STAGE_ROOT}:{prod.BTRFS_STAGE_ROOT}" in subvol


def test_firstboot_staging_is_source_and_hash_bound_and_private(tmp_path):
    (tmp_path / "persist").mkdir(mode=0o755)
    password_hash = ("$y$j9T$" + "A" * 21 + "." + "$" + "B" * 43 + "\n").encode("ascii")
    receipt = prod.stage_firstboot_credentials(mount_root=str(tmp_path), source_revision=REVISION, hash_bytes=password_hash)
    secret = Path(receipt["secret_path"])
    authority = Path(receipt["authority_path"])
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
    assert receipt["password_hash_sha256"] == digest


def test_firstboot_staging_refuses_existing_secret(tmp_path):
    persist = tmp_path / "persist"
    secret_dir = persist / "secrets" / "heim-pc" / "first-boot"
    secret_dir.mkdir(parents=True)
    (secret_dir / "alex-password-hash").write_text("do-not-overwrite")
    password_hash = ("$y$j9T$" + "A" * 21 + "." + "$" + "B" * 43 + "\n").encode("ascii")
    with pytest.raises(prod.ProductionInstallError, match="refuses existing"):
        prod.stage_firstboot_credentials(mount_root=str(tmp_path), source_revision=REVISION, hash_bytes=password_hash)


def test_plan_contains_no_secret_material():
    serialized = json.dumps(plan())
    assert "passphrase" not in serialized.lower() or "luks-passphrase-v1" in serialized
    assert "$y$j9T$" not in serialized


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
        prod.verify_partuuid_namespace_clear(prod.load_contract())


def _post_partition_target():
    target = observation()["target"]
    target["partition_table"] = "gpt"
    target["partitions"] = [
        {"number": number, "path": f"/dev/nvme0n1p{number}", "partuuid": partuuid}
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
    monkeypatch.setattr(prod, "_disk_observation", lambda authority: target)
    monkeypatch.setattr(prod.os.path, "islink", lambda path: path in aliases)
    monkeypatch.setattr(prod.os.path, "realpath", lambda path: aliases.get(path, path))
    prod.verify_target_partition_bindings(prod.load_contract())
    aliases[f"/dev/disk/by-partuuid/{PARTUUIDS[0]}"] = "/dev/nvme9n1p1"
    with pytest.raises(prod.ProductionInstallError, match="PARTUUID alias points outside"):
        prod.verify_target_partition_bindings(prod.load_contract())


def test_install_artifact_environment_recomputes_and_verifies_closure(monkeypatch):
    calls = []

    class Result:
        def __init__(self, stdout=b""):
            self.stdout = stdout
            self.returncode = 0
            self.stderr = b""

    def fake_run(argv, *, input_bytes=None, check=True):
        calls.append(argv)
        if argv[:4] == ["docker", "image", "inspect", "--format"]:
            return Result((prod.PINNED_NIX_IMAGE + "\n").encode())
        if "path-info" in argv:
            return Result(json.dumps(CLOSURE_PATH_INFO).encode())
        return Result()

    monkeypatch.setattr(prod, "_run", fake_run)
    prod.verify_install_artifact_environment(ARTIFACT)
    assert any("store" in argv and "verify" in argv and "--no-trust" in argv for argv in calls)
    with pytest.raises(prod.ProductionInstallError, match="closure metadata"):
        prod.verify_install_artifact_environment(dict(ARTIFACT, closure_manifest_sha256="0" * 64))
