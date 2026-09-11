#!/usr/bin/env python3
"""Guarded production installer for the isolated Heim-PC Seagate NixOS target.

The default mode is effect-free: observe, validate and compile a plan. Destructive
execution requires --apply plus a plan-hash-bound confirmation token. Kernel NVMe
names may appear only as observed resolution; mutation authority is the exact
contract by-id path or fixed by-partuuid paths.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "nixos" / "production" / "contract-v1.json"
FLAKE_SOURCE = ROOT / "nixos" / "system"
MOUNT_ROOT = "/mnt/heim-pc-nixos-production"
BTRFS_STAGE_ROOT = "/mnt/heim-pc-nixos-production-btrfs-stage"
CONFIRM_PREFIX = "APPLY-NIXOS-PRODUCTION:"
PINNED_NIX_IMAGE = "sha256:98edc6813218e179ce84587373e0b52d4aa58babae2d26b51fb01e7fdacf815f"
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SYSTEM_PATH_RE = re.compile(r"^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-nixos-system-heim-pc-[A-Za-z0-9._+-]+$")
NIX_VOLUME_RE = re.compile(r"^heim-pc-nixos-production-[0-9a-f]{12,40}$")
KERNEL_NVME_RE = re.compile(r"^/dev/nvme\d+n\d+(?:p\d+)?$")
YESCRYPT_RE = re.compile(r"^\$y\$j9T\$[./0-9A-Za-z]{22}\$[./0-9A-Za-z]{43}$")
CRYPT64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
YESCRYPT_SALT_LAST = frozenset(CRYPT64[:4])
YESCRYPT_CHECKSUM_LAST = frozenset(CRYPT64[:16])


class ProductionInstallError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProductionInstallError(f"cannot read production storage contract: {exc}") from exc
    if value.get("schema_version") != 1 or value.get("kind") != "heim_pc.nixos_production_storage_contract":
        raise ProductionInstallError("production storage contract identity mismatch")
    target = value.get("target_identity")
    if not isinstance(target, dict):
        raise ProductionInstallError("target_identity is missing")
    for key in ("exact_by_id", "exact_model", "exact_serial", "exact_wwn", "exact_size_bytes"):
        if target.get(key) in (None, ""):
            raise ProductionInstallError(f"target identity is not fully captured: {key}")
    _require_by_id(target["exact_by_id"], "target exact_by_id")
    if target.get("transport") != "nvme" or target.get("kernel_name_authoritative") is not False:
        raise ProductionInstallError("target transport/kernel-name policy mismatch")
    if not target.get("requires_blank") or not target.get("requires_unmounted"):
        raise ProductionInstallError("production target must require blank and unmounted state")
    protected = value.get("protected_disks")
    if not isinstance(protected, list) or len(protected) != 1:
        raise ProductionInstallError("exactly one protected fallback disk is required")
    _require_by_id(protected[0].get("by_id"), "protected disk by_id")
    fingerprint = protected[0].get("partition_table_fingerprint")
    if not isinstance(fingerprint, list) or len(fingerprint) != 4:
        raise ProductionInstallError("protected disk partition fingerprint must contain four partitions")
    topology = value.get("topology", {})
    if topology.get("partition_table") != "gpt" or topology.get("partition_identity_policy") != "contract-assigned-partuuid":
        raise ProductionInstallError("production GPT/PARTUUID policy mismatch")
    partitions = topology.get("partitions")
    if not isinstance(partitions, list) or len(partitions) != 3:
        raise ProductionInstallError("production topology must contain three partitions")
    partuuids = [str(item.get("partuuid", "")).lower() for item in partitions]
    if len(set(partuuids)) != 3 or any(not item for item in partuuids):
        raise ProductionInstallError("production PARTUUIDs must be unique and non-empty")
    boot = value.get("boot", {})
    if boot.get("own_esp_required") is not True or boot.get("shared_esp_forbidden") is not True or boot.get("touch_efi_variables") is not False:
        raise ProductionInstallError("isolated boot policy mismatch")
    mutation = value.get("mutation_policy", {})
    if not all(mutation.get(key) is True for key in (
        "target_by_id_only", "kernel_device_name_forbidden",
        "protected_disk_pre_post_identity_required",
        "protected_disk_partition_table_pre_post_required",
        "target_identity_must_be_fully_captured",
    )):
        raise ProductionInstallError("production mutation policy is incomplete")
    return value


def validate_install_artifact(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProductionInstallError("install artifact must be a JSON object")
    if value.get("schema_version") != 1 or value.get("kind") != "heim_pc.nixos_production_install_artifact":
        raise ProductionInstallError("production install artifact identity mismatch")
    revision = value.get("source_revision")
    if not isinstance(revision, str) or SOURCE_REVISION_RE.fullmatch(revision) is None:
        raise ProductionInstallError("install artifact source_revision must be exact 40-hex")
    system_path = value.get("system_path")
    if not isinstance(system_path, str) or SYSTEM_PATH_RE.fullmatch(system_path) is None:
        raise ProductionInstallError("install artifact system_path is not a canonical Heim-PC NixOS closure")
    volume = value.get("nix_volume")
    if not isinstance(volume, str) or NIX_VOLUME_RE.fullmatch(volume) is None:
        raise ProductionInstallError("install artifact nix_volume is invalid")
    if value.get("nix_image") != PINNED_NIX_IMAGE:
        raise ProductionInstallError("install artifact Nix image is not the pinned image")
    if value.get("profile") != "heim-pc-storage-target":
        raise ProductionInstallError("install artifact profile mismatch")
    bundle_sha = value.get("source_bundle_sha256")
    if not isinstance(bundle_sha, str) or re.fullmatch(r"[0-9a-f]{64}", bundle_sha) is None:
        raise ProductionInstallError("install artifact source bundle digest is invalid")
    return dict(value)


def load_install_artifact(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProductionInstallError(f"cannot read production install artifact: {exc}") from exc
    return validate_install_artifact(value)


def _docker_tool_argv(artifact: dict[str, Any], tool: str, args: list[str], *, mounts: list[str] | None = None, nix_read_only: bool = True) -> list[str]:
    nix_mount = f"{artifact['nix_volume']}:/nix" + (":ro" if nix_read_only else "")
    argv = ["docker", "run", "--rm", "--privileged", "--network", "none", "-v", nix_mount]
    for mount in mounts or []:
        argv += ["-v", mount]
    argv += ["--entrypoint", f"{artifact['system_path']}/sw/bin/{tool}", artifact["nix_image"]]
    return argv + args


def _require_by_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/dev/disk/by-id/") or os.path.normpath(value) != value:
        raise ProductionInstallError(f"{label} must be a canonical /dev/disk/by-id path")
    if KERNEL_NVME_RE.fullmatch(value):
        raise ProductionInstallError(f"{label} must not use a kernel NVMe name")
    return value


def _partition_by_role(contract: dict[str, Any], role: str) -> dict[str, Any]:
    matches = [item for item in contract["topology"]["partitions"] if item.get("role") == role]
    if len(matches) != 1:
        raise ProductionInstallError(f"topology must contain exactly one {role} partition")
    return matches[0]


def _partuuid_path(partition: dict[str, Any]) -> str:
    return f"/dev/disk/by-partuuid/{str(partition['partuuid']).lower()}"


def _partition_new_arg(partition: dict[str, Any]) -> str:
    size = partition["size"]
    end = f"+{size['value']}MiB" if size["kind"] == "fixed_mib" else "0"
    return f"--new={partition['number']}:0:{end}"


def _mount_path(logical: str) -> str:
    if logical == "/":
        return MOUNT_ROOT
    path = PurePosixPath(logical)
    if not path.is_absolute() or ".." in path.parts:
        raise ProductionInstallError(f"unsafe logical mountpoint: {logical}")
    return str(PurePosixPath(MOUNT_ROOT, *path.parts[1:]))


def _normalize_mounts(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ProductionInstallError("mountpoints must be a list")
    return [str(item) for item in value if item not in (None, "")]


def _identity_tuple(value: dict[str, Any]) -> tuple[Any, ...]:
    return (value.get("model"), value.get("serial"), value.get("wwn"), value.get("size_bytes"), value.get("transport"))


def validate_protected_state(observation: dict[str, Any], contract: dict[str, Any] | None = None) -> dict[str, Any]:
    contract = contract or load_contract()
    protected_contract = contract["protected_disks"][0]
    protected = observation.get("protected")
    if not isinstance(protected, dict):
        raise ProductionInstallError("protected disk observation missing")
    if protected.get("requested_path") != protected_contract["by_id"]:
        raise ProductionInstallError("protected disk was not selected by canonical by-id")
    expected_identity = (
        protected_contract["model"], protected_contract["serial"], protected_contract["wwn"],
        protected_contract["size_bytes"], "nvme",
    )
    if _identity_tuple(protected) != expected_identity:
        raise ProductionInstallError("protected WD identity mismatch")
    observed_parts = protected.get("partitions")
    if not isinstance(observed_parts, list):
        raise ProductionInstallError("protected partition observation missing")
    observed_by_number = {item.get("number"): item for item in observed_parts}
    if len(observed_by_number) != len(protected_contract["partition_table_fingerprint"]):
        raise ProductionInstallError("protected partition count mismatch")
    expected_paths: dict[str, str] = {}
    for expected in protected_contract["partition_table_fingerprint"]:
        actual = observed_by_number.get(expected["number"])
        if not isinstance(actual, dict):
            raise ProductionInstallError(f"protected partition {expected['number']} missing")
        if (
            actual.get("size_bytes") != expected["size_bytes"]
            or str(actual.get("partuuid", "")).lower() != expected["partuuid"].lower()
            or actual.get("fstype") != expected.get("fstype")
            or str(actual.get("uuid", "")) != str(expected.get("uuid", ""))
        ):
            raise ProductionInstallError(f"protected partition {expected['number']} fingerprint mismatch")
        path = actual.get("path")
        if not isinstance(path, str) or not KERNEL_NVME_RE.fullmatch(path):
            raise ProductionInstallError(f"protected partition {expected['number']} observed path is invalid")
        expected_paths[expected["role"]] = path
    if observation.get("root_source") != expected_paths.get("popos-root"):
        raise ProductionInstallError("current root is not the protected WD root partition")
    if observation.get("efi_source") != expected_paths.get("popos-esp"):
        raise ProductionInstallError("current EFI mount is not the protected WD ESP")
    return {
        "requested_path": protected_contract["by_id"],
        "resolved_path": protected.get("resolved_path"),
        "model": protected_contract["model"],
        "serial": protected_contract["serial"],
        "wwn": protected_contract["wwn"],
        "size_bytes": protected_contract["size_bytes"],
        "partition_table_fingerprint": protected_contract["partition_table_fingerprint"],
        "root_source": observation["root_source"],
        "efi_source": observation["efi_source"],
    }


def validate_preflight(observation: dict[str, Any], contract: dict[str, Any] | None = None) -> dict[str, Any]:
    contract = contract or load_contract()
    target_contract = contract["target_identity"]
    target = observation.get("target")
    if not isinstance(target, dict):
        raise ProductionInstallError("target observation missing")
    requested = target.get("requested_path")
    if requested != target_contract["exact_by_id"]:
        raise ProductionInstallError("target must be selected by the exact contract by-id")
    _require_by_id(requested, "observed target requested_path")
    if KERNEL_NVME_RE.fullmatch(requested):
        raise ProductionInstallError("kernel NVMe names are forbidden as target authority")
    expected_identity = (
        target_contract["exact_model"], target_contract["exact_serial"], target_contract["exact_wwn"],
        target_contract["exact_size_bytes"], target_contract["transport"],
    )
    if _identity_tuple(target) != expected_identity:
        raise ProductionInstallError("Seagate target identity mismatch")
    if target.get("mounted") is not False or _normalize_mounts(target.get("mountpoints")):
        raise ProductionInstallError("Seagate target must be unmounted")
    if target.get("partitions") not in ([], None):
        raise ProductionInstallError("Seagate target is not blank: partitions exist")
    if target.get("partition_table") not in (None, ""):
        raise ProductionInstallError("Seagate target is not blank: partition table exists")
    if target.get("filesystem") not in (None, "") or target.get("signatures") not in ([], None):
        raise ProductionInstallError("Seagate target is not blank: filesystem/signatures exist")
    protected = validate_protected_state(observation, contract)
    if target.get("resolved_path") == protected.get("resolved_path"):
        raise ProductionInstallError("target/protected disk alias collision")
    if requested == protected["requested_path"]:
        raise ProductionInstallError("target/protected authority path collision")
    return {"target": dict(target), "protected": protected}


def protected_fingerprint(value: dict[str, Any]) -> str:
    return sha256_json(value)


def _subvolume_mounts(contract: dict[str, Any]) -> list[tuple[str, str]]:
    result = [(item["name"], item["mountpoint"]) for item in contract["topology"]["btrfs"]["subvolumes"]]
    if len({mount for _, mount in result}) != len(result):
        raise ProductionInstallError("Btrfs mountpoints must be unique")
    result.sort(key=lambda item: (len(PurePosixPath(item[1]).parts), item[1]))
    if not result or result[0][1] != "/":
        raise ProductionInstallError("Btrfs topology must contain root")
    return result


def compile_plan(
    observation: dict[str, Any],
    *,
    install_artifact: dict[str, Any],
    flake_source: str,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    contract = contract or load_contract()
    artifact = validate_install_artifact(install_artifact)
    source_revision = artifact["source_revision"]
    flake = str(PurePosixPath(flake_source))
    if not flake.startswith("/") or os.path.normpath(flake) != flake:
        raise ProductionInstallError("flake source must be a canonical absolute path")
    preflight = validate_preflight(observation, contract)
    target = contract["target_identity"]["exact_by_id"]
    efi = _partition_by_role(contract, "efi-system-partition")
    recovery = _partition_by_role(contract, "recovery-surface")
    encrypted = _partition_by_role(contract, "encrypted-system")
    mapper_name = contract["topology"]["luks"]["mapper_name"]
    mapper = f"/dev/mapper/{mapper_name}"
    btrfs = contract["topology"]["btrfs"]
    commands: list[dict[str, Any]] = [{"effect": "partition-table-reset", "argv": ["sgdisk", "--zap-all", target]}]
    for partition in sorted(contract["topology"]["partitions"], key=lambda item: item["number"]):
        n = partition["number"]
        commands.append({
            "effect": f"partition-{partition['role']}",
            "argv": [
                "sgdisk", _partition_new_arg(partition), f"--typecode={n}:{partition['type_guid']}",
                f"--change-name={n}:{partition['label']}", f"--partition-guid={n}:{partition['partuuid']}", target,
            ],
        })
    commands += [
        {"effect": "partition-table-reread", "argv": ["partprobe", target]},
        {"effect": "udev-settle", "argv": ["udevadm", "settle"]},
        {"effect": "mount-root-create", "argv": ["mkdir", "-p", MOUNT_ROOT, BTRFS_STAGE_ROOT]},
        {"effect": "efi-filesystem", "argv": ["mkfs.fat", "-F", "32", "-n", efi["label"], _partuuid_path(efi)]},
        {"effect": "recovery-filesystem", "argv": ["mkfs.ext4", "-F", "-L", recovery["label"], _partuuid_path(recovery)]},
        {"effect": "luks-format", "argv": ["cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--key-file", "-", _partuuid_path(encrypted)], "secret_binding": "luks-passphrase-v1"},
        {"effect": "luks-open", "argv": ["cryptsetup", "open", "--type", "luks2", "--key-file", "-", _partuuid_path(encrypted), mapper_name], "secret_binding": "luks-passphrase-v1"},
        {
            "effect": "btrfs-filesystem",
            "argv": _docker_tool_argv(artifact, "mkfs.btrfs", ["-f", "-L", btrfs["label"], mapper], mounts=["/dev:/dev"]),
        },
        {"effect": "btrfs-stage-mount", "argv": ["mount", mapper, BTRFS_STAGE_ROOT]},
    ]
    for name, _mountpoint in _subvolume_mounts(contract):
        commands.append({
            "effect": "btrfs-subvolume-create",
            "argv": _docker_tool_argv(
                artifact,
                "btrfs",
                ["subvolume", "create", f"{BTRFS_STAGE_ROOT}/{name}"],
                mounts=[f"{BTRFS_STAGE_ROOT}:{BTRFS_STAGE_ROOT}"],
            ),
        })
    commands.append({"effect": "btrfs-stage-unmount", "argv": ["umount", BTRFS_STAGE_ROOT]})
    for name, logical in _subvolume_mounts(contract):
        dest = _mount_path(logical)
        commands.append({"effect": "mountpoint-create", "argv": ["mkdir", "-p", dest]})
        commands.append({"effect": "btrfs-subvolume-mount", "argv": ["mount", "-o", f"subvol={name}", mapper, dest]})
    for partition in (efi, recovery):
        dest = _mount_path(partition["mountpoint"])
        commands.append({"effect": "mountpoint-create", "argv": ["mkdir", "-p", dest]})
        commands.append({"effect": "surface-mount", "argv": ["mount", _partuuid_path(partition), dest]})
    commands.append({
        "effect": "nixos-install",
        "argv": _docker_tool_argv(
            artifact,
            "nixos-install",
            ["--root", "/mnt", "--system", artifact["system_path"], "--no-channel-copy", "--no-root-password"],
            mounts=[f"{MOUNT_ROOT}:/mnt"],
            nix_read_only=False,
        ),
    })
    mounted = [_mount_path(logical) for _, logical in _subvolume_mounts(contract)] + [_mount_path(efi["mountpoint"]), _mount_path(recovery["mountpoint"])]
    teardown = [{"effect": "unmount-stage", "argv": ["umount", BTRFS_STAGE_ROOT]}]
    teardown += [{"effect": "unmount", "argv": ["umount", path]} for path in sorted(set(mounted), key=lambda p: (len(PurePosixPath(p).parts), p), reverse=True)]
    teardown.append({"effect": "luks-close", "argv": ["cryptsetup", "close", mapper_name]})
    material = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_plan",
        "contract_sha256": sha256_json(contract),
        "install_artifact_sha256": sha256_json(artifact),
        "install_artifact": artifact,
        "source_revision": source_revision,
        "flake_source": flake,
        "system_path": artifact["system_path"],
        "target_authority": target,
        "protected_authority": contract["protected_disks"][0]["by_id"],
        "preflight": preflight,
        "protected_pre_fingerprint": protected_fingerprint(preflight["protected"]),
        "commands": commands,
        "teardown_commands": teardown,
        "credential_staging_required": True,
        "efi_variables_must_remain_untouched": True,
        "execution_authorized": False,
    }
    return {**material, "plan_sha256": sha256_json(material)}


def confirmation_for(plan: dict[str, Any]) -> str:
    return CONFIRM_PREFIX + plan["plan_sha256"]


def validate_confirmation(plan: dict[str, Any], confirmation: str | None) -> None:
    if confirmation != confirmation_for(plan):
        raise ProductionInstallError("apply confirmation does not match the exact plan digest")


def is_canonical_default_yescrypt(text: str) -> bool:
    if YESCRYPT_RE.fullmatch(text) is None:
        return False
    _prefix, salt, checksum = text.rsplit("$", 2)
    return salt[-1] in YESCRYPT_SALT_LAST and checksum[-1] in YESCRYPT_CHECKSUM_LAST


def _write_all_fd(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise ProductionInstallError("short write while staging firstboot credentials")
        view = view[written:]


def read_credential_hash(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProductionInstallError(f"cannot open credential hash file safely: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ProductionInstallError("credential hash file must be a single-link private regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 1024:
                raise ProductionInstallError("credential hash file is unexpectedly large")
        data = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProductionInstallError("credential hash must be ASCII") from exc
    if not text.endswith("\n") or text.count("\n") != 1 or not is_canonical_default_yescrypt(text[:-1]):
        raise ProductionInstallError("credential hash does not satisfy the pinned default-cost yescrypt contract")
    return data


def _safe_secret_dir(root: Path) -> Path:
    current = root / "persist"
    if not current.is_dir() or current.is_symlink():
        raise ProductionInstallError("target /persist mount is missing or unsafe")
    for name in ("secrets", "heim-pc", "first-boot"):
        current = current / name
        current.mkdir(mode=0o700, exist_ok=True)
        if current.is_symlink() or not current.is_dir():
            raise ProductionInstallError("credential staging directory is unsafe")
        os.chmod(current, 0o700)
    return current


def stage_firstboot_credentials(*, mount_root: str, source_revision: str, hash_bytes: bytes) -> dict[str, Any]:
    if SOURCE_REVISION_RE.fullmatch(source_revision) is None:
        raise ProductionInstallError("invalid source revision for credential authority")
    root = Path(mount_root)
    secret_dir = _safe_secret_dir(root)
    secret = secret_dir / "alex-password-hash"
    authority = secret_dir / "alex-password-bootstrap-authority"
    for destination in (secret, authority):
        if destination.exists() or destination.is_symlink():
            raise ProductionInstallError(f"credential staging refuses existing {destination.name}")
    digest = hashlib.sha256(hash_bytes).hexdigest()
    authority_bytes = (
        "schema_version=1\nuser=alex\naction=initialize-password\n"
        f"source_revision={source_revision}\npassword_hash_sha256={digest}\n"
    ).encode("ascii")
    for destination, payload in ((secret, hash_bytes), (authority, authority_bytes)):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(destination, flags, 0o600)
        try:
            _write_all_fd(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(destination, 0o600)
    dir_fd = os.open(secret_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return {"source_revision": source_revision, "password_hash_sha256": digest, "secret_path": str(secret), "authority_path": str(authority)}


def _run(argv: list[str], *, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if check and result.returncode != 0:
        if input_bytes is not None:
            raise ProductionInstallError(f"command failed ({argv[0]}) with sensitive stdin; stderr withheld")
        stderr = result.stderr.decode("utf-8", "replace")[-4000:]
        raise ProductionInstallError(f"command failed ({argv[0]}): {stderr}")
    return result


def _json_command(argv: list[str]) -> dict[str, Any]:
    result = _run(argv)
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProductionInstallError(f"invalid JSON from {argv[0]}") from exc


def _disk_observation(authority_path: str) -> dict[str, Any]:
    _require_by_id(authority_path, "disk observation authority")
    if not os.path.islink(authority_path):
        raise ProductionInstallError(f"by-id authority is missing: {authority_path}")
    resolved = os.path.realpath(authority_path)
    data = _json_command(["lsblk", "--json", "--bytes", "--paths", "-o", "PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN,FSTYPE,UUID,PTTYPE,PARTUUID,MOUNTPOINTS", resolved])
    devices = data.get("blockdevices") or []
    disks = [item for item in devices if item.get("type") == "disk" and item.get("path") == resolved]
    if len(disks) != 1:
        raise ProductionInstallError("lsblk did not return exactly the selected disk")
    disk = disks[0]
    children = list(disk.get("children") or [])
    if not children:
        partition_re = re.compile(re.escape(resolved) + r"p(\d+)$")
        children = [
            item for item in devices
            if item.get("type") == "part"
            and isinstance(item.get("path"), str)
            and partition_re.fullmatch(item["path"])
        ]
    parts = []
    for child in children:
        path = child.get("path")
        match = re.search(r"p(\d+)$", path or "")
        if child.get("type") == "part" and match:
            parts.append({
                "number": int(match.group(1)),
                "path": path,
                "size_bytes": int(child.get("size") or 0),
                "partuuid": str(child.get("partuuid") or "").lower(),
                "fstype": str(child.get("fstype") or ""),
                "uuid": str(child.get("uuid") or ""),
            })
    mounts = _normalize_mounts(disk.get("mountpoints"))
    mounts += [m for child in children for m in _normalize_mounts(child.get("mountpoints"))]
    return {
        "requested_path": authority_path,
        "resolved_path": resolved,
        "model": str(disk.get("model") or "").strip(),
        "serial": str(disk.get("serial") or "").strip(),
        "wwn": str(disk.get("wwn") or "").strip(),
        "size_bytes": int(disk.get("size") or 0),
        "transport": str(disk.get("tran") or "").strip(),
        "filesystem": disk.get("fstype"),
        "partition_table": disk.get("pttype"),
        "mountpoints": mounts,
        "mounted": bool(mounts),
        "signatures": [],
        "partitions": parts,
    }


def _findmnt(target: str) -> str:
    result = _run(["findmnt", "--nofsroot", "-rn", "-o", "SOURCE", target])
    return result.stdout.decode("utf-8").strip()


def observe_live(contract: dict[str, Any] | None = None) -> dict[str, Any]:
    contract = contract or load_contract()
    return {
        "target": _disk_observation(contract["target_identity"]["exact_by_id"]),
        "protected": _disk_observation(contract["protected_disks"][0]["by_id"]),
        "root_source": _findmnt("/"),
        "efi_source": _findmnt("/boot/efi"),
    }


def verify_persist_mount(mount_root: str, mapper: str) -> None:
    persist = str(PurePosixPath(mount_root, "persist"))
    result = _run([
        "findmnt", "--nofsroot", "-rn", "-o", "SOURCE,FSTYPE,FSROOT",
        "--mountpoint", persist,
    ])
    fields = result.stdout.decode("utf-8", "replace").strip().split()
    if len(fields) != 3:
        raise ProductionInstallError("target /persist is not a uniquely resolved mount")
    source, fstype, fsroot = fields
    if source != mapper or fstype != "btrfs" or fsroot != "/@persist":
        raise ProductionInstallError("target /persist is not the encrypted @persist subvolume")


def verify_no_hidden_target_signatures(target_authority: str) -> None:
    _require_by_id(target_authority, "target signature authority")
    result = _run(["wipefs", "--no-act", "--json", target_authority])
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProductionInstallError("invalid JSON from wipefs signature check") from exc
    signatures = payload.get("signatures")
    if not isinstance(signatures, list):
        raise ProductionInstallError("wipefs signature check returned an unexpected shape")
    if signatures:
        raise ProductionInstallError("Seagate target is not blank: wipefs found signatures")


def verify_source(flake_source: str, expected_revision: str | None = None) -> str:
    path = Path(flake_source)
    if not path.is_absolute():
        raise ProductionInstallError("flake source must be absolute")
    head = _run(["git", "-C", str(path), "rev-parse", "HEAD"]).stdout.decode().strip()
    if SOURCE_REVISION_RE.fullmatch(head) is None:
        raise ProductionInstallError("flake source is not bound to an exact Git revision")
    dirty = _run(["git", "-C", str(path), "status", "--porcelain"]).stdout
    if dirty:
        raise ProductionInstallError("flake source must be clean before a production install")
    if expected_revision is not None and head != expected_revision:
        raise ProductionInstallError("flake source revision mismatch")
    return head


def verify_install_artifact_environment(artifact: dict[str, Any]) -> None:
    artifact = validate_install_artifact(artifact)
    image = _run(["docker", "image", "inspect", "--format", "{{.Id}}", artifact["nix_image"]]).stdout.decode().strip()
    if image != artifact["nix_image"]:
        raise ProductionInstallError("pinned Nix image identity mismatch")
    _run(["docker", "volume", "inspect", artifact["nix_volume"]])
    checks = [
        ("-x", f"{artifact['system_path']}/sw/bin/nixos-install"),
        ("-x", f"{artifact['system_path']}/sw/bin/mkfs.btrfs"),
        ("-x", f"{artifact['system_path']}/sw/bin/btrfs"),
        ("-e", f"{artifact['system_path']}/etc/systemd/system/heim-pc-firstboot-credentials.service"),
    ]
    for mode, path in checks:
        _run([
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{artifact['nix_volume']}:/nix:ro",
            "--entrypoint", f"{artifact['system_path']}/sw/bin/test",
            artifact["nix_image"], mode, path,
        ])


def verify_scratch_state(mapper_name: str) -> None:
    for raw in (MOUNT_ROOT, BTRFS_STAGE_ROOT):
        path = Path(raw)
        if path.is_symlink():
            raise ProductionInstallError(f"scratch path is a symlink: {raw}")
        if path.exists() and not path.is_dir():
            raise ProductionInstallError(f"scratch path is not a directory: {raw}")
        if path.exists() and _run(["mountpoint", "-q", raw], check=False).returncode == 0:
            raise ProductionInstallError(f"scratch path is already mounted: {raw}")
    mapper = Path("/dev/mapper") / mapper_name
    if mapper.exists() or mapper.is_symlink():
        raise ProductionInstallError(f"LUKS mapper already exists: {mapper}")


def efi_nvram_digest() -> str:
    return hashlib.sha256(_run(["efibootmgr", "-v"]).stdout).hexdigest()


def verify_installed_target(artifact: dict[str, Any]) -> None:
    artifact = validate_install_artifact(artifact)
    root = Path(MOUNT_ROOT)
    profile = root / "nix/var/nix/profiles/system"
    if not profile.is_symlink():
        raise ProductionInstallError("installed target system profile link is missing")
    generation = os.readlink(profile)
    if os.path.isabs(generation) or "/" in generation or generation in ("", ".", ".."):
        raise ProductionInstallError("installed target system profile generation link is unsafe")
    generation_link = profile.parent / generation
    if not generation_link.is_symlink():
        raise ProductionInstallError("installed target system generation link is missing")
    target = os.readlink(generation_link)
    if target != artifact["system_path"]:
        raise ProductionInstallError("installed target system profile does not point to exact closure")
    closure_root = root / artifact["system_path"].lstrip("/")
    service = closure_root / "etc/systemd/system/heim-pc-firstboot-credentials.service"
    if not service.exists() and not service.is_symlink():
        raise ProductionInstallError("installed exact closure lacks firstboot credential service")
    boot = root / "boot"
    if not ((boot / "EFI/systemd/systemd-bootx64.efi").is_file() or (boot / "EFI/BOOT/BOOTX64.EFI").is_file()):
        raise ProductionInstallError("systemd-boot files are missing from the Seagate ESP")


def execute_plan(plan: dict[str, Any], *, confirmation: str | None, credential_hash_file: Path, observer=observe_live) -> dict[str, Any]:
    validate_confirmation(plan, confirmation)
    if os.geteuid() != 0:
        raise ProductionInstallError("production apply requires root")
    contract = load_contract()
    artifact = validate_install_artifact(plan.get("install_artifact"))
    if sha256_json(artifact) != plan.get("install_artifact_sha256"):
        raise ProductionInstallError("install artifact digest no longer matches the reviewed plan")
    if artifact["source_revision"] != plan.get("source_revision"):
        raise ProductionInstallError("install artifact revision no longer matches the reviewed plan")
    source_revision = verify_source(plan["flake_source"], artifact["source_revision"])
    verify_install_artifact_environment(artifact)
    verify_scratch_state(contract["topology"]["luks"]["mapper_name"])
    pre_now = validate_preflight(observer(contract), contract)
    verify_no_hidden_target_signatures(contract["target_identity"]["exact_by_id"])
    if protected_fingerprint(pre_now["protected"]) != plan["protected_pre_fingerprint"]:
        raise ProductionInstallError("live protected WD preimage differs from the reviewed plan")
    hash_bytes = read_credential_hash(credential_hash_file)
    first = getpass.getpass("LUKS passphrase: ", stream=sys.stderr)
    second = getpass.getpass("Repeat LUKS passphrase: ", stream=sys.stderr)
    if not first or first != second:
        raise ProductionInstallError("LUKS passphrase confirmation mismatch")
    secret = first.encode("utf-8")

    # Final race-closing gate immediately before the first destructive command.
    final_pre = validate_preflight(observer(contract), contract)
    verify_no_hidden_target_signatures(contract["target_identity"]["exact_by_id"])
    verify_scratch_state(contract["topology"]["luks"]["mapper_name"])
    if protected_fingerprint(final_pre["protected"]) != plan["protected_pre_fingerprint"]:
        raise ProductionInstallError("protected WD changed after interactive authorization")
    nvram_before = efi_nvram_digest()

    completed_effects: list[str] = []
    credential_receipt: dict[str, Any] | None = None
    failure: BaseException | None = None
    try:
        for command in plan["commands"]:
            _run(command["argv"], input_bytes=secret if command.get("secret_binding") else None)
            completed_effects.append(command["effect"])
        verify_installed_target(artifact)
        verify_persist_mount(MOUNT_ROOT, f"/dev/mapper/{contract['topology']['luks']['mapper_name']}")
        credential_receipt = stage_firstboot_credentials(mount_root=MOUNT_ROOT, source_revision=source_revision, hash_bytes=hash_bytes)
    except BaseException as exc:
        failure = exc
    finally:
        for command in plan["teardown_commands"]:
            _run(command["argv"], check=False)

    post = validate_protected_state(observer(contract), contract)
    if protected_fingerprint(post) != plan["protected_pre_fingerprint"]:
        raise ProductionInstallError("protected WD changed across production install")
    nvram_after = efi_nvram_digest()
    if nvram_after != nvram_before:
        raise ProductionInstallError("EFI/NVRAM state changed across production install")
    mapper = Path("/dev/mapper") / contract["topology"]["luks"]["mapper_name"]
    if mapper.exists() or mapper.is_symlink():
        raise ProductionInstallError("LUKS mapper remains open after teardown")
    if failure is not None:
        raise failure
    if credential_receipt is None:
        raise ProductionInstallError("credential staging did not complete")
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_receipt",
        "plan_sha256": plan["plan_sha256"],
        "install_artifact_sha256": plan["install_artifact_sha256"],
        "source_revision": source_revision,
        "system_path": artifact["system_path"],
        "target_authority": plan["target_authority"],
        "protected_post_fingerprint": protected_fingerprint(post),
        "completed_effects": completed_effects,
        "credential": credential_receipt,
        "efi_nvram_sha256_before": nvram_before,
        "efi_nvram_sha256_after": nvram_after,
        "efi_variables_touched": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation-json", type=Path)
    parser.add_argument("--flake-source", default=str(FLAKE_SOURCE))
    parser.add_argument("--install-artifact", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm")
    parser.add_argument("--credential-hash-file", type=Path)
    args = parser.parse_args(argv)
    try:
        contract = load_contract()
        artifact = load_install_artifact(args.install_artifact)
        observation = json.loads(args.observation_json.read_text()) if args.observation_json else observe_live(contract)
        verify_source(args.flake_source, artifact["source_revision"])
        if args.observation_json is None:
            verify_no_hidden_target_signatures(contract["target_identity"]["exact_by_id"])
        plan = compile_plan(
            observation,
            install_artifact=artifact,
            flake_source=args.flake_source,
            contract=contract,
        )
        if not args.apply:
            print(json.dumps(plan, indent=2, sort_keys=True))
            print(f"confirmation={confirmation_for(plan)}", file=sys.stderr)
            return 0
        if args.credential_hash_file is None:
            raise ProductionInstallError("--apply requires --credential-hash-file")
        receipt = execute_plan(plan, confirmation=args.confirm, credential_hash_file=args.credential_hash_file)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (ProductionInstallError, OSError, json.JSONDecodeError) as exc:
        print(f"nixos production install blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
