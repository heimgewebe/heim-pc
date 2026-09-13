#!/usr/bin/env python3
"""Guarded production installer for the isolated Heim-PC Seagate NixOS target.

The default mode is effect-free: observe, validate and compile a plan. Destructive
execution requires --apply plus a plan-hash-bound confirmation token. Kernel NVMe
names may appear only as observed resolution; mutation authority is the private exact
target by-id plus target-derived stable by-id partition paths.
"""
from __future__ import annotations

import argparse
import fcntl
import getpass
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "nixos" / "production" / "contract-v1.json"
FLAKE_SOURCE = ROOT / "nixos" / "system"
MOUNT_ROOT = "/mnt/heim-pc-nixos-production"
BTRFS_STAGE_ROOT = "/mnt/heim-pc-nixos-production-btrfs-stage"
CONFIRM_PREFIX = "APPLY-NIXOS-PRODUCTION:"
PINNED_NIX_IMAGE = "sha256:98edc6813218e179ce84587373e0b52d4aa58babae2d26b51fb01e7fdacf815f"
PINNED_NIX_IMAGE_TAG = "nixos/nix:2.35.2"
PINNED_NIX_IMAGE_REF = "nixos/nix@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c"
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
CANONICAL_MAIN_REMOTE = "https://github.com/heimgewebe/heim-pc.git"
READONLY_NIX_STORE = "local?root=/subject&read-only=true"
READONLY_NIX_FEATURES = "nix-command flakes read-only-local-store"
SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SYSTEM_PATH_RE = re.compile(r"^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-nixos-system-heim-pc-[A-Za-z0-9._+-]+$")
NIX_VOLUME_RE = re.compile(r"^heim-pc-nixos-production-[0-9a-f]{12,40}$")
KERNEL_NVME_RE = re.compile(r"^/dev/nvme\d+n\d+(?:p\d+)?$")
PARTLABEL_RE = re.compile(r"^[A-Z0-9_]{1,36}$")
FAT_LABEL_RE = re.compile(r"^[A-Z0-9_]{1,11}$")
EXT4_LABEL_RE = re.compile(r"^[A-Z0-9_]{1,16}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PRIVATE_STORAGE_IDENTITY_RELATIVE = PurePosixPath("persist/heim-pc/private-storage-identity.env")
INSTALL_ARTIFACT_AUTHORITIES = frozenset({"proof-only", "merged-main"})
MANAGED_BUILD_RECEIPT_SUFFIX = ".managed-build-receipt.json"
MANAGED_BUILD_RECEIPT_KIND = "heim_pc.nixos_managed_build_success_receipt"
MANAGED_BUILD_POLICY_RELATIVE = Path("config/managed-build.v1.json")
MANAGED_BUILD_ATTESTATION_SUFFIX = ".managed-build-attestation.json"
MANAGED_BUILD_ATTESTATION_REPOSITORY = "heimgewebe/heim-pc"
MANAGED_BUILD_ATTESTATION_WORKFLOW = "heimgewebe/heim-pc/.github/workflows/nixos-production-build-attest.yml"
MANAGED_BUILD_ATTESTATION_SOURCE_REF = "refs/heads/main"
MANAGED_BUILD_ATTESTATION_KIND = "heim_pc.nixos_independent_managed_build_attestation_verification"
MANAGED_BUILD_ATTESTATION_PREDICATE_TYPE = "https://heimgewebe.local/attestations/nixos-independent-managed-build/v1"
MANAGED_BUILD_ATTESTATION_PREDICATE_KIND = "heim_pc.nixos_independent_managed_rebuild_match"
INDEPENDENT_REBUILD_MATCH_FIELDS = (
    "schema_version", "kind", "source_revision", "system_path", "nix_volume",
    "nix_image", "profile", "source_authority", "closure_manifest_sha256",
    "closure_path_count",
)
GH_BIN = "/usr/bin/gh"
SEALED_TOOL_LAUNCHER = "/usr/bin/env"
CTR_BIN = "/usr/bin/ctr"
# Host-provided executables the apply path needs outside the reviewed plan argv.
APPLY_HOST_TOOLS = (
    GH_BIN,
    SEALED_TOOL_LAUNCHER,
    CTR_BIN,
    "/usr/bin/mksquashfs",
    "/usr/bin/chattr",
    "/usr/bin/lsattr",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/rm",
    "/usr/sbin/losetup",
    "docker",
    "efibootmgr",
    "findmnt",
    "git",
    "lsblk",
    "mountpoint",
    "systemctl",
    "wipefs",
)
SEALED_NIX_BASE = Path("/var/lib/heim-pc/nixos-production-seals")
VERIFIER_ARCHIVE_BASE = Path("/var/lib/heim-pc/nixos-production-verifiers")
CONTAINERD_SOCKET = Path("/run/containerd/containerd.sock")
CONTAINERD_VERIFIER_NAMESPACE_PREFIX = "heim-pc-nixos-verify-"
HOST_NIX_ROOT = Path("/nix")
PRODUCTION_APPLY_LOCK_DIR = Path("/run/heim-pc-nixos-production-locks")
PRODUCTION_APPLY_LOCK_OWNER_UID = 0
PRODUCTION_APPLY_LOCK_OWNER_GID = 0
PROTECTED_EFI_MOUNTPOINT = Path("/boot/efi")
# Linux _IOWR('X', 119/120, int), verified against /usr/include/linux/fs.h.
PROTECTED_EFI_FIFREEZE_IOCTL = 0xC0045877
PROTECTED_EFI_FITHAW_IOCTL = 0xC0045878
# The canonical managed cache suffix stays bound exactly; only the HOME prefix is
# host-relative, because the independent GitHub-hosted rebuild that authenticates a
# merged-main candidate emits the same receipt shape under the runner account.
MANAGED_NIX_STORE_ROOT_RE = re.compile(
    r"^/(?:home/[a-z_][a-z0-9_-]{0,31}|root)"
    r"/\.cache/heim-pc/managed-builds/nix/[0-9a-f]{64}/nix-store$"
)
YESCRYPT_RE = re.compile(r"^\$y\$j9T\$[./0-9A-Za-z]{22}\$[./0-9A-Za-z]{43}$")
CRYPT64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
YESCRYPT_SALT_LAST = frozenset(CRYPT64[:4])
YESCRYPT_CHECKSUM_LAST = frozenset(CRYPT64[:16])

_IDENTITY_SPEC = importlib.util.spec_from_file_location(
    "nixos_production_identity", Path(__file__).with_name("nixos_production_identity.py")
)
if _IDENTITY_SPEC is None or _IDENTITY_SPEC.loader is None:
    raise RuntimeError("cannot load production identity module")
storage_identity = importlib.util.module_from_spec(_IDENTITY_SPEC)
_IDENTITY_SPEC.loader.exec_module(storage_identity)


class ProductionInstallError(RuntimeError):
    pass


class ProtectedEfiThawError(ProductionInstallError):
    pass


PROTECTED_EFI_RECOVERY_MESSAGE = (
    "nixos production install RECOVERY ALARM: the protected fallback EFI filesystem "
    "could not be thawed safely; inspect /boot/efi before any retry"
)


POST_MUTATION_PUBLIC_MESSAGES = {
    "apply-failed-after-mutation-attempt": "nixos production install POST-MUTATION ALARM: destructive execution was attempted and the apply did not complete; inspect target and fallback before any retry",
    "credential-staging-incomplete": "nixos production install POST-MUTATION ALARM: credential staging did not complete; inspect installed target before any retry",
    "efi-nvram-changed": "nixos production install POST-MUTATION ALARM: EFI/NVRAM state changed; inspect firmware state before any retry",
    "efi-nvram-unverifiable": "nixos production install POST-MUTATION ALARM: EFI/NVRAM state could not be verified; inspect firmware state before any retry",
    "mapper-open-after-teardown": "nixos production install POST-MUTATION ALARM: encrypted mapper remains open after teardown; inspect mounts and mapper before any retry",
    "teardown-incomplete": "nixos production install POST-MUTATION ALARM: target teardown did not complete cleanly; inspect target mounts and mapper before any retry",
    "protected-fallback-changed": "nixos production install POST-MUTATION ALARM: protected fallback fingerprint changed; stop and inspect the fallback disk before any retry",
    "protected-fallback-unverifiable": "nixos production install POST-MUTATION ALARM: protected fallback state could not be verified; stop and inspect the fallback disk before any retry",
    "trusted-build-seal-teardown-incomplete": "nixos production install POST-MUTATION ALARM: the root-protected build seal could not be fully torn down; inspect /nix and the seal before any retry",
    "docker-quiesce-restore-incomplete": "nixos production install POST-MUTATION ALARM: the pre-apply Docker service state could not be restored safely; inspect Docker before any retry",
    "private-receipt-finalization-incomplete": "nixos production install POST-MUTATION ALARM: the reserved private success receipt could not be finalized safely; inspect target and receipt path before any retry",
    "protected-efi-thaw-incomplete": "nixos production install POST-MUTATION ALARM: the protected fallback EFI filesystem could not be thawed safely; inspect /boot/efi before any retry",
}


class PostMutationInstallError(ProductionInstallError):
    """Stable non-secret alarm after destructive execution has been attempted."""

    def __init__(self, code: str, *, private_evidence: dict[str, Any] | None = None):
        if code not in POST_MUTATION_PUBLIC_MESSAGES:
            raise ValueError("unknown post-mutation alarm code")
        self.code = code
        self.private_evidence = dict(private_evidence or {})
        super().__init__(code)


def canonical_json(value: Any) -> bytes:
    return storage_identity.canonical_json(value)


def sha256_json(value: Any) -> str:
    return storage_identity.sha256_json(value)


def load_contract(
    identity_path: Path, *, expected_revision: str, path: Path = CONTRACT_PATH
) -> dict[str, Any]:
    try:
        value = storage_identity.load_contract(
            path, identity_path, expected_revision=expected_revision
        )
    except storage_identity.IdentityContractError as exc:
        raise ProductionInstallError("production storage identity contract rejected") from exc
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
    if (
        topology.get("partition_table") != "gpt"
        or topology.get("partition_identity_policy")
        != "private-identity-contract-assigned-partuuid"
    ):
        raise ProductionInstallError("production GPT/PARTUUID policy mismatch")
    partitions = topology.get("partitions")
    if not isinstance(partitions, list) or len(partitions) != 3:
        raise ProductionInstallError("production topology must contain three partitions")
    partuuids = [str(item.get("partuuid", "")).lower() for item in partitions]
    if len(set(partuuids)) != 3 or any(not item for item in partuuids):
        raise ProductionInstallError("production PARTUUIDs must be unique and non-empty")
    labels = [item.get("label") for item in partitions]
    if (
        len(set(labels)) != 3
        or any(not isinstance(label, str) or PARTLABEL_RE.fullmatch(label) is None for label in labels)
    ):
        raise ProductionInstallError("production PARTLABELs must be canonical and unique")
    for partition in partitions:
        filesystem = partition.get("filesystem")
        filesystem_label = partition.get("filesystem_label")
        if filesystem == "vfat" and (
            not isinstance(filesystem_label, str)
            or FAT_LABEL_RE.fullmatch(filesystem_label) is None
        ):
            raise ProductionInstallError(
                "vfat filesystem label must fit the FAT 11-character limit"
            )
        if filesystem == "ext4" and (
            not isinstance(filesystem_label, str)
            or EXT4_LABEL_RE.fullmatch(filesystem_label) is None
        ):
            raise ProductionInstallError(
                "ext4 filesystem label must fit the ext4 16-character limit"
            )
    boot = value.get("boot", {})
    if (
        boot.get("own_esp_required") is not True
        or boot.get("shared_esp_forbidden") is not True
        or boot.get("touch_efi_variables") is not False
    ):
        raise ProductionInstallError("isolated boot policy mismatch")
    mutation = value.get("mutation_policy", {})
    if not all(mutation.get(key) is True for key in (
        "target_by_id_only", "kernel_device_name_forbidden",
        "protected_disk_pre_post_identity_required",
        "protected_disk_partition_table_pre_post_required",
        "target_identity_must_be_fully_captured",
    )):
        raise ProductionInstallError("production mutation policy is incomplete")
    binding = value.get("identity_binding")
    if (
        not isinstance(binding, dict)
        or binding.get("source_revision") != expected_revision
        or not isinstance(binding.get("public_contract_sha256"), str)
        or not isinstance(binding.get("identity_contract_sha256"), str)
    ):
        raise ProductionInstallError("production identity binding is incomplete")
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
    if value.get("source_authority") not in INSTALL_ARTIFACT_AUTHORITIES:
        raise ProductionInstallError("install artifact source authority is invalid")
    bundle_sha = value.get("source_bundle_sha256")
    if not isinstance(bundle_sha, str) or re.fullmatch(r"[0-9a-f]{64}", bundle_sha) is None:
        raise ProductionInstallError("install artifact source bundle digest is invalid")
    closure_sha = value.get("closure_manifest_sha256")
    if not isinstance(closure_sha, str) or re.fullmatch(r"[0-9a-f]{64}", closure_sha) is None:
        raise ProductionInstallError("install artifact closure manifest digest is invalid")
    closure_count = value.get("closure_path_count")
    if isinstance(closure_count, bool) or not isinstance(closure_count, int) or closure_count < 1:
        raise ProductionInstallError("install artifact closure path count is invalid")
    return dict(value)


def load_install_artifact(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProductionInstallError(f"cannot read production install artifact: {exc}") from exc
    return validate_install_artifact(value)




def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def managed_build_receipt_path(artifact_path: Path) -> Path:
    artifact_path = Path(artifact_path)
    if not artifact_path.is_absolute() or os.path.normpath(str(artifact_path)) != str(artifact_path):
        raise ProductionInstallError("install artifact path must be canonical and absolute")
    return Path(str(artifact_path) + MANAGED_BUILD_RECEIPT_SUFFIX)


def managed_policy_sha256_for_source(flake_source: str) -> str:
    result = _run(["git", "-C", flake_source, "rev-parse", "--show-toplevel"])
    try:
        root_text = result.stdout.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as exc:
        raise ProductionInstallError("managed-build source root is not UTF-8") from exc
    root = Path(root_text)
    if not root.is_absolute() or os.path.normpath(str(root)) != str(root):
        raise ProductionInstallError("managed-build source root is not canonical")
    policy_path = root / MANAGED_BUILD_POLICY_RELATIVE
    try:
        info = policy_path.lstat()
    except OSError as exc:
        raise ProductionInstallError("managed-build policy is unavailable from exact source") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ProductionInstallError("managed-build policy is not a single-link regular file")
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProductionInstallError("managed-build policy is invalid") from exc
    return sha256_json(policy)


def validate_managed_build_receipt(
    value: Any,
    artifact: dict[str, Any],
    *,
    expected_policy_sha256: str,
    artifact_file_sha256: str | None = None,
) -> dict[str, Any]:
    artifact = validate_install_artifact(artifact)
    if not isinstance(value, dict):
        raise ProductionInstallError("managed-build success receipt must be an object")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != MANAGED_BUILD_RECEIPT_KIND
        or value.get("status") != "success"
        or value.get("returncode") != 0
        or value.get("tool") != "nix"
        or value.get("profile") != "nixos-production-prepare"
        or value.get("source_revision") != artifact["source_revision"]
        or value.get("docker_volume") != artifact["nix_volume"]
        or not isinstance(value.get("store_root"), str)
        or MANAGED_NIX_STORE_ROOT_RE.fullmatch(value["store_root"]) is None
        or value.get("system_closure") != artifact["system_path"]
        or value.get("closure_manifest_sha256") != artifact["closure_manifest_sha256"]
        or value.get("closure_path_count") != artifact["closure_path_count"]
        or value.get("artifact_json_sha256") != sha256_json(artifact)
        or value.get("managed_policy_sha256") != expected_policy_sha256
        or value.get("store_budget_stop_triggered") is not False
        or value.get("store_scan_error_detected") is not False
        or value.get("runtime_timeout_triggered") is not False
        or value.get("container_cleanup_verified") is not True
        or value.get("lifecycle_fence_cleared") is not True
    ):
        raise ProductionInstallError("managed-build success receipt does not authorize this artifact")
    for name in (
        "managed_plan_sha256",
        "managed_policy_sha256",
        "managed_receipt_sha256",
        "artifact_file_sha256",
        "artifact_json_sha256",
    ):
        if not isinstance(value.get(name), str) or re.fullmatch(r"[0-9a-f]{64}", value[name]) is None:
            raise ProductionInstallError("managed-build success receipt digest is invalid")
    if artifact_file_sha256 is not None and value["artifact_file_sha256"] != artifact_file_sha256:
        raise ProductionInstallError("managed-build success receipt artifact file digest mismatch")
    stop = value.get("store_stop_threshold_bytes")
    hard = value.get("store_hard_limit_bytes")
    maximum = value.get("store_max_observed_bytes")
    if (
        type(stop) is not int
        or type(hard) is not int
        or type(maximum) is not int
        or not 0 < stop < hard
        or maximum < 0
        or maximum >= stop
    ):
        raise ProductionInstallError("managed-build success receipt store budget evidence is invalid")
    return json.loads(json.dumps(value))


def load_managed_build_receipt(
    path: Path,
    artifact: dict[str, Any],
    *,
    expected_policy_sha256: str,
    artifact_path: Path,
) -> dict[str, Any]:
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ProductionInstallError("managed-build success receipt is not a private single-link regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
        artifact_file_sha256 = _sha256_file(artifact_path)
    except ProductionInstallError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise ProductionInstallError("cannot load managed-build success receipt") from exc
    return validate_managed_build_receipt(
        value,
        artifact,
        expected_policy_sha256=expected_policy_sha256,
        artifact_file_sha256=artifact_file_sha256,
    )


def managed_build_attestation_path(artifact_path: Path) -> Path:
    artifact_path = Path(artifact_path)
    if not artifact_path.is_absolute() or os.path.normpath(str(artifact_path)) != str(artifact_path):
        raise ProductionInstallError("install artifact path must be canonical and absolute")
    return Path(str(artifact_path) + MANAGED_BUILD_ATTESTATION_SUFFIX)


def verify_independent_rebuild_candidate(
    candidate_path: Path, independent_path: Path, *, candidate_receipt_path: Path, flake_source: str
) -> dict[str, Any]:
    candidate_path = Path(candidate_path)
    independent_path = Path(independent_path)
    candidate_receipt_path = Path(candidate_receipt_path)
    if candidate_receipt_path != managed_build_receipt_path(candidate_path):
        raise ProductionInstallError("candidate managed-build receipt path is not canonical")
    candidate = load_install_artifact(candidate_path)
    independent = load_install_artifact(independent_path)
    if candidate["source_authority"] != "merged-main" or independent["source_authority"] != "merged-main":
        raise ProductionInstallError("independent rebuild comparison requires merged-main artifacts")
    mismatches = [
        field for field in INDEPENDENT_REBUILD_MATCH_FIELDS
        if candidate.get(field) != independent.get(field)
    ]
    if mismatches:
        raise ProductionInstallError(
            "independent managed rebuild differs from candidate: " + ", ".join(mismatches)
        )
    policy_sha256 = managed_policy_sha256_for_source(flake_source)
    candidate_receipt = load_managed_build_receipt(
        candidate_receipt_path, candidate,
        expected_policy_sha256=policy_sha256, artifact_path=candidate_path,
    )
    receipt_path = managed_build_receipt_path(independent_path)
    receipt = load_managed_build_receipt(
        receipt_path, independent,
        expected_policy_sha256=policy_sha256, artifact_path=independent_path,
    )
    semantic_identity = {field: candidate[field] for field in INDEPENDENT_REBUILD_MATCH_FIELDS}
    return {
        "schema_version": 1,
        "kind": MANAGED_BUILD_ATTESTATION_PREDICATE_KIND,
        "candidate_artifact_sha256": _sha256_file(candidate_path),
        "candidate_receipt_sha256": _sha256_file(candidate_receipt_path),
        "candidate_managed_receipt_sha256": candidate_receipt["managed_receipt_sha256"],
        "independent_artifact_sha256": _sha256_file(independent_path),
        "independent_receipt_sha256": _sha256_file(receipt_path),
        "independent_managed_receipt_sha256": receipt["managed_receipt_sha256"],
        "managed_policy_sha256": policy_sha256,
        "semantic_identity_sha256": sha256_json(semantic_identity),
        "excluded_nonsemantic_fields": ["source_bundle_sha256"],
    }


def _attestation_bundle_sha256(path: Path) -> str:
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise ProductionInstallError("managed-build attestation bundle is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > 2 * 1024 * 1024
    ):
        raise ProductionInstallError("managed-build attestation bundle file is not trusted")
    return _sha256_file(path)


def managed_build_attestation_verify_argv(
    artifact_path: Path, bundle_path: Path, source_revision: str
) -> list[str]:
    if SOURCE_REVISION_RE.fullmatch(source_revision) is None:
        raise ProductionInstallError("managed-build attestation source revision is invalid")
    for path, label in ((Path(artifact_path), "artifact"), (Path(bundle_path), "bundle")):
        if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
            raise ProductionInstallError(f"managed-build attestation {label} path is not canonical")
    return [
        GH_BIN, "attestation", "verify", str(artifact_path),
        "--repo", MANAGED_BUILD_ATTESTATION_REPOSITORY,
        "--bundle", str(bundle_path),
        "--signer-workflow", MANAGED_BUILD_ATTESTATION_WORKFLOW,
        "--signer-digest", source_revision,
        "--source-digest", source_revision,
        "--source-ref", MANAGED_BUILD_ATTESTATION_SOURCE_REF,
        "--predicate-type", MANAGED_BUILD_ATTESTATION_PREDICATE_TYPE,
        "--deny-self-hosted-runners",
        "--format", "json",
    ]


def verify_managed_build_attestation(
    artifact_path: Path,
    bundle_path: Path,
    source_revision: str,
    *,
    expected_policy_sha256: str,
    runner=None,
) -> dict[str, Any]:
    artifact_path = Path(artifact_path)
    bundle_path = Path(bundle_path)
    artifact = load_install_artifact(artifact_path)
    artifact_sha256 = _sha256_file(artifact_path)
    bundle_sha256 = _attestation_bundle_sha256(bundle_path)
    if not isinstance(expected_policy_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_policy_sha256) is None:
        raise ProductionInstallError("managed-build attestation policy digest is invalid")
    argv = managed_build_attestation_verify_argv(artifact_path, bundle_path, source_revision)
    run_command = _run if runner is None else runner
    result = run_command(argv)
    try:
        output = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        raise ProductionInstallError("managed-build attestation verifier returned invalid JSON") from exc
    if not isinstance(output, list) or len(output) != 1 or not isinstance(output[0], dict):
        raise ProductionInstallError("managed-build attestation verifier returned no unique verified attestation")
    verification_result = output[0].get("verificationResult")
    statement = verification_result.get("statement") if isinstance(verification_result, dict) else None
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    required_predicate = {
        "schema_version", "kind", "candidate_artifact_sha256",
        "candidate_receipt_sha256", "candidate_managed_receipt_sha256",
        "independent_artifact_sha256", "independent_receipt_sha256",
        "independent_managed_receipt_sha256", "managed_policy_sha256",
        "semantic_identity_sha256", "excluded_nonsemantic_fields",
    }
    if not isinstance(predicate, dict) or set(predicate) != required_predicate:
        raise ProductionInstallError("managed-build attestation predicate is invalid")
    semantic_identity = {field: artifact[field] for field in INDEPENDENT_REBUILD_MATCH_FIELDS}
    if (
        predicate.get("schema_version") != 1
        or predicate.get("kind") != MANAGED_BUILD_ATTESTATION_PREDICATE_KIND
        or predicate.get("candidate_artifact_sha256") != artifact_sha256
        or predicate.get("managed_policy_sha256") != expected_policy_sha256
        or predicate.get("semantic_identity_sha256") != sha256_json(semantic_identity)
        or predicate.get("excluded_nonsemantic_fields") != ["source_bundle_sha256"]
    ):
        raise ProductionInstallError("managed-build attestation predicate does not bind current artifact")
    for field in (
        "candidate_artifact_sha256", "candidate_receipt_sha256",
        "candidate_managed_receipt_sha256", "independent_artifact_sha256",
        "independent_receipt_sha256", "independent_managed_receipt_sha256",
        "managed_policy_sha256", "semantic_identity_sha256",
    ):
        if not isinstance(predicate.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", predicate[field]) is None:
            raise ProductionInstallError("managed-build attestation predicate digest is invalid")
    return {
        "schema_version": 1,
        "kind": MANAGED_BUILD_ATTESTATION_KIND,
        "artifact_sha256": artifact_sha256,
        "attestation_bundle_sha256": bundle_sha256,
        "verifier_argv_sha256": sha256_json(argv),
        "predicate_sha256": sha256_json(predicate),
        "candidate_receipt_sha256": predicate["candidate_receipt_sha256"],
        "candidate_managed_receipt_sha256": predicate["candidate_managed_receipt_sha256"],
        "independent_artifact_sha256": predicate["independent_artifact_sha256"],
        "independent_receipt_sha256": predicate["independent_receipt_sha256"],
        "independent_managed_receipt_sha256": predicate["independent_managed_receipt_sha256"],
        "managed_policy_sha256": predicate["managed_policy_sha256"],
        "semantic_identity_sha256": predicate["semantic_identity_sha256"],
        "verified_attestation_count": 1,
    }


def validate_managed_build_attestation_summary(
    value: Any, *, expected_artifact_sha256: str, expected_policy_sha256: str
) -> dict[str, Any]:
    required = {
        "schema_version", "kind", "artifact_sha256", "attestation_bundle_sha256",
        "verifier_argv_sha256", "predicate_sha256", "candidate_receipt_sha256",
        "candidate_managed_receipt_sha256", "independent_artifact_sha256",
        "independent_receipt_sha256", "independent_managed_receipt_sha256",
        "managed_policy_sha256", "semantic_identity_sha256", "verified_attestation_count",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ProductionInstallError("managed-build attestation verification summary is invalid")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != MANAGED_BUILD_ATTESTATION_KIND
        or value.get("artifact_sha256") != expected_artifact_sha256
        or value.get("managed_policy_sha256") != expected_policy_sha256
        or isinstance(value.get("verified_attestation_count"), bool)
        or not isinstance(value.get("verified_attestation_count"), int)
        or value["verified_attestation_count"] != 1
    ):
        raise ProductionInstallError("managed-build attestation verification summary is invalid")
    for field in required - {"schema_version", "kind", "verified_attestation_count"}:
        if not isinstance(value.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None:
            raise ProductionInstallError("managed-build attestation verification digest is invalid")
    return json.loads(json.dumps(value))


def verify_managed_build_binding(plan: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    artifact_path_raw = plan.get("install_artifact_path")
    if not isinstance(artifact_path_raw, str):
        raise ProductionInstallError("reviewed plan lacks install artifact path")
    artifact_path = Path(artifact_path_raw)
    observed_artifact = load_install_artifact(artifact_path)
    if sha256_json(observed_artifact) != sha256_json(artifact):
        raise ProductionInstallError("install artifact file changed after planning")
    policy_sha256 = managed_policy_sha256_for_source(str(plan.get("flake_source", "")))
    if policy_sha256 != plan.get("managed_policy_sha256"):
        raise ProductionInstallError("managed-build policy changed after planning")
    receipt_path = managed_build_receipt_path(artifact_path)
    receipt = load_managed_build_receipt(
        receipt_path, artifact, expected_policy_sha256=policy_sha256, artifact_path=artifact_path,
    )
    if sha256_json(receipt) != plan.get("managed_build_receipt_sha256"):
        raise ProductionInstallError("managed-build success receipt changed after planning")
    if receipt != plan.get("managed_build_receipt"):
        raise ProductionInstallError("managed-build success receipt no longer matches reviewed plan")
    if artifact["source_authority"] == "merged-main":
        verification = verify_managed_build_attestation(
            artifact_path,
            managed_build_attestation_path(artifact_path),
            artifact["source_revision"],
            expected_policy_sha256=policy_sha256,
        )
        if verification != plan.get("managed_build_attestation_verification"):
            raise ProductionInstallError("independent managed-build attestation changed after planning")
        if verification["candidate_receipt_sha256"] != _sha256_file(receipt_path):
            raise ProductionInstallError("independent attestation does not authenticate local managed-build receipt bytes")
        if verification["candidate_managed_receipt_sha256"] != receipt["managed_receipt_sha256"]:
            raise ProductionInstallError("independent attestation does not authenticate local managed-build receipt identity")
        if verification["attestation_bundle_sha256"] != plan.get("managed_build_attestation_sha256"):
            raise ProductionInstallError("independent managed-build attestation digest changed after planning")
    return receipt


def _sealed_nix_paths(artifact: dict[str, Any], artifact_file_sha256: str) -> dict[str, Path]:
    artifact = validate_install_artifact(artifact)
    if not isinstance(artifact_file_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", artifact_file_sha256) is None:
        raise ProductionInstallError("sealed Nix artifact digest is invalid")
    seal_id = f"{artifact['source_revision']}-{artifact_file_sha256[:16]}"
    root = SEALED_NIX_BASE / seal_id
    return {
        "seal_root": root,
        "image": root / "nix.squashfs",
        "mountpoint": HOST_NIX_ROOT,
    }


def _verifier_archive_path(artifact: dict[str, Any], artifact_file_sha256: str) -> Path:
    artifact = validate_install_artifact(artifact)
    if not isinstance(artifact_file_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", artifact_file_sha256) is None:
        raise ProductionInstallError("verifier artifact digest is invalid")
    name = f"{artifact['source_revision']}-{artifact_file_sha256[:16]}.docker.tar"
    return VERIFIER_ARCHIVE_BASE / name


def _verifier_namespace(artifact_file_sha256: str) -> str:
    if not isinstance(artifact_file_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", artifact_file_sha256) is None:
        raise ProductionInstallError("verifier artifact digest is invalid")
    return CONTAINERD_VERIFIER_NAMESPACE_PREFIX + artifact_file_sha256[:16]


def _sealed_tool_argv(artifact: dict[str, Any], tool: str, args: list[str]) -> list[str]:
    artifact = validate_install_artifact(artifact)
    if tool not in {"mkfs.btrfs", "btrfs", "nixos-install"}:
        raise ProductionInstallError("sealed Nix tool is not allowlisted")
    executable = f"{artifact['system_path']}/sw/bin/{tool}"
    path_value = f"{artifact['system_path']}/sw/bin:{TRUSTED_PATH}"
    return [SEALED_TOOL_LAUNCHER, f"PATH={path_value}", executable, *args]


def _require_by_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/dev/disk/by-id/") or os.path.normpath(value) != value:
        raise ProductionInstallError(f"{label} must be a canonical /dev/disk/by-id path")
    if KERNEL_NVME_RE.fullmatch(value):
        raise ProductionInstallError(f"{label} must not use a kernel NVMe name")
    return value


def _production_apply_lock_identity(plan: dict[str, Any]) -> tuple[dict[str, Any], str]:
    target_authority = _require_by_id(
        plan.get("target_authority"), "production apply lock target"
    )
    preflight = plan.get("preflight")
    if not isinstance(preflight, dict):
        raise ProductionInstallError("production apply lock lacks preflight identity")
    target = preflight.get("target")
    if not isinstance(target, dict) or target.get("requested_path") != target_authority:
        raise ProductionInstallError("production apply lock target/preflight binding mismatch")
    model = target.get("model")
    serial = target.get("serial")
    wwn = target.get("wwn")
    transport = target.get("transport")
    size_bytes = target.get("size_bytes")
    if (
        not isinstance(model, str) or not model
        or not isinstance(serial, str) or not serial
        or not isinstance(wwn, str) or not wwn
        or not isinstance(transport, str) or not transport
        or isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes <= 0
    ):
        raise ProductionInstallError("production apply lock physical target identity is incomplete")
    physical_identity = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_target_physical_identity",
        "model": model,
        "serial": serial,
        "wwn": wwn,
        "size_bytes": size_bytes,
        "transport": transport,
    }
    return physical_identity, sha256_json(physical_identity)


def acquire_production_apply_lock(plan: dict[str, Any]) -> dict[str, Any]:
    _physical_identity, target_sha256 = _production_apply_lock_identity(plan)
    if (
        os.geteuid() != PRODUCTION_APPLY_LOCK_OWNER_UID
        or os.getegid() != PRODUCTION_APPLY_LOCK_OWNER_GID
    ):
        raise ProductionInstallError("production apply lock requires root authority")
    directory = PRODUCTION_APPLY_LOCK_DIR
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ProductionInstallError("production apply lock directory is unavailable") from exc
    try:
        linked_directory = directory.lstat()
    except OSError as exc:
        raise ProductionInstallError("production apply lock directory is unavailable") from exc
    if (
        stat.S_ISLNK(linked_directory.st_mode)
        or not stat.S_ISDIR(linked_directory.st_mode)
        or linked_directory.st_uid != PRODUCTION_APPLY_LOCK_OWNER_UID
        or linked_directory.st_gid != PRODUCTION_APPLY_LOCK_OWNER_GID
        or stat.S_IMODE(linked_directory.st_mode) != 0o700
    ):
        raise ProductionInstallError("production apply lock directory identity is unsafe")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd: int | None = None
    lock_fd: int | None = None
    locked = False
    try:
        directory_fd = os.open(directory, directory_flags)
        opened_directory = os.fstat(directory_fd)
        linked_directory_after = directory.lstat()
        if (
            opened_directory.st_dev != linked_directory_after.st_dev
            or opened_directory.st_ino != linked_directory_after.st_ino
            or opened_directory.st_mode != linked_directory_after.st_mode
            or opened_directory.st_uid != linked_directory_after.st_uid
            or opened_directory.st_gid != linked_directory_after.st_gid
            or not stat.S_ISDIR(opened_directory.st_mode)
            or stat.S_IMODE(opened_directory.st_mode) != 0o700
        ):
            raise ProductionInstallError("production apply lock directory identity changed")

        lock_name = f"target-{target_sha256}.lock"
        lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_fd = os.open(lock_name, lock_flags, 0o600, dir_fd=directory_fd)
        opened = os.fstat(lock_fd)
        linked = os.stat(lock_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != PRODUCTION_APPLY_LOCK_OWNER_UID
            or opened.st_gid != PRODUCTION_APPLY_LOCK_OWNER_GID
            or stat.S_IMODE(opened.st_mode) != 0o600
            or linked.st_dev != opened.st_dev
            or linked.st_ino != opened.st_ino
            or linked.st_mode != opened.st_mode
            or linked.st_uid != opened.st_uid
            or linked.st_gid != opened.st_gid
            or linked.st_nlink != opened.st_nlink
        ):
            raise ProductionInstallError("production apply lock file identity is unsafe")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProductionInstallError(
                "another production apply already holds the selected target lock"
            ) from exc
        locked = True
        linked_after_lock = os.stat(lock_name, dir_fd=directory_fd, follow_symlinks=False)
        opened_after_lock = os.fstat(lock_fd)
        if (
            linked_after_lock.st_dev != opened_after_lock.st_dev
            or linked_after_lock.st_ino != opened_after_lock.st_ino
            or linked_after_lock.st_mode != opened_after_lock.st_mode
            or linked_after_lock.st_uid != opened_after_lock.st_uid
            or linked_after_lock.st_gid != opened_after_lock.st_gid
            or linked_after_lock.st_nlink != 1
        ):
            raise ProductionInstallError("production apply lock identity changed after acquisition")
        return {
            "fd": lock_fd,
            "directory_fd": directory_fd,
            "target_physical_identity_sha256": target_sha256,
        }
    except ProductionInstallError:
        if lock_fd is not None:
            try:
                if locked:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(lock_fd)
            except OSError:
                pass
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        raise
    except OSError as exc:
        if lock_fd is not None:
            try:
                if locked:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(lock_fd)
            except OSError:
                pass
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        raise ProductionInstallError("cannot acquire production apply target lock") from exc


def release_production_apply_lock(lock: dict[str, Any]) -> None:
    lock_fd = lock.pop("fd", None)
    directory_fd = lock.pop("directory_fd", None)
    if type(lock_fd) is int:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(lock_fd)
        except OSError:
            pass
    if type(directory_fd) is int:
        try:
            os.close(directory_fd)
        except OSError:
            pass


def acquire_protected_efi_freeze(expected_source: str) -> dict[str, Any]:
    if not isinstance(expected_source, str) or KERNEL_NVME_RE.fullmatch(expected_source) is None:
        raise ProductionInstallError("protected EFI freeze source is invalid")
    if os.geteuid() != 0:
        raise ProductionInstallError("protected EFI freeze requires root authority")
    mountpoint = PROTECTED_EFI_MOUNTPOINT
    if _findmnt(str(mountpoint)) != expected_source:
        raise ProductionInstallError("protected EFI mount changed before freeze")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(mountpoint, flags)
    except OSError as exc:
        raise ProductionInstallError("protected EFI mount cannot be opened for freeze") from exc
    frozen = False
    try:
        opened = os.fstat(fd)
        linked = os.stat(mountpoint, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(linked.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_mode != linked.st_mode
        ):
            raise ProductionInstallError("protected EFI mount identity changed before freeze")
        if _findmnt(str(mountpoint)) != expected_source:
            raise ProductionInstallError("protected EFI mount source changed before freeze")
        try:
            fcntl.ioctl(fd, PROTECTED_EFI_FIFREEZE_IOCTL, 0)
        except OSError as exc:
            raise ProductionInstallError("protected EFI filesystem cannot be frozen safely") from exc
        frozen = True
        opened_after = os.fstat(fd)
        linked_after = os.stat(mountpoint, follow_symlinks=False)
        if (
            opened_after.st_dev != opened.st_dev
            or opened_after.st_ino != opened.st_ino
            or opened_after.st_mode != opened.st_mode
            or linked_after.st_dev != opened.st_dev
            or linked_after.st_ino != opened.st_ino
            or linked_after.st_mode != opened.st_mode
            or _findmnt(str(mountpoint)) != expected_source
        ):
            raise ProductionInstallError("protected EFI mount identity changed during freeze")
        return {
            "fd": fd,
            "device": opened.st_dev,
            "inode": opened.st_ino,
            "mode": opened.st_mode,
            "source": expected_source,
        }
    except BaseException as exc:
        thaw_failure: BaseException | None = None
        if frozen:
            try:
                fcntl.ioctl(fd, PROTECTED_EFI_FITHAW_IOCTL, 0)
            except BaseException as thaw_exc:
                thaw_failure = thaw_exc
        try:
            os.close(fd)
        except OSError:
            pass
        if thaw_failure is not None:
            raise ProtectedEfiThawError(
                "protected EFI freeze acquisition failed and thaw is incomplete"
            ) from thaw_failure
        raise exc


def release_protected_efi_freeze(freeze: dict[str, Any]) -> None:
    fd = freeze.pop("fd", None)
    if type(fd) is not int:
        raise ProductionInstallError("protected EFI freeze handle is invalid")
    identity_failure: BaseException | None = None
    thaw_failure: BaseException | None = None
    try:
        try:
            current = os.fstat(fd)
            if (
                current.st_dev != freeze.get("device")
                or current.st_ino != freeze.get("inode")
                or current.st_mode != freeze.get("mode")
                or not stat.S_ISDIR(current.st_mode)
            ):
                identity_failure = ProductionInstallError(
                    "protected EFI frozen filesystem identity changed"
                )
        except BaseException as exc:
            identity_failure = exc
        try:
            fcntl.ioctl(fd, PROTECTED_EFI_FITHAW_IOCTL, 0)
        except BaseException as exc:
            thaw_failure = exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if thaw_failure is not None:
        raise ProtectedEfiThawError("protected EFI filesystem could not be thawed safely") from thaw_failure
    if identity_failure is not None:
        raise ProductionInstallError("protected EFI frozen filesystem identity was not stable") from identity_failure


def _partition_by_role(contract: dict[str, Any], role: str) -> dict[str, Any]:
    matches = [item for item in contract["topology"]["partitions"] if item.get("role") == role]
    if len(matches) != 1:
        raise ProductionInstallError(f"topology must contain exactly one {role} partition")
    return matches[0]


def _partuuid_path(partition: dict[str, Any]) -> str:
    return f"/dev/disk/by-partuuid/{str(partition['partuuid']).lower()}"


def _partlabel_path(partition: dict[str, Any]) -> str:
    label = partition.get("label")
    if not isinstance(label, str) or PARTLABEL_RE.fullmatch(label) is None:
        raise ProductionInstallError("target PARTLABEL is invalid")
    return f"/dev/disk/by-partlabel/{label}"


def _target_partition_path(target_authority: str, partition: dict[str, Any]) -> str:
    target = _require_by_id(target_authority, "target partition authority")
    number = partition.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise ProductionInstallError("target partition number is invalid")
    return f"{target}-part{number}"


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


def validate_protected_state(observation: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
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
    if (
        protected.get("partition_table") != "gpt"
        or storage_identity.GPT_GUID_RE.fullmatch(str(protected.get("gpt_disk_guid", ""))) is None
        or isinstance(protected.get("logical_sector_size"), bool)
        or not isinstance(protected.get("logical_sector_size"), int)
        or protected["logical_sector_size"] <= 0
    ):
        raise ProductionInstallError("protected WD GPT identity is incomplete")
    protected_signatures = _normalize_signature_records(
        protected.get("signatures"), "protected WD"
    )
    efi_content_sha256 = observation.get("efi_content_sha256")
    if not isinstance(efi_content_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", efi_content_sha256) is None:
        raise ProductionInstallError("protected EFI content digest is missing or invalid")
    observed_parts = protected.get("partitions")
    if not isinstance(observed_parts, list):
        raise ProductionInstallError("protected partition observation missing")
    observed_by_number = {item.get("number"): item for item in observed_parts}
    if len(observed_by_number) != len(protected_contract["partition_table_fingerprint"]):
        raise ProductionInstallError("protected partition count mismatch")
    expected_paths: dict[str, str] = {}
    live_fingerprint: list[dict[str, Any]] = []
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
        if (
            isinstance(actual.get("start_sector"), bool)
            or not isinstance(actual.get("start_sector"), int)
            or isinstance(actual.get("end_sector"), bool)
            or not isinstance(actual.get("end_sector"), int)
            or actual["start_sector"] < 0
            or actual["end_sector"] < actual["start_sector"]
            or storage_identity.GPT_GUID_RE.fullmatch(str(actual.get("type_guid", ""))) is None
            or not isinstance(actual.get("partlabel"), str)
            or not isinstance(actual.get("partflags"), str)
        ):
            raise ProductionInstallError(
                f"protected partition {expected['number']} GPT fingerprint is incomplete"
            )
        path = actual.get("path")
        if not isinstance(path, str) or not KERNEL_NVME_RE.fullmatch(path):
            raise ProductionInstallError(f"protected partition {expected['number']} observed path is invalid")
        expected_paths[expected["role"]] = path
        partition_signatures = _normalize_signature_records(
            actual.get("signatures"), f"protected partition {expected['number']}"
        )
        live_fingerprint.append({
            "number": expected["number"],
            "role": expected["role"],
            "size_bytes": actual["size_bytes"],
            "start_sector": actual["start_sector"],
            "end_sector": actual["end_sector"],
            "partuuid": str(actual["partuuid"]).lower(),
            "type_guid": str(actual["type_guid"]).lower(),
            "partlabel": actual["partlabel"],
            "partflags": actual["partflags"],
            "fstype": actual["fstype"],
            "uuid": str(actual["uuid"]),
            "signatures": partition_signatures,
        })
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
        "partition_table": "gpt",
        "gpt_disk_guid": str(protected["gpt_disk_guid"]).lower(),
        "logical_sector_size": protected["logical_sector_size"],
        "signatures": protected_signatures,
        "partition_table_fingerprint": live_fingerprint,
        "root_source": observation["root_source"],
        "efi_source": observation["efi_source"],
        "efi_content_sha256": efi_content_sha256,
    }


def validate_preflight(observation: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
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


def closure_manifest_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise ProductionInstallError("Nix closure path-info must be a non-empty object")
    entries: list[dict[str, Any]] = []
    for path in sorted(value):
        details = value[path]
        if not isinstance(path, str) or not path.startswith("/nix/store/") or not isinstance(details, dict):
            raise ProductionInstallError("Nix closure path-info contains an invalid store entry")
        nar_hash = details.get("narHash")
        nar_size = details.get("narSize")
        references = details.get("references")
        if not isinstance(nar_hash, str) or re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", nar_hash) is None:
            raise ProductionInstallError("Nix closure path-info contains an invalid narHash")
        if isinstance(nar_size, bool) or not isinstance(nar_size, int) or nar_size < 0:
            raise ProductionInstallError("Nix closure path-info contains an invalid narSize")
        if not isinstance(references, list) or any(not isinstance(item, str) or not item.startswith("/nix/store/") for item in references):
            raise ProductionInstallError("Nix closure path-info contains invalid references")
        entries.append({
            "path": path,
            "narHash": nar_hash,
            "narSize": nar_size,
            "references": sorted(references),
        })
    material = {"schema_version": 1, "entries": entries}
    return {
        "closure_manifest_sha256": sha256_json(material),
        "closure_path_count": len(entries),
    }


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
    install_artifact_path: Path,
    managed_build_receipt: dict[str, Any],
    managed_policy_sha256: str,
    flake_source: str,
    contract: dict[str, Any],
    managed_build_attestation_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    artifact = validate_install_artifact(install_artifact)
    artifact_path = Path(install_artifact_path)
    if not artifact_path.is_absolute() or os.path.normpath(str(artifact_path)) != str(artifact_path):
        raise ProductionInstallError("install artifact path must be canonical and absolute")
    managed_receipt = validate_managed_build_receipt(
        managed_build_receipt, artifact, expected_policy_sha256=managed_policy_sha256
    )
    source_revision = artifact["source_revision"]
    attestation_verification = None
    if artifact["source_authority"] == "merged-main":
        if managed_build_attestation_verification is None:
            raise ProductionInstallError("merged-main artifact requires independent managed-build attestation")
        attestation_verification = validate_managed_build_attestation_summary(
            managed_build_attestation_verification,
            expected_artifact_sha256=managed_receipt["artifact_file_sha256"],
            expected_policy_sha256=managed_policy_sha256,
        )
    elif managed_build_attestation_verification is not None:
        raise ProductionInstallError("proof-only artifact must not carry production attestation authority")
    sealed_paths = _sealed_nix_paths(artifact, managed_receipt["artifact_file_sha256"])
    verifier_archive = _verifier_archive_path(artifact, managed_receipt["artifact_file_sha256"])
    verifier_namespace = _verifier_namespace(managed_receipt["artifact_file_sha256"])
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
        {"effect": "efi-filesystem", "argv": ["mkfs.fat", "-F", "32", "-n", efi["filesystem_label"], _target_partition_path(target, efi)]},
        {"effect": "recovery-filesystem", "argv": ["mkfs.ext4", "-F", "-L", recovery["filesystem_label"], _target_partition_path(target, recovery)]},
        {"effect": "luks-format", "argv": ["cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--uuid", encrypted["partuuid"], "--key-file", "-", _target_partition_path(target, encrypted)], "secret_binding": "luks-passphrase-v1"},
        {"effect": "luks-open", "argv": ["cryptsetup", "open", "--type", "luks2", "--key-file", "-", _target_partition_path(target, encrypted), mapper_name], "secret_binding": "luks-passphrase-v1"},
        {
            "effect": "btrfs-filesystem",
            "argv": _sealed_tool_argv(
                artifact, "mkfs.btrfs", ["-f", "-L", btrfs["label"], mapper]
            ),
        },
        {"effect": "btrfs-stage-mount", "argv": ["mount", mapper, BTRFS_STAGE_ROOT]},
    ]
    for name, _mountpoint in _subvolume_mounts(contract):
        commands.append({
            "effect": "btrfs-subvolume-create",
            "argv": _sealed_tool_argv(
                artifact, "btrfs", ["subvolume", "create", f"{BTRFS_STAGE_ROOT}/{name}"]
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
        commands.append({"effect": "surface-mount", "argv": ["mount", _target_partition_path(target, partition), dest]})
    commands.append({
        "effect": "nixos-install",
        "argv": _sealed_tool_argv(
            artifact, "nixos-install",
            ["--root", MOUNT_ROOT, "--system", artifact["system_path"], "--no-channel-copy", "--no-root-password"],
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
        "identity_contract_sha256": contract["identity_binding"]["identity_contract_sha256"],
        "install_artifact_sha256": sha256_json(artifact),
        "install_artifact_path": str(artifact_path),
        "install_artifact": artifact,
        "managed_policy_sha256": managed_policy_sha256,
        "managed_build_receipt_sha256": sha256_json(managed_receipt),
        "managed_build_receipt": managed_receipt,
        "managed_build_attestation_required": artifact["source_authority"] == "merged-main",
        "managed_build_attestation_sha256": (
            attestation_verification["attestation_bundle_sha256"]
            if attestation_verification is not None else None
        ),
        "managed_build_attestation_verification": attestation_verification,
        "source_revision": source_revision,
        "source_authority": artifact["source_authority"],
        "flake_source": flake,
        "system_path": artifact["system_path"],
        "sealed_nix_image": str(sealed_paths["image"]),
        "verifier_image_archive": str(verifier_archive),
        "containerd_verifier_namespace": verifier_namespace,
        "host_nix_root": str(HOST_NIX_ROOT),
        "trusted_build_seal_required": artifact["source_authority"] == "merged-main",
        "docker_quiesce_required": artifact["source_authority"] == "merged-main",
        "target_authority": target,
        "protected_authority": contract["protected_disks"][0]["by_id"],
        "preflight": preflight,
        "protected_pre_fingerprint": protected_fingerprint(preflight["protected"]),
        "partition_binding_verification_required": True,
        "commands": commands,
        "teardown_commands": teardown,
        "credential_staging_required": True,
        "efi_variables_must_remain_untouched": True,
        "execution_authorized": False,
    }
    return {**material, "plan_sha256": sha256_json(material)}


def plan_summary(_plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_plan_summary",
        "execution_authorized": False,
        "private_plan_redacted": True,
        "private_hardware_identity_redacted": True,
    }


def write_private_plan(path: Path, plan: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ProductionInstallError("refusing to overwrite private production plan")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        _write_all_fd(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ProductionInstallError("refusing to overwrite private production plan") from exc
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _private_receipt_reservation_marker() -> bytes:
    return (json.dumps({
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_receipt_reservation",
        "status": "reserved",
    }, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _private_receipt_reservation_valid(reservation: dict[str, Any]) -> None:
    path = reservation.get("path")
    fd = reservation.get("fd")
    parent_fd = reservation.get("parent_fd")
    if not isinstance(path, Path) or type(fd) is not int or type(parent_fd) is not int:
        raise ProductionInstallError("private production receipt reservation is invalid")
    try:
        opened = os.fstat(fd)
        linked = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        opened_parent = os.fstat(parent_fd)
        linked_parent = os.lstat(path.parent)
    except OSError as exc:
        raise ProductionInstallError("private production receipt reservation identity is unavailable") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_uid != os.geteuid()
        or opened.st_gid != os.getegid()
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_dev != reservation.get("device")
        or opened.st_ino != reservation.get("inode")
        or opened.st_mode != reservation.get("mode")
        or opened.st_uid != reservation.get("uid")
        or opened.st_gid != reservation.get("gid")
        or opened.st_nlink != reservation.get("nlink")
        or linked.st_dev != opened.st_dev
        or linked.st_ino != opened.st_ino
        or linked.st_mode != opened.st_mode
        or linked.st_uid != opened.st_uid
        or linked.st_gid != opened.st_gid
        or linked.st_nlink != opened.st_nlink
        or not stat.S_ISREG(linked.st_mode)
        or not stat.S_ISDIR(opened_parent.st_mode)
        or opened_parent.st_nlink < 1
        or opened_parent.st_uid != os.geteuid()
        or opened_parent.st_gid != os.getegid()
        or (stat.S_IMODE(opened_parent.st_mode) & 0o022) != 0
        or opened_parent.st_dev != reservation.get("parent_device")
        or opened_parent.st_ino != reservation.get("parent_inode")
        or opened_parent.st_mode != reservation.get("parent_mode")
        or opened_parent.st_uid != reservation.get("parent_uid")
        or opened_parent.st_gid != reservation.get("parent_gid")
        or opened_parent.st_nlink != reservation.get("parent_nlink")
        or linked_parent.st_dev != opened_parent.st_dev
        or linked_parent.st_ino != opened_parent.st_ino
        or linked_parent.st_mode != opened_parent.st_mode
        or linked_parent.st_uid != opened_parent.st_uid
        or linked_parent.st_gid != opened_parent.st_gid
        or linked_parent.st_nlink != opened_parent.st_nlink
        or not stat.S_ISDIR(linked_parent.st_mode)
    ):
        raise ProductionInstallError("private production receipt reservation identity changed")


def _private_receipt_target_matches_reservation(reservation: dict[str, Any]) -> bool:
    path = reservation.get("path")
    fd = reservation.get("fd")
    parent_fd = reservation.get("parent_fd")
    if not isinstance(path, Path) or type(fd) is not int or type(parent_fd) is not int:
        return False
    try:
        opened = os.fstat(fd)
        linked = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        opened_parent = os.fstat(parent_fd)
    except OSError:
        return False
    return (
        stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(linked.st_mode)
        and stat.S_ISDIR(opened_parent.st_mode)
        and opened.st_dev == reservation.get("device")
        and opened.st_ino == reservation.get("inode")
        and linked.st_dev == opened.st_dev
        and linked.st_ino == opened.st_ino
        and opened_parent.st_dev == reservation.get("parent_device")
        and opened_parent.st_ino == reservation.get("parent_inode")
    )


def _private_receipt_reservation_marker_valid(reservation: dict[str, Any]) -> None:
    marker = _private_receipt_reservation_marker()
    fd = reservation["fd"]
    try:
        opened = os.fstat(fd)
        content = os.pread(fd, len(marker) + 1, 0)
    except OSError as exc:
        raise ProductionInstallError("private production receipt reservation marker is unavailable") from exc
    if opened.st_size != len(marker) or content != marker:
        raise ProductionInstallError("private production receipt reservation marker changed")


def reserve_private_receipt(path: Path) -> dict[str, Any]:
    path = Path(os.path.abspath(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    try:
        parent_fd = os.open(path.parent, parent_flags)
    except OSError as exc:
        raise ProductionInstallError("private production receipt directory is unavailable") from exc
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
    except FileExistsError as exc:
        os.close(parent_fd)
        raise ProductionInstallError("refusing to overwrite private production receipt") from exc
    except OSError as exc:
        os.close(parent_fd)
        raise ProductionInstallError("cannot reserve private production receipt") from exc
    reservation: dict[str, Any] | None = None
    try:
        os.fchmod(fd, 0o600)
        opened = os.fstat(fd)
        opened_parent = os.fstat(parent_fd)
        reservation = {
            "path": path,
            "fd": fd,
            "parent_fd": parent_fd,
            "device": opened.st_dev,
            "inode": opened.st_ino,
            "mode": opened.st_mode,
            "uid": opened.st_uid,
            "gid": opened.st_gid,
            "nlink": opened.st_nlink,
            "parent_device": opened_parent.st_dev,
            "parent_inode": opened_parent.st_ino,
            "parent_mode": opened_parent.st_mode,
            "parent_uid": opened_parent.st_uid,
            "parent_gid": opened_parent.st_gid,
            "parent_nlink": opened_parent.st_nlink,
        }
        _private_receipt_reservation_valid(reservation)
        marker = _private_receipt_reservation_marker()
        _write_all_fd(fd, marker)
        os.fsync(fd)
        _private_receipt_reservation_valid(reservation)
        _private_receipt_reservation_marker_valid(reservation)
        os.fsync(parent_fd)
        return reservation
    except BaseException:
        try:
            if reservation is not None and _private_receipt_target_matches_reservation(reservation):
                os.unlink(path.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
        except OSError:
            pass
        os.close(fd)
        os.close(parent_fd)
        raise


def _close_private_receipt_reservation(reservation: dict[str, Any]) -> None:
    fd = reservation.pop("fd", None)
    parent_fd = reservation.pop("parent_fd", None)
    if type(fd) is int:
        os.close(fd)
    if type(parent_fd) is int:
        os.close(parent_fd)


def discard_private_receipt_reservation(reservation: dict[str, Any]) -> None:
    try:
        _private_receipt_reservation_valid(reservation)
        if not _private_receipt_target_matches_reservation(reservation):
            raise ProductionInstallError("private production receipt reservation identity changed")
        os.unlink(reservation["path"].name, dir_fd=reservation["parent_fd"])
        if os.fstat(reservation["fd"]).st_nlink != 0:
            raise ProductionInstallError("private production receipt reservation cleanup was not verified")
        os.fsync(reservation["parent_fd"])
    except OSError as exc:
        raise ProductionInstallError("cannot discard private production receipt reservation") from exc
    finally:
        _close_private_receipt_reservation(reservation)


def preserve_private_receipt_reservation(reservation: dict[str, Any]) -> None:
    try:
        _private_receipt_reservation_valid(reservation)
        _private_receipt_reservation_marker_valid(reservation)
        os.fsync(reservation["fd"])
        os.fsync(reservation["parent_fd"])
        _private_receipt_reservation_valid(reservation)
        _private_receipt_reservation_marker_valid(reservation)
    except OSError as exc:
        raise ProductionInstallError("cannot preserve private production receipt reservation") from exc
    finally:
        _close_private_receipt_reservation(reservation)


def _restore_private_receipt_reservation_marker(reservation: dict[str, Any]) -> None:
    _private_receipt_reservation_valid(reservation)
    marker = _private_receipt_reservation_marker()
    fd = reservation["fd"]
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        _write_all_fd(fd, marker)
        os.fsync(fd)
        _private_receipt_reservation_valid(reservation)
        _private_receipt_reservation_marker_valid(reservation)
        os.fsync(reservation["parent_fd"])
    except OSError as exc:
        raise ProductionInstallError(
            "cannot restore private production receipt reservation marker"
        ) from exc


def _invalidate_private_receipt_reservation(reservation: dict[str, Any]) -> None:
    fd = reservation.get("fd")
    parent_fd = reservation.get("parent_fd")
    path = reservation.get("path")
    if type(fd) is not int or type(parent_fd) is not int or not isinstance(path, Path):
        raise ProductionInstallError("private production receipt reservation is invalid")
    try:
        # Destroy any syntactically valid success payload through the already-held
        # descriptor even if the pathname or its parent was raced after reservation.
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.fsync(fd)
        if _private_receipt_target_matches_reservation(reservation):
            os.unlink(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
    except OSError as exc:
        raise ProductionInstallError(
            "cannot invalidate private production receipt after finalization failure"
        ) from exc
    finally:
        _close_private_receipt_reservation(reservation)


def finalize_private_receipt(reservation: dict[str, Any], receipt: dict[str, Any]) -> None:
    _private_receipt_reservation_valid(reservation)
    _private_receipt_reservation_marker_valid(reservation)
    payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = reservation["fd"]
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        _write_all_fd(fd, payload)
        os.fsync(fd)
        _private_receipt_reservation_valid(reservation)
        if os.fstat(fd).st_size != len(payload) or os.pread(fd, len(payload) + 1, 0) != payload:
            raise ProductionInstallError("private production receipt final payload is invalid")
        os.fsync(reservation["parent_fd"])
    except (OSError, ProductionInstallError) as exc:
        try:
            _restore_private_receipt_reservation_marker(reservation)
        except (OSError, ProductionInstallError) as restore_exc:
            try:
                _invalidate_private_receipt_reservation(reservation)
            except (OSError, ProductionInstallError) as invalidate_exc:
                raise ProductionInstallError(
                    "private production receipt finalization failed and reservation recovery is incomplete"
                ) from invalidate_exc
            raise ProductionInstallError(
                "private production receipt finalization failed; reservation was invalidated"
            ) from restore_exc
        raise ProductionInstallError("cannot finalize private production receipt") from exc
    else:
        _close_private_receipt_reservation(reservation)

def write_private_receipt(path: Path, receipt: dict[str, Any]) -> None:
    reservation = reserve_private_receipt(path)
    try:
        finalize_private_receipt(reservation, receipt)
    except BaseException:
        if "fd" in reservation:
            try:
                discard_private_receipt_reservation(reservation)
            except BaseException:
                pass
        raise


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
    return {"schema_version": 1, "source_revision": source_revision, "password_hash_sha256": digest, "staged": True}


def _private_storage_identity_values(contract: dict[str, Any]) -> dict[str, str]:
    values = {
        "efi_partuuid": str(_partition_by_role(contract, "efi-system-partition")["partuuid"]).lower(),
        "recovery_partuuid": str(_partition_by_role(contract, "recovery-surface")["partuuid"]).lower(),
        "encrypted_partuuid": str(_partition_by_role(contract, "encrypted-system")["partuuid"]).lower(),
        "mapper_name": str(contract["topology"]["luks"]["mapper_name"]),
    }
    uuids = [values["efi_partuuid"], values["recovery_partuuid"], values["encrypted_partuuid"]]
    if any(UUID_RE.fullmatch(value) is None for value in uuids) or len(set(uuids)) != 3:
        raise ProductionInstallError("private boot PARTUUID identity is invalid")
    if values["mapper_name"] != "heimpc-nixos-crypt":
        raise ProductionInstallError("private boot mapper identity is invalid")
    return values


def _private_storage_identity_bytes(contract: dict[str, Any]) -> bytes:
    values = _private_storage_identity_values(contract)
    return (
        "schema_version=1\n"
        f"efi_partuuid={values['efi_partuuid']}\n"
        f"recovery_partuuid={values['recovery_partuuid']}\n"
        f"encrypted_partuuid={values['encrypted_partuuid']}\n"
        f"mapper_name={values['mapper_name']}\n"
    ).encode("ascii")


def _private_storage_identity_path(mount_root: str) -> Path:
    root = Path(mount_root)
    if not root.is_absolute() or os.path.normpath(str(root)) != str(root):
        raise ProductionInstallError("private storage mount root is invalid")
    return root / str(PRIVATE_STORAGE_IDENTITY_RELATIVE)


def stage_private_storage_identity(*, mount_root: str, contract: dict[str, Any]) -> dict[str, Any]:
    destination = _private_storage_identity_path(mount_root)
    persist = Path(mount_root) / "persist"
    try:
        persist_info = persist.lstat()
    except OSError as exc:
        raise ProductionInstallError("target /persist mount is missing for private storage identity") from exc
    if stat.S_ISLNK(persist_info.st_mode) or not stat.S_ISDIR(persist_info.st_mode):
        raise ProductionInstallError("target /persist mount is unsafe for private storage identity")
    parent = destination.parent
    parent.mkdir(mode=0o700, exist_ok=True)
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise ProductionInstallError("private storage identity directory is unsafe")
    os.chmod(parent, 0o700)
    if destination.exists() or destination.is_symlink():
        raise ProductionInstallError("private storage identity staging refuses existing destination")
    payload = _private_storage_identity_bytes(contract)
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
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return {"schema_version": 1, "identity_sha256": hashlib.sha256(payload).hexdigest(), "staged": True}


def _read_private_storage_identity(*, mount_root: str, contract: dict[str, Any]) -> dict[str, str]:
    path = _private_storage_identity_path(mount_root)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ProductionInstallError("private storage identity is unavailable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ProductionInstallError("private storage identity file is unsafe")
        payload = os.read(fd, 4097)
        if len(payload) > 4096 or os.read(fd, 1):
            raise ProductionInstallError("private storage identity file is unexpectedly large")
    finally:
        os.close(fd)
    expected = _private_storage_identity_bytes(contract)
    if payload != expected:
        raise ProductionInstallError("private storage identity file does not match reviewed contract")
    return _private_storage_identity_values(contract)


def _private_luks_token(contract: dict[str, Any]) -> str:
    values = _private_storage_identity_values(contract)
    return f"rd.luks.name={values['encrypted_partuuid']}={values['mapper_name']}"


def _nixos_loader_entries(mount_root: str) -> list[Path]:
    directory = Path(mount_root) / "boot/loader/entries"
    try:
        info = directory.lstat()
    except OSError as exc:
        raise ProductionInstallError("systemd-boot loader entry directory is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ProductionInstallError("systemd-boot loader entry directory is unsafe")
    result: list[Path] = []
    for path in sorted(directory.glob("*.conf")):
        linked = path.lstat()
        if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode) or linked.st_nlink != 1:
            raise ProductionInstallError("systemd-boot loader entry is unsafe")
        text = path.read_text(encoding="utf-8")
        if any(line == "sort-key nixos" for line in text.splitlines()):
            result.append(path)
    if not result:
        raise ProductionInstallError("no NixOS systemd-boot loader entries found")
    return result


def _loader_options_with_private_luks(text: str, expected_token: str, mapper_name: str) -> str:
    lines = text.splitlines()
    indexes = [index for index, line in enumerate(lines) if line.startswith("options ")]
    if len(indexes) != 1:
        raise ProductionInstallError("NixOS loader entry must contain exactly one options line")
    index = indexes[0]
    tokens = lines[index][len("options "):].split()
    kept: list[str] = []
    seen = 0
    suffix = "=" + mapper_name
    for token in tokens:
        if token.startswith("rd.luks.name=") and token.endswith(suffix):
            if token != expected_token or seen:
                raise ProductionInstallError("conflicting private LUKS token in loader entry")
            seen += 1
        else:
            kept.append(token)
    lines[index] = "options " + " ".join([*kept, expected_token])
    return "\n".join(lines) + "\n"


def bind_private_boot_entries(*, mount_root: str, contract: dict[str, Any]) -> None:
    _read_private_storage_identity(mount_root=mount_root, contract=contract)
    token = _private_luks_token(contract)
    mapper_name = contract["topology"]["luks"]["mapper_name"]
    for entry in _nixos_loader_entries(mount_root):
        updated = _loader_options_with_private_luks(entry.read_text(encoding="utf-8"), token, mapper_name)
        temporary_fd, temporary_name = tempfile.mkstemp(dir=entry.parent, prefix=f".{entry.name}.", suffix=".tmp")
        temporary = Path(temporary_name)
        try:
            mode = stat.S_IMODE(entry.lstat().st_mode)
            os.fchmod(temporary_fd, mode)
            _write_all_fd(temporary_fd, updated.encode("utf-8"))
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            os.replace(temporary, entry)
            directory_fd = os.open(entry.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            temporary.unlink(missing_ok=True)


def verify_private_luks_uuid(contract: dict[str, Any]) -> None:
    encrypted = _partition_by_role(contract, "encrypted-system")
    expected = _private_storage_identity_values(contract)["encrypted_partuuid"]
    path = _target_partition_path(contract["target_identity"]["exact_by_id"], encrypted)
    observed = _run(["cryptsetup", "luksUUID", path]).stdout.decode("utf-8", "strict").strip().lower()
    if observed != expected:
        raise ProductionInstallError("LUKS UUID does not match private encrypted partition identity")


def verify_private_boot_binding(*, mount_root: str, contract: dict[str, Any]) -> None:
    _read_private_storage_identity(mount_root=mount_root, contract=contract)
    verify_private_luks_uuid(contract)
    expected = _private_luks_token(contract)
    mapper_name = contract["topology"]["luks"]["mapper_name"]
    for entry in _nixos_loader_entries(mount_root):
        text = entry.read_text(encoding="utf-8")
        rewritten = _loader_options_with_private_luks(text, expected, mapper_name)
        if rewritten != text:
            raise ProductionInstallError("systemd-boot loader entry is not bound to private LUKS identity")


def _run(argv: list[str], *, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    command_env = {
        "PATH": TRUSTED_PATH,
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": "/",
        "SYSTEMD_COLORS": "0",
    }
    result = subprocess.run(
        argv, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, env=command_env,
    )
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


def _partition_start_sector(path: str) -> int:
    name = Path(path).name
    if not name or "/" in name:
        raise ProductionInstallError("partition path has no canonical kernel name")
    try:
        value = int((Path("/sys/class/block") / name / "start").read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise ProductionInstallError("cannot observe protected partition start sector") from exc
    if value < 0:
        raise ProductionInstallError("protected partition start sector is invalid")
    return value


def _normalize_signature_records(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ProductionInstallError(f"{label} signature inventory is invalid")
    normalized: list[dict[str, Any]] = []
    for record in value:
        if not isinstance(record, dict) or not record:
            raise ProductionInstallError(f"{label} signature inventory is invalid")
        clean: dict[str, Any] = {}
        for key, raw in record.items():
            if not isinstance(key, str) or not key or not isinstance(raw, (str, int, float, bool, type(None))):
                raise ProductionInstallError(f"{label} signature inventory is invalid")
            clean[key] = raw
        normalized.append(clean)
    return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))


def _wipefs_signatures(authority_path: str) -> list[dict[str, Any]]:
    _require_by_id(authority_path, "wipefs observation authority")
    payload = _json_command(["wipefs", "--no-act", "--json", authority_path])
    return _normalize_signature_records(payload.get("signatures"), authority_path)


def _directory_content_snapshot(root: Path) -> tuple[str, str]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        raise ProductionInstallError("protected EFI content root cannot be opened safely") from exc
    digest = hashlib.sha256()
    metadata = hashlib.sha256()
    directory_identities: dict[str, tuple[int, ...]] = {}

    def stable_identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
        )

    def bind_metadata(kind: bytes, relative: str, info: os.stat_result) -> None:
        metadata.update(kind + b"\0" + relative.encode("utf-8") + b"\0")
        metadata.update(
            (":".join(str(item) for item in stable_identity(info)) + "\0").encode("ascii")
        )

    def open_relative_directory(relative: str) -> int:
        current_fd = os.dup(root_fd)
        try:
            for component in PurePosixPath(relative).parts:
                next_fd = os.open(component, flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
                info = os.fstat(current_fd)
                if not stat.S_ISDIR(info.st_mode) or info.st_dev != root_device:
                    raise ProductionInstallError(
                        "protected EFI directory path changed while hashing"
                    )
            return current_fd
        except OSError as exc:
            os.close(current_fd)
            raise ProductionInstallError(
                "protected EFI directory cannot be re-opened safely"
            ) from exc
        except BaseException:
            os.close(current_fd)
            raise

    try:
        root_before = os.fstat(root_fd)
        if not stat.S_ISDIR(root_before.st_mode):
            raise ProductionInstallError("protected EFI content root is not a directory")
        root_device = root_before.st_dev
        root_identity = stable_identity(root_before)
        directory_identities[""] = root_identity
        bind_metadata(b"D", "", root_before)
        for dirpath, dirnames, filenames, dir_fd in os.fwalk(
            ".", topdown=True, follow_symlinks=False, dir_fd=root_fd
        ):
            dirnames.sort()
            filenames.sort()
            prefix = "" if dirpath == "." else dirpath.removeprefix("./")
            opened_dir = os.fstat(dir_fd)
            if not stat.S_ISDIR(opened_dir.st_mode) or opened_dir.st_dev != root_device:
                raise ProductionInstallError("protected EFI directory identity changed while hashing")
            opened_directory_identity = stable_identity(opened_dir)
            if prefix:
                directory_identities[prefix] = opened_directory_identity
                bind_metadata(b"D", prefix, opened_dir)
            elif opened_directory_identity != root_identity:
                raise ProductionInstallError("protected EFI content root changed while hashing")
            for name in dirnames:
                linked = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                if stat.S_ISLNK(linked.st_mode) or not stat.S_ISDIR(linked.st_mode) or linked.st_dev != root_device:
                    raise ProductionInstallError("protected EFI content contains unsafe directory entries")
                relative = str(PurePosixPath(prefix, name))
                digest.update(b"D\0" + relative.encode("utf-8") + b"\0")
            for name in filenames:
                linked_before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                if stat.S_ISLNK(linked_before.st_mode) or not stat.S_ISREG(linked_before.st_mode) or linked_before.st_dev != root_device:
                    raise ProductionInstallError("protected EFI content contains unsafe file entries")
                file_flags = os.O_RDONLY | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    file_flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(name, file_flags, dir_fd=dir_fd)
                except OSError as exc:
                    raise ProductionInstallError("protected EFI file cannot be opened safely") from exc
                try:
                    opened = os.fstat(fd)
                    before_identity = stable_identity(linked_before)
                    opened_identity = stable_identity(opened)
                    if opened_identity != before_identity or opened.st_dev != root_device or not stat.S_ISREG(opened.st_mode):
                        raise ProductionInstallError("protected EFI file identity changed before hashing")
                    relative = str(PurePosixPath(prefix, name))
                    bind_metadata(b"F", relative, opened)
                    digest.update(b"F\0" + relative.encode("utf-8") + b"\0")
                    digest.update(str(opened.st_size).encode("ascii") + b"\0")
                    remaining = opened.st_size
                    while remaining:
                        chunk = os.read(fd, min(1024 * 1024, remaining))
                        if not chunk:
                            raise ProductionInstallError("protected EFI file changed while hashing")
                        digest.update(chunk)
                        remaining -= len(chunk)
                    if os.read(fd, 1):
                        raise ProductionInstallError("protected EFI file exceeds observed size")
                    opened_after = os.fstat(fd)
                    linked_after = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                    if (
                        stable_identity(opened_after) != opened_identity
                        or stable_identity(linked_after) != opened_identity
                    ):
                        raise ProductionInstallError("protected EFI file identity changed while hashing")
                finally:
                    os.close(fd)
        for relative, expected_identity in sorted(directory_identities.items()):
            if not relative:
                current = os.fstat(root_fd)
            else:
                check_fd = open_relative_directory(relative)
                try:
                    current = os.fstat(check_fd)
                finally:
                    os.close(check_fd)
            if stable_identity(current) != expected_identity:
                raise ProductionInstallError(
                    "protected EFI directory changed after hashing"
                )
        root_after = os.fstat(root_fd)
        if stable_identity(root_after) != root_identity:
            raise ProductionInstallError("protected EFI content root changed while hashing")
        return digest.hexdigest(), metadata.hexdigest()
    finally:
        os.close(root_fd)


def _directory_content_sha256(root: Path) -> str:
    previous = _directory_content_snapshot(root)
    for _attempt in range(3):
        current = _directory_content_snapshot(root)
        if current == previous:
            return current[0]
        previous = current
    raise ProductionInstallError("protected EFI content did not stabilize while hashing")


def _disk_observation(authority_path: str) -> dict[str, Any]:
    _require_by_id(authority_path, "disk observation authority")
    if not os.path.islink(authority_path):
        raise ProductionInstallError(f"by-id authority is missing: {authority_path}")
    resolved = os.path.realpath(authority_path)
    data = _json_command([
        "lsblk", "--json", "--bytes", "--paths", "-o",
        "PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN,FSTYPE,UUID,PTTYPE,PTUUID,LOG-SEC,PARTUUID,PARTTYPE,PARTLABEL,PARTFLAGS,MOUNTPOINTS",
        resolved,
    ])
    devices = data.get("blockdevices") or []
    disks = [item for item in devices if item.get("type") == "disk" and item.get("path") == resolved]
    if len(disks) != 1:
        raise ProductionInstallError("lsblk did not return exactly the selected disk")
    disk = disks[0]
    logical_sector_size = int(disk.get("log-sec") or 0)
    if logical_sector_size <= 0:
        raise ProductionInstallError("disk logical sector size is unavailable")
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
            number = int(match.group(1))
            partition_authority = f"{authority_path}-part{number}"
            if not os.path.islink(partition_authority) or os.path.realpath(partition_authority) != path:
                raise ProductionInstallError(f"stable by-id alias for partition {number} is missing or mismatched")
            size_bytes = int(child.get("size") or 0)
            if size_bytes <= 0 or size_bytes % logical_sector_size != 0:
                raise ProductionInstallError("partition size is not sector aligned")
            start_sector = _partition_start_sector(path)
            sector_count = size_bytes // logical_sector_size
            parts.append({
                "number": number,
                "path": path,
                "size_bytes": size_bytes,
                "start_sector": start_sector,
                "end_sector": start_sector + sector_count - 1,
                "partuuid": str(child.get("partuuid") or "").lower(),
                "type_guid": str(child.get("parttype") or "").lower(),
                "partlabel": str(child.get("partlabel") or ""),
                "partflags": str(child.get("partflags") or ""),
                "fstype": str(child.get("fstype") or ""),
                "uuid": str(child.get("uuid") or ""),
                "signatures": _wipefs_signatures(partition_authority),
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
        "gpt_disk_guid": str(disk.get("ptuuid") or "").lower(),
        "logical_sector_size": logical_sector_size,
        "mountpoints": mounts,
        "mounted": bool(mounts),
        "signatures": _wipefs_signatures(authority_path),
        "partitions": parts,
    }


def _findmnt(target: str) -> str:
    result = _run([
        "findmnt", "--first-only", "--nofsroot", "-rn", "-o", "SOURCE",
        "--mountpoint", target
    ])
    source = result.stdout.decode("utf-8").strip()
    if not source or "\n" in source:
        raise ProductionInstallError(f"{target} did not resolve to one mount source")
    resolved = os.path.realpath(source)
    if KERNEL_NVME_RE.fullmatch(resolved) is None:
        raise ProductionInstallError(f"{target} is not backed by one direct NVMe partition")
    return resolved


def _verify_protected_by_id_aliases(contract: dict[str, Any]) -> None:
    protected = contract["protected_disks"][0]
    authority = _require_by_id(protected["by_id"], "protected disk by-id")
    resolved = os.path.realpath(authority)
    for alias in protected.get("verified_by_id_aliases", []):
        alias = _require_by_id(alias, "protected verified by-id alias")
        if not os.path.islink(alias) or os.path.realpath(alias) != resolved:
            raise ProductionInstallError("protected verified by-id alias no longer resolves to the WD")


def observe_live(contract: dict[str, Any]) -> dict[str, Any]:
    _verify_protected_by_id_aliases(contract)
    root_source = _findmnt("/")
    efi_source = _findmnt("/boot/efi")
    efi_content_sha256 = _directory_content_sha256(Path("/boot/efi"))
    if _findmnt("/boot/efi") != efi_source:
        raise ProductionInstallError("protected EFI mount changed while hashing content")
    return {
        "target": _disk_observation(contract["target_identity"]["exact_by_id"]),
        "protected": _disk_observation(contract["protected_disks"][0]["by_id"]),
        "root_source": root_source,
        "efi_source": efi_source,
        "efi_content_sha256": efi_content_sha256,
    }


def verify_partuuid_namespace_clear(contract: dict[str, Any]) -> None:
    for partition in contract["topology"]["partitions"]:
        alias = _partuuid_path(partition)
        if os.path.lexists(alias):
            raise ProductionInstallError(f"planned PARTUUID already exists before partitioning: {alias}")


def verify_partlabel_namespace_clear(contract: dict[str, Any]) -> None:
    for partition in contract["topology"]["partitions"]:
        alias = _partlabel_path(partition)
        if os.path.lexists(alias):
            raise ProductionInstallError(f"planned PARTLABEL already exists before partitioning: {alias}")


def verify_target_partition_bindings(contract: dict[str, Any]) -> dict[str, Any]:
    target_contract = contract["target_identity"]
    target = target_contract["exact_by_id"]
    observed = _disk_observation(target)
    expected_identity = (
        target_contract["exact_model"], target_contract["exact_serial"], target_contract["exact_wwn"],
        target_contract["exact_size_bytes"], target_contract["transport"],
    )
    if _identity_tuple(observed) != expected_identity:
        raise ProductionInstallError("Seagate target identity changed after partitioning")
    expected = sorted(contract["topology"]["partitions"], key=lambda item: item["number"])
    actual_parts = observed.get("partitions")
    if not isinstance(actual_parts, list) or len(actual_parts) != len(expected):
        raise ProductionInstallError("Seagate partition count mismatch after partitioning")
    actual_by_number = {item.get("number"): item for item in actual_parts}
    for partition in expected:
        number = partition["number"]
        actual = actual_by_number.get(number)
        if not isinstance(actual, dict) or str(actual.get("partuuid", "")).lower() != str(partition["partuuid"]).lower():
            raise ProductionInstallError(f"Seagate partition {number} PARTUUID mismatch after partitioning")
        if actual.get("partlabel") != partition["label"]:
            raise ProductionInstallError(f"Seagate partition {number} PARTLABEL mismatch after partitioning")
        actual_path = actual.get("path")
        if not isinstance(actual_path, str) or KERNEL_NVME_RE.fullmatch(actual_path) is None:
            raise ProductionInstallError(f"Seagate partition {number} observed path is invalid")
        for label, alias in (
            ("target by-id", _target_partition_path(target, partition)),
            ("PARTUUID", _partuuid_path(partition)),
            ("PARTLABEL", _partlabel_path(partition)),
        ):
            if not os.path.islink(alias):
                raise ProductionInstallError(f"Seagate partition {number} {label} alias is missing")
            if os.path.realpath(alias) != actual_path:
                raise ProductionInstallError(f"Seagate partition {number} {label} alias points outside the selected target")
    return observed


def verify_persist_mount(mount_root: str, mapper: str) -> None:
    persist = str(PurePosixPath(mount_root, "persist"))
    result = _run([
        "findmnt", "--first-only", "--nofsroot", "-rn", "-o", "SOURCE,FSTYPE,FSROOT",
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
    payload = _json_command(["wipefs", "--no-act", "--json", target_authority])
    signatures = payload.get("signatures")
    if not isinstance(signatures, list):
        raise ProductionInstallError("wipefs signature check returned an unexpected shape")
    if signatures:
        raise ProductionInstallError("Seagate target is not blank: wipefs found signatures")


def verify_promoted_main_revision(revision: str) -> None:
    if SOURCE_REVISION_RE.fullmatch(revision) is None:
        raise ProductionInstallError("promoted main revision must be exact 40-hex")
    result = _run([
        "git", "ls-remote", "--exit-code", CANONICAL_MAIN_REMOTE, "refs/heads/main"
    ])
    lines = [line.strip() for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    if lines != [f"{revision}\trefs/heads/main"]:
        raise ProductionInstallError("production apply source is not the current canonical GitHub main")


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


def _nix_volume_argv(artifact: dict[str, Any], args: list[str]) -> list[str]:
    return [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{artifact['nix_volume']}:/subject/nix:ro",
        "--entrypoint", "/nix/var/nix/profiles/default/bin/nix",
        artifact["nix_image"],
        "--extra-experimental-features", READONLY_NIX_FEATURES,
        "--store", READONLY_NIX_STORE,
        *args,
    ]


def verify_pinned_nix_image_identity(artifact: dict[str, Any]) -> dict[str, Any]:
    artifact = validate_install_artifact(artifact)
    raw = _run(["docker", "image", "inspect", artifact["nix_image"]]).stdout
    try:
        payload = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionInstallError("pinned Nix image metadata is invalid") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise ProductionInstallError("pinned Nix image metadata is ambiguous")
    image = payload[0]
    repo_tags = image.get("RepoTags")
    repo_digests = image.get("RepoDigests")
    if (
        image.get("Id") != artifact["nix_image"]
        or not isinstance(repo_tags, list)
        or PINNED_NIX_IMAGE_TAG not in repo_tags
        or not isinstance(repo_digests, list)
        or PINNED_NIX_IMAGE_REF not in repo_digests
    ):
        raise ProductionInstallError("pinned Nix image identity mismatch")
    return {
        "image_id": artifact["nix_image"],
        "image_tag": PINNED_NIX_IMAGE_TAG,
        "image_ref": PINNED_NIX_IMAGE_REF,
    }


def verify_install_artifact_environment(artifact: dict[str, Any]) -> None:
    artifact = validate_install_artifact(artifact)
    verify_pinned_nix_image_identity(artifact)
    _run(["docker", "volume", "inspect", artifact["nix_volume"]])
    path_info = _json_command(_nix_volume_argv(artifact, ["path-info", "--json", "--recursive", artifact["system_path"]]))
    closure = closure_manifest_metadata(path_info)
    if closure["closure_manifest_sha256"] != artifact["closure_manifest_sha256"] or closure["closure_path_count"] != artifact["closure_path_count"]:
        raise ProductionInstallError("prepared Nix closure metadata no longer matches the install artifact")
    _run(_nix_volume_argv(artifact, ["store", "verify", "--no-trust", "--recursive", artifact["system_path"]]))
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



def verify_host_nix_root_absent() -> None:
    if HOST_NIX_ROOT.exists() or HOST_NIX_ROOT.is_symlink():
        raise ProductionInstallError("canonical /nix must be absent before production apply")
    if _mountpoint_is_mounted(str(HOST_NIX_ROOT)):
        raise ProductionInstallError("canonical /nix is already mounted")


def _resolve_trusted_executable(name: str) -> str:
    if name.startswith("/"):
        if os.path.normpath(name) != name:
            raise ProductionInstallError("required host tool path is not canonical")
        candidates = [name]
    elif "/" in name or not name:
        raise ProductionInstallError("required host tool name is not canonical")
    else:
        candidates = [f"{directory}/{name}" for directory in TRUSTED_PATH.split(":")]
    for candidate in candidates:
        try:
            info = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111:
            return candidate
    raise ProductionInstallError(f"required host tool is unavailable: {name}")


def verify_host_tools_available(plan: dict[str, Any]) -> list[str]:
    """Prove every host-provided executable exists before the first effect.

    A tool missing from Pop!_OS (for example cryptsetup or mksquashfs) must block
    the run while the Seagate is still blank, not abort it halfway through a
    partition/format sequence.
    """
    names: list[str] = []
    for command in list(plan.get("commands", [])) + list(plan.get("teardown_commands", [])):
        argv = command.get("argv") if isinstance(command, dict) else None
        if not isinstance(argv, list) or not argv or not isinstance(argv[0], str):
            raise ProductionInstallError("reviewed plan contains an invalid command")
        # Sealed-closure tools are addressed through the seal that is not mounted yet.
        if argv[0] == SEALED_TOOL_LAUNCHER:
            continue
        names.append(argv[0])
    names.extend(APPLY_HOST_TOOLS)
    return sorted({_resolve_trusted_executable(name) for name in dict.fromkeys(names)})


def _systemd_active(unit: str) -> bool:
    result = _run(["systemctl", "is-active", "--quiet", unit], check=False)
    if result.returncode == 0:
        return True
    if result.returncode == 3:
        return False
    raise ProductionInstallError(f"cannot determine {unit} state")


def _validate_docker_container_ids(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) != len(set(value))
        or any(
            not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None
            for item in value
        )
    ):
        raise ProductionInstallError("Docker container inventory is invalid")
    return sorted(value)


def _running_docker_container_ids() -> list[str]:
    ids = [
        line.strip()
        for line in _run(["docker", "ps", "--no-trunc", "-q"]).stdout.decode(
            "utf-8", "replace"
        ).splitlines()
        if line.strip()
    ]
    return _validate_docker_container_ids(ids)


def _running_docker_container_pids(container_ids: list[str] | None = None) -> list[int]:
    ids = (
        _running_docker_container_ids()
        if container_ids is None
        else _validate_docker_container_ids(container_ids)
    )
    if not ids:
        return []
    rows = _json_command(["docker", "inspect", *ids])
    if not isinstance(rows, list) or len(rows) != len(ids):
        raise ProductionInstallError("Docker process inventory is invalid")
    expected_ids = set(ids)
    observed_ids: set[str] = set()
    pids: list[int] = []
    for row in rows:
        identity = row.get("Id") if isinstance(row, dict) else None
        state = row.get("State") if isinstance(row, dict) else None
        pid = state.get("Pid") if isinstance(state, dict) else None
        running = state.get("Running") if isinstance(state, dict) else None
        if (
            not isinstance(identity, str)
            or identity not in expected_ids
            or identity in observed_ids
            or running is not True
            or type(pid) is not int
            or pid <= 0
        ):
            raise ProductionInstallError("Docker process inventory is incomplete")
        observed_ids.add(identity)
        pids.append(pid)
    if observed_ids != expected_ids or len(pids) != len(set(pids)):
        raise ProductionInstallError("Docker process inventory is incomplete")
    return sorted(pids)


def _process_exists(pid: int) -> bool:
    return type(pid) is int and pid > 0 and Path(f"/proc/{pid}").exists()


def _moby_shim_pids() -> list[int]:
    result: list[int] = []
    try:
        entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise ProductionInstallError("cannot inspect Docker container shims") from exc
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        argv = [item.decode("utf-8", "replace") for item in raw.split(b"\0") if item]
        if not argv or not argv[0].endswith("containerd-shim-runc-v2"):
            continue
        if "-namespace" not in argv:
            continue
        index = argv.index("-namespace")
        if index + 1 < len(argv) and argv[index + 1] == "moby":
            result.append(int(entry.name))
    return sorted(result)


def stop_docker_for_apply() -> dict[str, Any]:
    if os.geteuid() != 0:
        raise ProductionInstallError("Docker quiesce requires root")
    state = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_docker_quiesce_state",
        "service_active": _systemd_active("docker.service"),
        "socket_active": _systemd_active("docker.socket"),
        "running_container_ids": [],
        "running_pid_count": 0,
    }
    running_ids = _running_docker_container_ids() if state["service_active"] else []
    running_pids = _running_docker_container_pids(running_ids) if running_ids else []
    state["running_container_ids"] = running_ids
    state["running_pid_count"] = len(running_pids)
    try:
        _run(["systemctl", "stop", "docker.socket", "docker.service"])
        if _systemd_active("docker.service") or _systemd_active("docker.socket"):
            raise ProductionInstallError("Docker did not become inactive before production apply")
        survivors = [pid for pid in running_pids if _process_exists(pid)]
        shim_survivors = _moby_shim_pids()
        if survivors or shim_survivors:
            raise ProductionInstallError("Docker containers survived service quiesce")
        return state
    except BaseException as exc:
        try:
            restore_docker_after_apply(state)
        except BaseException as restore_exc:
            raise ProductionInstallError(
                "Docker quiesce failed and the pre-apply service/container state could not be restored"
            ) from restore_exc
        raise exc


def verify_docker_quiesced() -> None:
    if _systemd_active("docker.service") or _systemd_active("docker.socket"):
        raise ProductionInstallError("Docker reactivated during production apply")
    if _moby_shim_pids():
        raise ProductionInstallError("Docker container shim appeared during production apply")


def restore_docker_after_apply(state: dict[str, Any]) -> None:
    if (
        not isinstance(state, dict)
        or state.get("schema_version") != 1
        or state.get("kind") != "heim_pc.nixos_docker_quiesce_state"
        or not isinstance(state.get("service_active"), bool)
        or not isinstance(state.get("socket_active"), bool)
        or type(state.get("running_pid_count")) is not int
        or state["running_pid_count"] < 0
    ):
        raise ProductionInstallError("Docker quiesce state is invalid")
    running_ids = _validate_docker_container_ids(state.get("running_container_ids"))
    if state["running_pid_count"] != len(running_ids) or (
        running_ids and not state["service_active"]
    ):
        raise ProductionInstallError("Docker quiesce state is invalid")
    if state["socket_active"]:
        _run(["systemctl", "start", "docker.socket"])
    if state["service_active"]:
        _run(["systemctl", "start", "docker.service"])
        current_ids = set(_running_docker_container_ids())
        missing = [container_id for container_id in running_ids if container_id not in current_ids]
        if missing:
            _run(["docker", "start", *missing])
        restored_ids = set(_running_docker_container_ids())
        if restored_ids != set(running_ids):
            raise ProductionInstallError("Docker pre-apply container state restore could not be verified exactly")
    if not state["service_active"] and _systemd_active("docker.service"):
        _run(["systemctl", "stop", "docker.service"])
    if not state["socket_active"] and _systemd_active("docker.socket"):
        _run(["systemctl", "stop", "docker.socket"])
    if _systemd_active("docker.service") != state["service_active"]:
        raise ProductionInstallError("Docker service state restore could not be verified")
    if _systemd_active("docker.socket") != state["socket_active"]:
        raise ProductionInstallError("Docker socket state restore could not be verified")


def _managed_nix_source_root(receipt: dict[str, Any]) -> Path:
    raw = receipt.get("store_root")
    if not isinstance(raw, str) or MANAGED_NIX_STORE_ROOT_RE.fullmatch(raw) is None:
        raise ProductionInstallError("managed Nix source root is outside canonical authority")
    path = Path(raw)
    try:
        info = path.lstat()
    except OSError as exc:
        raise ProductionInstallError("managed Nix source root is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ProductionInstallError("managed Nix source root is unsafe")
    return path


def _sealed_mount_record(path: Path) -> dict[str, str]:
    path = Path(path)
    result = _run([
        "/usr/bin/findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "-T", str(path)
    ])
    line = result.stdout.decode("utf-8", "strict").strip()
    fields = line.split(None, 3)
    if len(fields) != 4:
        raise ProductionInstallError("sealed Nix mount identity is unreadable")
    target, source, fstype, options = fields
    if (
        target != str(HOST_NIX_ROOT)
        or re.fullmatch(r"/dev/loop[0-9]+", source) is None
        or fstype != "squashfs"
        or "ro" not in set(options.split(","))
    ):
        raise ProductionInstallError("sealed Nix mount identity is invalid")
    return {"target": target, "source": source, "fstype": fstype, "options": options}


def _resolve_inside_sealed_store(path: Path) -> Path:
    path = Path(path)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProductionInstallError(f"sealed Nix path is unavailable: {path}") from exc
    store_root = HOST_NIX_ROOT / "store"
    try:
        resolved.relative_to(store_root)
    except ValueError as exc:
        raise ProductionInstallError(f"sealed Nix path escapes /nix/store: {path}") from exc
    _sealed_mount_record(resolved)
    return resolved


def _verify_immutable_image(path: Path) -> None:
    path = Path(path)
    result = _run(["/usr/bin/lsattr", "-d", str(path)])
    line = result.stdout.decode("utf-8", "strict").strip()
    fields = line.split(None, 1)
    if len(fields) != 2 or "i" not in fields[0]:
        raise ProductionInstallError("production Nix seal image is not immutable")


def verify_sealed_nix_structure(
    artifact: dict[str, Any], seal: dict[str, Any] | None = None
) -> None:
    artifact = validate_install_artifact(artifact)
    try:
        store_info = (HOST_NIX_ROOT / "store").lstat()
        var_info = (HOST_NIX_ROOT / "var").lstat()
    except OSError as exc:
        raise ProductionInstallError("sealed Nix root is incomplete") from exc
    if (
        stat.S_ISLNK(store_info.st_mode)
        or not stat.S_ISDIR(store_info.st_mode)
        or stat.S_ISLNK(var_info.st_mode)
        or not stat.S_ISDIR(var_info.st_mode)
    ):
        raise ProductionInstallError("sealed Nix root contains unsafe store/state paths")
    mount = _sealed_mount_record(HOST_NIX_ROOT / "store")
    _resolve_inside_sealed_store(Path(artifact["system_path"]))
    for relative in (
        "sw/bin/nix",
        "sw/bin/nixos-install",
        "sw/bin/mkfs.btrfs",
        "sw/bin/btrfs",
        "etc/systemd/system/heim-pc-firstboot-credentials.service",
    ):
        path = Path(artifact["system_path"]) / relative
        resolved = _resolve_inside_sealed_store(path)
        if relative.startswith("sw/bin/"):
            if not resolved.is_file() or not os.access(resolved, os.X_OK):
                raise ProductionInstallError(f"sealed Nix closure lacks executable {relative}")
        elif not resolved.exists():
            raise ProductionInstallError(f"sealed Nix closure lacks {relative}")
    if seal is not None:
        image = Path(str(seal.get("image", "")))
        if (
            seal.get("kind") != "heim_pc.nixos_production_build_seal"
            or seal.get("mountpoint") != str(HOST_NIX_ROOT)
            or image.parent != Path(str(seal.get("seal_root", "")))
            or image.name != "nix.squashfs"
            or seal.get("loop_device") != mount["source"]
            or seal.get("closure_manifest_sha256") != artifact["closure_manifest_sha256"]
        ):
            raise ProductionInstallError("sealed Nix runtime identity is inconsistent")
        _verify_immutable_image(image)


def _require_root_owned_directory(path: Path, *, mode: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ProductionInstallError(f"root-owned directory is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise ProductionInstallError(f"root-owned directory has unsafe identity: {path}")


def _safe_tar_member_name(name: str) -> bool:
    if not isinstance(name, str) or not name or "\\" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and path.parts[0] not in {"", "."}


def _read_tar_member(tar: tarfile.TarFile, name: str, *, max_bytes: int) -> bytes:
    try:
        member = tar.getmember(name)
    except KeyError as exc:
        raise ProductionInstallError(f"pinned verifier archive lacks {name}") from exc
    if not member.isfile() or member.size < 0 or member.size > max_bytes:
        raise ProductionInstallError(f"pinned verifier archive member is invalid: {name}")
    stream = tar.extractfile(member)
    if stream is None:
        raise ProductionInstallError(f"pinned verifier archive member is unreadable: {name}")
    payload = stream.read(max_bytes + 1)
    if len(payload) != member.size or len(payload) > max_bytes:
        raise ProductionInstallError(f"pinned verifier archive member size changed: {name}")
    return payload


def _sha256_tar_member(tar: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    if not member.isfile() or member.size <= 0:
        raise ProductionInstallError(f"pinned verifier image layer is invalid: {member.name}")
    stream = tar.extractfile(member)
    if stream is None:
        raise ProductionInstallError(f"pinned verifier image layer is unreadable: {member.name}")
    digest = hashlib.sha256()
    remaining = member.size
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise ProductionInstallError(f"pinned verifier image layer is truncated: {member.name}")
        digest.update(chunk)
        remaining -= len(chunk)
    if stream.read(1):
        raise ProductionInstallError(f"pinned verifier image layer exceeds declared size: {member.name}")
    return digest.hexdigest()


def validate_verifier_image_archive(
    path: Path,
    artifact: dict[str, Any],
    *,
    expected_archive_sha256: str | None = None,
) -> dict[str, Any]:
    artifact = validate_install_artifact(artifact)
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise ProductionInstallError("pinned verifier image archive is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o400
    ):
        raise ProductionInstallError("pinned verifier image archive identity is unsafe")
    archive_sha256 = _sha256_file(path)
    if expected_archive_sha256 is not None and archive_sha256 != expected_archive_sha256:
        raise ProductionInstallError("pinned verifier image archive changed after Docker quiesce")
    try:
        with tarfile.open(path, mode="r:*") as tar:
            members = tar.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)) or not all(_safe_tar_member_name(name) for name in names):
                raise ProductionInstallError("pinned verifier image archive contains unsafe member names")
            manifest_raw = _read_tar_member(tar, "manifest.json", max_bytes=1024 * 1024)
            try:
                manifest = json.loads(manifest_raw.decode("utf-8", "strict"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProductionInstallError("pinned verifier image manifest is invalid") from exc
            if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
                raise ProductionInstallError("pinned verifier image manifest is ambiguous")
            entry = manifest[0]
            config_name = entry.get("Config")
            repo_tags = entry.get("RepoTags")
            layers = entry.get("Layers")
            pinned_hex = artifact["nix_image"].removeprefix("sha256:")
            if (
                config_name != f"blobs/sha256/{pinned_hex}"
                or not isinstance(repo_tags, list)
                or PINNED_NIX_IMAGE_TAG not in repo_tags
                or not isinstance(layers, list)
                or not layers
                or len(layers) != len(set(layers))
                or not all(isinstance(item, str) and _safe_tar_member_name(item) for item in layers)
            ):
                raise ProductionInstallError("pinned verifier image manifest does not match authority")
            config_raw = _read_tar_member(tar, config_name, max_bytes=4 * 1024 * 1024)
            config_sha256 = hashlib.sha256(config_raw).hexdigest()
            if config_sha256 != pinned_hex:
                raise ProductionInstallError("pinned verifier image config digest mismatch")
            try:
                config = json.loads(config_raw.decode("utf-8", "strict"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProductionInstallError("pinned verifier image config is invalid") from exc
            rootfs = config.get("rootfs") if isinstance(config, dict) else None
            diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
            if (
                not isinstance(diff_ids, list)
                or len(diff_ids) != len(layers)
                or not all(
                    isinstance(item, str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", item) is not None
                    for item in diff_ids
                )
            ):
                raise ProductionInstallError("pinned verifier image layer identity is invalid")
            by_name = {member.name: member for member in members}
            for layer, diff_id in zip(layers, diff_ids):
                expected_hex = diff_id.removeprefix("sha256:")
                if layer != f"blobs/sha256/{expected_hex}":
                    raise ProductionInstallError("pinned verifier image layer path/diff-id mismatch")
                member = by_name.get(layer)
                if member is None:
                    raise ProductionInstallError("pinned verifier image layer is missing")
                if _sha256_tar_member(tar, member) != expected_hex:
                    raise ProductionInstallError("pinned verifier image layer digest mismatch")
    except (tarfile.TarError, OSError) as exc:
        raise ProductionInstallError("pinned verifier image archive is invalid") from exc
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_pinned_verifier_archive",
        "path": str(path),
        "archive_sha256": archive_sha256,
        "image_id": artifact["nix_image"],
        "image_tag": PINNED_NIX_IMAGE_TAG,
        "layer_count": len(layers),
    }


def prepare_verifier_image_archive(plan: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise ProductionInstallError("pinned verifier archive preparation requires root")
    artifact = validate_install_artifact(artifact)
    expected = _verifier_archive_path(artifact, plan["managed_build_receipt"]["artifact_file_sha256"])
    if plan.get("verifier_image_archive") != str(expected):
        raise ProductionInstallError("reviewed verifier archive identity is inconsistent")
    _require_root_owned_directory(VERIFIER_ARCHIVE_BASE.parent, mode=0o700)
    if VERIFIER_ARCHIVE_BASE.exists() or VERIFIER_ARCHIVE_BASE.is_symlink():
        _require_root_owned_directory(VERIFIER_ARCHIVE_BASE, mode=0o700)
    else:
        VERIFIER_ARCHIVE_BASE.mkdir(mode=0o700)
        _require_root_owned_directory(VERIFIER_ARCHIVE_BASE, mode=0o700)
    if expected.exists() or expected.is_symlink():
        raise ProductionInstallError("refusing existing pinned verifier image archive")
    verify_pinned_nix_image_identity(artifact)
    immutable = False
    try:
        _run(["docker", "image", "save", "--output", str(expected), PINNED_NIX_IMAGE_TAG])
        try:
            info = expected.lstat()
        except OSError as exc:
            raise ProductionInstallError("pinned verifier image export did not materialize") from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_nlink != 1
        ):
            raise ProductionInstallError("pinned verifier image export identity is unsafe")
        os.chmod(expected, 0o400, follow_symlinks=False)
        metadata = validate_verifier_image_archive(expected, artifact)
        _run(["/usr/bin/chattr", "+i", str(expected)])
        immutable = True
        _verify_immutable_image(expected)
        verify_pinned_nix_image_identity(artifact)
        return metadata
    except BaseException:
        if immutable:
            _run(["/usr/bin/chattr", "-i", str(expected)], check=False)
        _run(["/usr/bin/rm", "-f", "--", str(expected)], check=False)
        raise


def cleanup_verifier_image_archive(metadata: dict[str, Any]) -> None:
    path = Path(str(metadata.get("path", "")))
    if path.parent != VERIFIER_ARCHIVE_BASE or not re.fullmatch(
        r"[0-9a-f]{40}-[0-9a-f]{16}\.docker\.tar", path.name
    ):
        raise ProductionInstallError("pinned verifier archive cleanup identity is invalid")
    if path.exists() or path.is_symlink():
        if _run(["/usr/bin/chattr", "-i", str(path)], check=False).returncode != 0:
            raise ProductionInstallError("cannot clear pinned verifier archive immutable bit")
        if _run(["/usr/bin/rm", "--", str(path)], check=False).returncode != 0:
            raise ProductionInstallError("cannot remove pinned verifier archive")
    if path.exists() or path.is_symlink():
        raise ProductionInstallError("pinned verifier archive cleanup could not be verified")


def _verify_containerd_socket() -> None:
    try:
        info = CONTAINERD_SOCKET.lstat()
    except OSError as exc:
        raise ProductionInstallError("root-only containerd socket is unavailable") from exc
    mode = stat.S_IMODE(info.st_mode)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or mode & 0o007
        or mode & 0o600 != 0o600
    ):
        raise ProductionInstallError("root-only containerd socket identity is unsafe")


def _ctr_argv(namespace: str | None, args: list[str]) -> list[str]:
    argv = [CTR_BIN, "--address", str(CONTAINERD_SOCKET)]
    if namespace is not None:
        if re.fullmatch(r"heim-pc-nixos-verify-[0-9a-f]{16}", namespace) is None:
            raise ProductionInstallError("containerd verifier namespace is invalid")
        argv += ["--namespace", namespace]
    return [*argv, *args]


def _containerd_namespaces() -> list[str]:
    output = _run(_ctr_argv(None, ["namespaces", "list", "-q"])).stdout.decode("utf-8", "strict")
    result = [line.strip() for line in output.splitlines() if line.strip()]
    if len(result) != len(set(result)):
        raise ProductionInstallError("containerd namespace inventory is ambiguous")
    return result


def _containerd_nix_run_argv(
    namespace: str, container_id: str, args: list[str]
) -> list[str]:
    if re.fullmatch(r"heim-pc-nixos-verify-[0-9a-f]{16}-(info|verify)", container_id) is None:
        raise ProductionInstallError("containerd verifier container identity is invalid")
    return _ctr_argv(namespace, [
        "run", "--rm", "--read-only",
        "--mount", "type=bind,src=/nix,dst=/subject/nix,options=rbind:ro",
        "--mount", "type=tmpfs,dst=/tmp,options=nosuid:nodev:mode=1777",
        "--env", "HOME=/tmp",
        "--env", "TMPDIR=/tmp",
        "docker.io/nixos/nix:2.35.2", container_id,
        "/nix/var/nix/profiles/default/bin/nix",
        "--extra-experimental-features", READONLY_NIX_FEATURES,
        "--store", READONLY_NIX_STORE,
        *args,
    ])


def _cleanup_containerd_verifier_namespace(namespace: str) -> None:
    tasks = _run(_ctr_argv(namespace, ["tasks", "list", "-q"]), check=False)
    containers = _run(_ctr_argv(namespace, ["containers", "list", "-q"]), check=False)
    if tasks.returncode != 0 or containers.returncode != 0:
        raise ProductionInstallError("cannot prove containerd verifier task cleanup")
    if tasks.stdout.strip() or containers.stdout.strip():
        raise ProductionInstallError("containerd verifier left tasks or containers behind")
    _run(_ctr_argv(namespace, ["images", "remove", "docker.io/nixos/nix:2.35.2"]), check=False)
    result = _run(_ctr_argv(None, ["namespaces", "remove", namespace]), check=False)
    if result.returncode != 0 or namespace in _containerd_namespaces():
        raise ProductionInstallError("containerd verifier namespace cleanup could not be verified")


def verify_sealed_nix_with_containerd(
    plan: dict[str, Any],
    artifact: dict[str, Any],
    seal: dict[str, Any],
    archive_metadata: dict[str, Any],
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise ProductionInstallError("independent sealed Nix verification requires root")
    artifact = validate_install_artifact(artifact)
    verify_docker_quiesced()
    verify_sealed_nix_structure(artifact, seal)
    _verify_containerd_socket()
    archive = Path(plan["verifier_image_archive"])
    expected_archive = _verifier_archive_path(
        artifact, plan["managed_build_receipt"]["artifact_file_sha256"]
    )
    if archive != expected_archive or archive_metadata.get("path") != str(archive):
        raise ProductionInstallError("containerd verifier archive identity changed after planning")
    archive_check = validate_verifier_image_archive(
        archive,
        artifact,
        expected_archive_sha256=str(archive_metadata.get("archive_sha256", "")),
    )
    _verify_immutable_image(archive)
    namespace = str(plan.get("containerd_verifier_namespace", ""))
    expected_namespace = _verifier_namespace(plan["managed_build_receipt"]["artifact_file_sha256"])
    if namespace != expected_namespace:
        raise ProductionInstallError("containerd verifier namespace changed after planning")
    if namespace in _containerd_namespaces():
        raise ProductionInstallError("refusing existing containerd verifier namespace")
    created = False
    try:
        _run(_ctr_argv(None, ["namespaces", "create", namespace]))
        created = True
        _run(_ctr_argv(namespace, ["images", "import", str(archive)]))
        image_refs = _run(_ctr_argv(namespace, ["images", "list", "-q"])).stdout.decode(
            "utf-8", "strict"
        ).splitlines()
        image_refs = [item.strip() for item in image_refs if item.strip()]
        if image_refs != ["docker.io/nixos/nix:2.35.2"]:
            raise ProductionInstallError("containerd verifier imported unexpected image references")
        ready_refs = _run(_ctr_argv(namespace, ["images", "check", "--quiet"])).stdout.decode(
            "utf-8", "strict"
        ).splitlines()
        ready_refs = [item.strip() for item in ready_refs if item.strip()]
        if ready_refs != ["docker.io/nixos/nix:2.35.2"]:
            raise ProductionInstallError("containerd verifier image is not fully ready")
        info_id = f"{namespace}-info"
        path_info = _json_command(_containerd_nix_run_argv(
            namespace,
            info_id,
            ["path-info", "--json", "--recursive", artifact["system_path"]],
        ))
        closure = closure_manifest_metadata(path_info)
        if (
            closure["closure_manifest_sha256"] != artifact["closure_manifest_sha256"]
            or closure["closure_path_count"] != artifact["closure_path_count"]
        ):
            raise ProductionInstallError("root-only verifier found sealed Nix closure drift")
        verify_id = f"{namespace}-verify"
        _run(_containerd_nix_run_argv(
            namespace,
            verify_id,
            ["store", "verify", "--no-trust", "--recursive", artifact["system_path"]],
        ))
        verify_docker_quiesced()
        verify_sealed_nix_structure(artifact, seal)
        return {
            "schema_version": 1,
            "kind": "heim_pc.nixos_root_only_seal_verification",
            "namespace": namespace,
            "archive_sha256": archive_check["archive_sha256"],
            "image_id": artifact["nix_image"],
            "closure_manifest_sha256": closure["closure_manifest_sha256"],
            "closure_path_count": closure["closure_path_count"],
        }
    finally:
        if created:
            _cleanup_containerd_verifier_namespace(namespace)


def create_sealed_nix_store(plan: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise ProductionInstallError("trusted build seal requires root")
    artifact = validate_install_artifact(artifact)
    receipt = validate_managed_build_receipt(
        plan["managed_build_receipt"],
        artifact,
        expected_policy_sha256=plan["managed_policy_sha256"],
    )
    expected = _sealed_nix_paths(artifact, receipt["artifact_file_sha256"])
    if (
        plan.get("sealed_nix_image") != str(expected["image"])
        or plan.get("host_nix_root") != str(HOST_NIX_ROOT)
    ):
        raise ProductionInstallError("reviewed plan sealed Nix identity is inconsistent")
    verify_host_nix_root_absent()
    source = _managed_nix_source_root(receipt)
    for path, label in ((source, "root"), (source / "store", "store"), (source / "var", "state")):
        try:
            info = path.lstat()
        except OSError as exc:
            raise ProductionInstallError(f"managed Nix {label} source is unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ProductionInstallError(f"managed Nix {label} source is unsafe")

    _require_root_owned_directory(SEALED_NIX_BASE.parent, mode=0o700)
    root = expected["seal_root"]
    if root.exists() or root.is_symlink():
        raise ProductionInstallError("refusing existing production Nix seal")
    if SEALED_NIX_BASE.exists() or SEALED_NIX_BASE.is_symlink():
        _require_root_owned_directory(SEALED_NIX_BASE, mode=0o700)
    else:
        SEALED_NIX_BASE.mkdir(mode=0o700)
        _require_root_owned_directory(SEALED_NIX_BASE, mode=0o700)
    root.mkdir(mode=0o700)
    _require_root_owned_directory(root, mode=0o700)
    HOST_NIX_ROOT.mkdir(mode=0o755)

    loop_device: str | None = None
    mounted = False
    immutable = False
    try:
        _run(
            [
                "/usr/bin/mksquashfs",
                str(source),
                str(expected["image"]),
                "-noappend",
                "-no-progress",
                "-quiet",
            ]
        )
        image_info = expected["image"].lstat()
        if (
            not stat.S_ISREG(image_info.st_mode)
            or image_info.st_uid != 0
            or image_info.st_gid != 0
            or image_info.st_nlink != 1
        ):
            raise ProductionInstallError("production Nix seal image is unsafe")
        os.chmod(expected["image"], 0o400, follow_symlinks=False)
        _run(["/usr/bin/chattr", "+i", str(expected["image"])])
        immutable = True
        _verify_immutable_image(expected["image"])
        loop_result = _run(
            [
                "/usr/sbin/losetup",
                "--find",
                "--show",
                "--read-only",
                str(expected["image"]),
            ]
        )
        loop_device = loop_result.stdout.decode("utf-8", "strict").strip()
        if re.fullmatch(r"/dev/loop[0-9]+", loop_device) is None:
            raise ProductionInstallError("production Nix seal loop identity is invalid")
        _run(
            [
                "/usr/bin/mount",
                "-t",
                "squashfs",
                "-o",
                "ro,nodev,nosuid",
                loop_device,
                str(expected["mountpoint"]),
            ]
        )
        mounted = True
        seal = {
            "schema_version": 1,
            "kind": "heim_pc.nixos_production_build_seal",
            "seal_root": str(root),
            "image": str(expected["image"]),
            "loop_device": loop_device,
            "mountpoint": str(expected["mountpoint"]),
            "immutable_image": True,
            "closure_manifest_sha256": artifact["closure_manifest_sha256"],
        }
        verify_sealed_nix_structure(artifact, seal)
        return seal
    except BaseException:
        partial_seal = {
            "seal_root": str(root),
            "image": str(expected["image"]),
            "loop_device": loop_device,
        }
        try:
            cleanup_sealed_nix_store(partial_seal)
        except BaseException as cleanup_exc:
            raise ProductionInstallError(
                "production Nix seal creation cleanup could not be verified"
            ) from cleanup_exc
        raise


def cleanup_sealed_nix_store(seal: dict[str, Any]) -> None:
    root = Path(str(seal.get("seal_root", "")))
    if (
        root.parent != SEALED_NIX_BASE
        or re.fullmatch(r"[0-9a-f]{40}-[0-9a-f]{16}", root.name) is None
    ):
        raise ProductionInstallError("sealed Nix cleanup identity is invalid")
    image = Path(str(seal.get("image", "")))
    if image != root / "nix.squashfs":
        raise ProductionInstallError("sealed Nix cleanup image identity is invalid")
    mountpoint = HOST_NIX_ROOT
    loop_device = seal.get("loop_device")
    failures: list[str] = []
    if _mountpoint_is_mounted(str(mountpoint)):
        if _run(["/usr/bin/umount", str(mountpoint)], check=False).returncode != 0:
            failures.append("umount")
    if (
        not failures
        and isinstance(loop_device, str)
        and re.fullmatch(r"/dev/loop[0-9]+", loop_device)
    ):
        if _run(["/usr/sbin/losetup", "-d", loop_device], check=False).returncode != 0:
            failures.append("losetup")
    if not failures and (HOST_NIX_ROOT.exists() or HOST_NIX_ROOT.is_symlink()):
        if _run(["/usr/bin/rm", "-rf", "--", str(HOST_NIX_ROOT)], check=False).returncode != 0:
            failures.append("nix-root-rm")
    if not failures and (image.exists() or image.is_symlink()):
        if _run(["/usr/bin/chattr", "-i", str(image)], check=False).returncode != 0:
            failures.append("chattr")
    if not failures and (root.exists() or root.is_symlink()):
        if _run(["/usr/bin/rm", "-rf", "--", str(root)], check=False).returncode != 0:
            failures.append("seal-rm")
    if (
        failures
        or HOST_NIX_ROOT.exists()
        or HOST_NIX_ROOT.is_symlink()
        or root.exists()
        or root.is_symlink()
    ):
        raise ProductionInstallError("production Nix seal teardown could not be verified")

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


def _mountpoint_is_mounted(path: str) -> bool:
    result = _run(
        ["findmnt", "--first-only", "--noheadings", "--mountpoint", path],
        check=False,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise ProductionInstallError("cannot determine teardown mount state")


def _attempt_teardown(
    commands: list[dict[str, Any]], mapper_name: str
) -> tuple[list[str], BaseException | None]:
    failures: list[str] = []
    first_exception: BaseException | None = None
    mapper = Path("/dev/mapper") / mapper_name
    for command in commands:
        effect = str(command.get("effect", "unknown"))
        try:
            if effect in {"unmount-stage", "unmount"}:
                if not _mountpoint_is_mounted(str(command["argv"][-1])):
                    continue
            elif effect == "luks-close" and not (mapper.exists() or mapper.is_symlink()):
                continue
            result = _run(command["argv"], check=False)
            if result.returncode != 0:
                failures.append(effect)
        except BaseException as exc:
            failures.append(effect)
            if first_exception is None:
                first_exception = exc
    return failures, first_exception


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


def _success_receipt(
    *, plan: dict[str, Any], artifact: dict[str, Any], source_revision: str,
    post: dict[str, Any], completed_effects: list[str], nvram_before: str, nvram_after: str,
) -> dict[str, Any]:
    target_authority = str(plan["target_authority"])
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_receipt",
        "plan_sha256": plan["plan_sha256"],
        "install_artifact_sha256": plan["install_artifact_sha256"],
        "source_revision": source_revision,
        "system_path": artifact["system_path"],
        "target_authority_sha256": hashlib.sha256(target_authority.encode("utf-8")).hexdigest(),
        "private_target_authority_redacted": True,
        "protected_post_fingerprint": protected_fingerprint(post),
        "completed_effects": completed_effects,
        "credential_staged": True,
        "efi_nvram_sha256_before": nvram_before,
        "efi_nvram_sha256_after": nvram_after,
        "efi_variables_touched": False,
    }


def _post_mutation_failure_receipt(
    *, plan: dict[str, Any], artifact: dict[str, Any], error: PostMutationInstallError,
) -> dict[str, Any]:
    evidence = error.private_evidence if isinstance(error.private_evidence, dict) else {}
    allowed_effects = {
        str(command.get("effect"))
        for command in plan.get("commands", [])
        if isinstance(command, dict) and isinstance(command.get("effect"), str)
    } | {"private-storage-identity-staged", "private-boot-entries-bound"}
    completed = evidence.get("completed_effects")
    completed_effects = (
        [item for item in completed if isinstance(item, str) and item in allowed_effects]
        if isinstance(completed, list) else []
    )
    allowed_teardown = {
        str(command.get("effect"))
        for command in plan.get("teardown_commands", [])
        if isinstance(command, dict) and isinstance(command.get("effect"), str)
    }
    teardown = evidence.get("teardown_failures")
    teardown_failures = (
        sorted({item for item in teardown if isinstance(item, str) and item in allowed_teardown})
        if isinstance(teardown, list) else []
    )

    def safe_digest(value: Any) -> str | None:
        return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None

    target_authority = str(plan["target_authority"])
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_failure_receipt",
        "status": "failure",
        "alarm_code": error.code,
        "plan_sha256": plan["plan_sha256"],
        "install_artifact_sha256": plan["install_artifact_sha256"],
        "source_revision": artifact["source_revision"],
        "system_path": artifact["system_path"],
        "target_authority_sha256": hashlib.sha256(target_authority.encode("utf-8")).hexdigest(),
        "private_target_authority_redacted": True,
        "protected_pre_fingerprint": plan["protected_pre_fingerprint"],
        "protected_post_fingerprint": safe_digest(evidence.get("protected_post_fingerprint")),
        "completed_effects": completed_effects,
        "mutation_attempted": evidence.get("mutation_attempted", True) is True,
        "credential_staging_attempted": evidence.get("credential_staging_attempted") is True,
        "credential_staged": evidence.get("credential_staged") is True,
        "private_storage_identity_staged": evidence.get("private_storage_identity_staged") is True,
        "teardown_failures": teardown_failures,
        "efi_nvram_sha256_before": safe_digest(evidence.get("efi_nvram_sha256_before")),
        "efi_nvram_sha256_after": safe_digest(evidence.get("efi_nvram_sha256_after")),
        "efi_variables_touched": False,
    }


def execute_plan(
    plan: dict[str, Any], *, contract: dict[str, Any], confirmation: str | None,
    credential_hash_file: Path, observer=observe_live,
) -> dict[str, Any]:
    validate_confirmation(plan, confirmation)
    if os.geteuid() != 0:
        raise ProductionInstallError("production apply requires root")
    if sha256_json(contract) != plan.get("contract_sha256"):
        raise ProductionInstallError("storage contract no longer matches the reviewed plan")
    if contract.get("identity_binding", {}).get("identity_contract_sha256") != plan.get("identity_contract_sha256"):
        raise ProductionInstallError("private storage identity no longer matches the reviewed plan")
    artifact = validate_install_artifact(plan.get("install_artifact"))
    verify_managed_build_binding(plan, artifact)
    if artifact["source_authority"] != "merged-main":
        raise ProductionInstallError(
            "production apply requires a merged-main install artifact"
        )
    verify_promoted_main_revision(artifact["source_revision"])
    if sha256_json(artifact) != plan.get("install_artifact_sha256"):
        raise ProductionInstallError("install artifact digest no longer matches the reviewed plan")
    if artifact["source_revision"] != plan.get("source_revision"):
        raise ProductionInstallError("install artifact revision no longer matches the reviewed plan")
    source_revision = verify_source(plan["flake_source"], artifact["source_revision"])
    verify_install_artifact_environment(artifact)
    verify_host_tools_available(plan)
    verify_scratch_state(contract["topology"]["luks"]["mapper_name"])
    pre_now = validate_preflight(observer(contract), contract)
    verify_no_hidden_target_signatures(contract["target_identity"]["exact_by_id"])
    verify_partuuid_namespace_clear(contract)
    verify_partlabel_namespace_clear(contract)
    if protected_fingerprint(pre_now["protected"]) != plan["protected_pre_fingerprint"]:
        raise ProductionInstallError("live protected WD preimage differs from the reviewed plan")
    hash_bytes = read_credential_hash(credential_hash_file)
    first = getpass.getpass("LUKS passphrase: ", stream=sys.stderr)
    second = getpass.getpass("Repeat LUKS passphrase: ", stream=sys.stderr)
    if not first or first != second:
        raise ProductionInstallError("LUKS passphrase confirmation mismatch")
    secret = first.encode("utf-8")

    # Final race-closing gate immediately before the first destructive command.
    docker_state: dict[str, Any] | None = None
    seal: dict[str, Any] | None = None
    verifier_archive: dict[str, Any] | None = None
    seal_verification: dict[str, Any] | None = None
    mutation_attempted = False
    completed_effects: list[str] = []
    credential_staging_attempted = False
    credential_staged = False
    private_storage_identity_staged = False
    teardown_failures: list[str] = []
    teardown_exception: BaseException | None = None
    failure: BaseException | None = None
    post: dict[str, Any] | None = None
    nvram_before: str | None = None
    nvram_after: str | None = None
    protected_efi_freeze: dict[str, Any] | None = None

    def post_mutation_alarm(code: str) -> ProductionInstallError:
        # An in-loop guard can fail before the first destructive command runs. The
        # target is untouched then, so that is an ordinary block, not an alarm that
        # tells the operator destructive execution was attempted.
        if not mutation_attempted:
            return ProductionInstallError(
                f"production apply blocked before mutation: {code}"
            )
        return PostMutationInstallError(
            code,
            private_evidence={
                "completed_effects": list(completed_effects),
                "mutation_attempted": mutation_attempted,
                "credential_staging_attempted": credential_staging_attempted,
                "credential_staged": credential_staged,
                "private_storage_identity_staged": private_storage_identity_staged,
                "teardown_failures": list(teardown_failures),
                "protected_post_fingerprint": (
                    protected_fingerprint(post) if post is not None else None
                ),
                "efi_nvram_sha256_before": nvram_before,
                "efi_nvram_sha256_after": nvram_after,
            },
        )

    try:
        verify_host_nix_root_absent()
        verifier_archive = prepare_verifier_image_archive(plan, artifact)
        docker_state = stop_docker_for_apply()
        verify_docker_quiesced()
        validate_verifier_image_archive(
            Path(plan["verifier_image_archive"]),
            artifact,
            expected_archive_sha256=verifier_archive["archive_sha256"],
        )
        seal = create_sealed_nix_store(plan, artifact)
        verify_docker_quiesced()
        verify_sealed_nix_structure(artifact, seal)
        seal_verification = verify_sealed_nix_with_containerd(
            plan, artifact, seal, verifier_archive
        )
        if (
            seal_verification["closure_manifest_sha256"]
            != artifact["closure_manifest_sha256"]
            or seal_verification["closure_path_count"] != artifact["closure_path_count"]
        ):
            raise ProductionInstallError("root-only sealed Nix verification changed unexpectedly")
        cleanup_verifier_image_archive(verifier_archive)
        verifier_archive = None

        protected_efi_freeze = acquire_protected_efi_freeze(
            pre_now["protected"]["efi_source"]
        )
        final_pre = validate_preflight(observer(contract), contract)
        verify_no_hidden_target_signatures(contract["target_identity"]["exact_by_id"])
        verify_partuuid_namespace_clear(contract)
        verify_partlabel_namespace_clear(contract)
        verify_scratch_state(contract["topology"]["luks"]["mapper_name"])
        verify_managed_build_binding(plan, artifact)
        verify_promoted_main_revision(artifact["source_revision"])
        verify_docker_quiesced()
        verify_sealed_nix_structure(artifact, seal)
        if protected_fingerprint(final_pre["protected"]) != plan["protected_pre_fingerprint"]:
            raise ProductionInstallError("protected WD changed after interactive authorization")
        nvram_before = efi_nvram_digest()

        try:
            for command in plan["commands"]:
                verify_docker_quiesced()
                verify_sealed_nix_structure(artifact, seal)
                if command["effect"] == "nixos-install":
                    stage_private_storage_identity(mount_root=MOUNT_ROOT, contract=contract)
                    private_storage_identity_staged = True
                    completed_effects.append("private-storage-identity-staged")
                mutation_attempted = True
                _run(
                    command["argv"],
                    input_bytes=secret if command.get("secret_binding") else None,
                )
                completed_effects.append(command["effect"])
                if command["effect"] == "udev-settle":
                    verify_target_partition_bindings(contract)
                if command["effect"] == "luks-format":
                    verify_private_luks_uuid(contract)
            if not private_storage_identity_staged:
                raise ProductionInstallError("private storage identity was not staged before installation")
            verify_installed_target(artifact)
            bind_private_boot_entries(mount_root=MOUNT_ROOT, contract=contract)
            completed_effects.append("private-boot-entries-bound")
            verify_private_boot_binding(mount_root=MOUNT_ROOT, contract=contract)
            verify_persist_mount(
                MOUNT_ROOT, f"/dev/mapper/{contract['topology']['luks']['mapper_name']}"
            )
            credential_staging_attempted = True
            stage_firstboot_credentials(
                mount_root=MOUNT_ROOT,
                source_revision=source_revision,
                hash_bytes=hash_bytes,
            )
            credential_staged = True
        except BaseException as exc:
            failure = exc
        finally:
            teardown_failures, teardown_exception = _attempt_teardown(
                plan["teardown_commands"], contract["topology"]["luks"]["mapper_name"]
            )

        try:
            post = validate_protected_state(observer(contract), contract)
        except (ProductionInstallError, OSError, json.JSONDecodeError) as exc:
            raise post_mutation_alarm("protected-fallback-unverifiable") from exc
        if protected_fingerprint(post) != plan["protected_pre_fingerprint"]:
            raise post_mutation_alarm("protected-fallback-changed")
        try:
            nvram_after = efi_nvram_digest()
        except (ProductionInstallError, OSError, json.JSONDecodeError) as exc:
            raise post_mutation_alarm("efi-nvram-unverifiable") from exc
        if nvram_after != nvram_before:
            raise post_mutation_alarm("efi-nvram-changed")
        mapper = Path("/dev/mapper") / contract["topology"]["luks"]["mapper_name"]
        if mapper.exists() or mapper.is_symlink():
            raise post_mutation_alarm("mapper-open-after-teardown")
        for command in plan["teardown_commands"]:
            if command["effect"] in {"unmount-stage", "unmount"}:
                try:
                    if _mountpoint_is_mounted(str(command["argv"][-1])):
                        teardown_failures.append(command["effect"])
                except BaseException as exc:
                    teardown_failures.append(command["effect"])
                    if teardown_exception is None:
                        teardown_exception = exc
        if teardown_failures:
            raise post_mutation_alarm("teardown-incomplete") from (
                failure if failure is not None else teardown_exception
            )
        if credential_staging_attempted and not credential_staged:
            raise post_mutation_alarm("credential-staging-incomplete") from failure
        if failure is not None:
            if mutation_attempted:
                raise post_mutation_alarm("apply-failed-after-mutation-attempt") from failure
            raise failure
        if not credential_staged:
            raise post_mutation_alarm("credential-staging-incomplete")
        return _success_receipt(
            plan=plan,
            artifact=artifact,
            source_revision=source_revision,
            post=post,
            completed_effects=completed_effects,
            nvram_before=nvram_before,
            nvram_after=nvram_after,
        )
    finally:
        archive_failure: BaseException | None = None
        seal_failure: BaseException | None = None
        docker_failure: BaseException | None = None
        protected_efi_thaw_failure: BaseException | None = None
        if verifier_archive is not None:
            try:
                cleanup_verifier_image_archive(verifier_archive)
            except BaseException as exc:
                archive_failure = exc
        if seal is not None:
            try:
                cleanup_sealed_nix_store(seal)
            except BaseException as exc:
                seal_failure = exc
        if docker_state is not None:
            try:
                restore_docker_after_apply(docker_state)
            except BaseException as exc:
                docker_failure = exc
        if protected_efi_freeze is not None:
            try:
                release_protected_efi_freeze(protected_efi_freeze)
            except BaseException as exc:
                protected_efi_thaw_failure = exc
        if protected_efi_thaw_failure is not None:
            if mutation_attempted:
                raise post_mutation_alarm("protected-efi-thaw-incomplete") from protected_efi_thaw_failure
            if isinstance(protected_efi_thaw_failure, ProtectedEfiThawError):
                raise protected_efi_thaw_failure
            raise ProtectedEfiThawError(
                "protected EFI filesystem thaw failed before storage mutation"
            ) from protected_efi_thaw_failure
        if archive_failure is not None:
            if mutation_attempted:
                raise post_mutation_alarm("trusted-build-seal-teardown-incomplete") from archive_failure
            raise ProductionInstallError(
                "pinned verifier archive cleanup failed before storage mutation"
            ) from archive_failure
        if docker_failure is not None:
            if mutation_attempted:
                raise post_mutation_alarm("docker-quiesce-restore-incomplete") from docker_failure
            raise ProductionInstallError(
                "Docker state restore failed before storage mutation"
            ) from docker_failure
        if seal_failure is not None:
            if mutation_attempted:
                raise post_mutation_alarm("trusted-build-seal-teardown-incomplete") from seal_failure
            raise ProductionInstallError(
                "trusted build seal teardown failed before storage mutation"
            ) from seal_failure


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation-json", type=Path)
    parser.add_argument("--flake-source", default=str(FLAKE_SOURCE))
    parser.add_argument("--install-artifact", type=Path, required=True)
    parser.add_argument("--identity-contract", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm")
    parser.add_argument("--credential-hash-file", type=Path)
    parser.add_argument("--write-plan", type=Path)
    parser.add_argument("--write-receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        artifact_path = args.install_artifact.resolve()
        artifact = load_install_artifact(artifact_path)
        verify_source(args.flake_source, artifact["source_revision"])
        managed_policy_sha256 = managed_policy_sha256_for_source(args.flake_source)
        managed_receipt = load_managed_build_receipt(
            managed_build_receipt_path(artifact_path),
            artifact,
            expected_policy_sha256=managed_policy_sha256,
            artifact_path=artifact_path,
        )
        managed_attestation_verification = None
        if artifact["source_authority"] == "merged-main":
            managed_attestation_verification = verify_managed_build_attestation(
                artifact_path,
                managed_build_attestation_path(artifact_path),
                artifact["source_revision"],
                expected_policy_sha256=managed_policy_sha256,
            )
        contract = load_contract(
            args.identity_contract, expected_revision=artifact["source_revision"]
        )
        observation = json.loads(args.observation_json.read_text()) if args.observation_json else observe_live(contract)
        if args.observation_json is None:
            verify_no_hidden_target_signatures(contract["target_identity"]["exact_by_id"])
        plan = compile_plan(
            observation,
            install_artifact=artifact,
            install_artifact_path=artifact_path,
            managed_build_receipt=managed_receipt,
            managed_policy_sha256=managed_policy_sha256,
            flake_source=args.flake_source,
            contract=contract,
            managed_build_attestation_verification=managed_attestation_verification,
        )
        if not args.apply:
            if args.write_plan is not None:
                write_private_plan(args.write_plan.resolve(), plan)
            print(json.dumps(plan_summary(plan), indent=2, sort_keys=True))
            print(f"confirmation={confirmation_for(plan)}", file=sys.stderr)
            return 0
        if args.credential_hash_file is None:
            raise ProductionInstallError("--apply requires --credential-hash-file")
        if args.write_receipt is None:
            raise ProductionInstallError("--apply requires --write-receipt")
        apply_lock = acquire_production_apply_lock(plan)
        try:
            receipt_reservation = reserve_private_receipt(args.write_receipt)
            try:
                receipt = execute_plan(
                    plan, contract=contract, confirmation=args.confirm,
                    credential_hash_file=args.credential_hash_file,
                )
            except PostMutationInstallError as exc:
                try:
                    failure_receipt = _post_mutation_failure_receipt(
                        plan=plan, artifact=artifact, error=exc
                    )
                    finalize_private_receipt(receipt_reservation, failure_receipt)
                except BaseException as evidence_exc:
                    if "fd" in receipt_reservation:
                        try:
                            preserve_private_receipt_reservation(receipt_reservation)
                        except BaseException:
                            if "fd" in receipt_reservation:
                                _close_private_receipt_reservation(receipt_reservation)
                    raise PostMutationInstallError(
                        "private-receipt-finalization-incomplete"
                    ) from evidence_exc
                raise
            except BaseException:
                discard_private_receipt_reservation(receipt_reservation)
                raise
            try:
                finalize_private_receipt(receipt_reservation, receipt)
            except BaseException as exc:
                if "fd" in receipt_reservation:
                    _close_private_receipt_reservation(receipt_reservation)
                raise PostMutationInstallError("private-receipt-finalization-incomplete") from exc
            print(json.dumps({
                "schema_version": 1,
                "kind": "heim_pc.nixos_production_install_completed",
                "private_receipt_redacted": True,
            }, indent=2, sort_keys=True))
            return 0
        finally:
            release_production_apply_lock(apply_lock)
    except PostMutationInstallError as exc:
        print(POST_MUTATION_PUBLIC_MESSAGES[exc.code], file=sys.stderr)
        return 3
    except ProtectedEfiThawError:
        print(PROTECTED_EFI_RECOVERY_MESSAGE, file=sys.stderr)
        return 3
    except (ProductionInstallError, OSError, json.JSONDecodeError):
        print("nixos production install blocked by a safety check", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
