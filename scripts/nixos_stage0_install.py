#!/usr/bin/env python3
"""Nonproduction Seagate Stage0 installer. PLAN never changes a block device.

This installer is intentionally separate from nixos_production_install.py.
Physical APPLY belongs to the separately authorized hardware operator, never
to a CI job, build job, review agent, or implicit command.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib import error as url_error, request as url_request

ROOT = Path(__file__).resolve().parents[1]
BUILD_REV = "e68efce49eaba0014865fd1c4e0b62f692f016af"
BUILD_STATE = Path("/home/alex/.local/state/heim-pc-stage0-e68efce49eab")
BUILD_VOLUME = "heim-pc-nixos-stage0-e68efce49eab"
NIX_IMAGE = "sha256:98edc6813218e179ce84587373e0b52d4aa58babae2d26b51fb01e7fdacf815f"
SEALED_IMAGE = "sha256:91b210f35fe468e2901448b5d9dadbadcf12e3240121d573c08255028f874aa9"
SEALED_BUSYBOX_SHA256 = "b3c1009e1b5c927e537487c80639cdf404f69e3eb49371d9be5d841672be3ff9"
SEALED_SOURCE_ATTESTATION = Path("/etc/heim-pc/stage0-sealed-oci-source-v1.json")
SOURCE_PROTOTYPE_REPORT_SHA256 = "778bd0ea924717c2492661f4b03e4d9ce11de814a2ef10dc058318ccdbec865e"
SOURCE_SCRATCH_REPORT_SHA256 = "e82c5b85df9ed491b0d4a4686fe172f1ba4cf5c49d8c88e07b27cc7658a0f0cd"

SYSTEM = "/nix/store/9imhrwyy6bf5fkhqrjfx6dqn4rva8y67-nixos-system-heim-pc-stage0-26.05.20260829.c5c4a43"
INSTALLER = "/nix/store/k4a7p2ap87g5a7hvrdxx8ii9fb9fq5if-nixos-install"
NIX_ROOT = Path("/mnt/heim-pc-stage0")
EFI_LABEL = "NIXOS2_EFI"
RECOVERY_LABEL = "NIXOS2_RECOVERY"
ROOT_LABEL = "NIXOS_STAGE0_ROOT"
LUKS_GUID = "ca7d7ccb-63ed-4c53-861c-1742536059cc"
LINUX_GUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"
EFI_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
BY_ID = re.compile(r"^/dev/disk/by-id/nvme-[a-zA-Z0-9_.:+-]+$")
# Hardware-pinned Stage0 scope: never accept another similar model/size disk.
# All identities are verified again in Plan and immediately before Apply.
SEAGATE_BY_ID = "/dev/disk/by-id/nvme-Seagate_ZP4000GP304001_7VS01DX7"
WD_BY_ID = "/dev/disk/by-id/nvme-WD_BLACK_SN850X_2000GB_25025T802519"
SEAGATE_IDENTITY = {
    "model": "Seagate ZP4000GP304001", "serial": "7VS01DX7",
    "wwn": "eui.6479a7716f000a39", "size": 4000787030016,
    "gpt_guid": "b862830a-c8f1-4968-bf65-636b87bc2e85",
}
WD_IDENTITY = {
    "model": "WD_BLACK SN850X 2000GB", "serial": "25025T802519",
    "wwn": "eui.e8238fa6bf530001001b448b4d59e756",
    "size": 2000398934016,
    "gpt_guid": "79aa7645-4dea-4992-bf90-72e8d75e117b",
}
UTIL_LINUX = "/nix/store/j2cwh4a23s7z65nyvjfck2axj2ci16ml-util-linux-minimal-2.42.2-bin"
# Exact content (NAR) fingerprints remeasured from pinned standalone OCI image.
# A source Nix DB self-check alone must not authorize an alternate NAR.
SEALED_NAR = {
    SYSTEM: ("sha256-ocr+cay5yrcarnw5ZzFxQnht7pTQwC1HEMbU/i8zN4U=", 200200),
    INSTALLER: ("sha256-bxwMQvK0elYQJUdV2+uKVeGDf9TVHTz5v/8uhagZPs8=", 15464),
    UTIL_LINUX: ("sha256-QTeruJR6p/tf7gNryZqDMHuT63N9rqrADmS2aBuRB4I=", 8905168),
}
SUBVOLS = ("@root", "@nix", "@home", "@persist")
MIN_ROOT_SIZE = 3_000_000_000_000
MAX_ESP_FILES = 5000
MAX_ESP_BYTES = 2 * 1024**3
TRUSTED_HOST_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
APPLY_HOST_TOOLS = (
    "sgdisk", "udevadm", "wipefs", "lsblk", "sfdisk", "findmnt",
    "efibootmgr", "mount", "umount", "btrfs", "mkfs.btrfs", "git",
)


class AdmissionError(RuntimeError):
    """A fail-closed precondition, not permission to improvise."""


def demand(ok: object, why: str) -> None:
    if not ok:
        raise AdmissionError(why)


def run(*argv: str, check: bool = True, input_bytes: bytes | None = None, **kwargs) -> subprocess.CompletedProcess:
    if input_bytes is not None:
        kwargs["input"] = input_bytes
    p = subprocess.run(list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=False, **kwargs)
    if check and p.returncode:
        # Explicitly suppress diagnostics for anything that received secrets.
        # No command arguments, plaintext passwords, or environment are echoed.
        diagnostics = ""
        if input_bytes is None:
            diagnostics = p.stderr.decode("utf-8", errors="replace").splitlines()
            diagnostics = f": {diagnostics[0][:240]}" if diagnostics else ""
        raise AdmissionError(f"command failed: {argv[0]} (exit={p.returncode}){diagnostics}")
    return p


def output(*argv: str) -> str:
    return run(*argv).stdout.decode("utf-8", errors="strict").strip()


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def read_text(path: Path) -> str:
    """Read one evidence inode, disallowing a symlink substitution."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        demand(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size < 65536,
               f"missing/unsafe local build evidence: {path.name}")
        return stream.read(65536).decode("utf-8", errors="strict").strip()


def git_args(*arguments: str) -> tuple[str, ...]:
    """Allow only this exact, pinned checkout under root, without global git config."""
    return ("git", "-c", f"safe.directory={ROOT}",
            "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
            "-c", "diff.external=", "-C", str(ROOT), *arguments)


def check_source() -> dict:
    revision = output(*git_args("rev-parse", "HEAD"))
    demand(re.fullmatch(r"[a-f0-9]{40}", revision), "invalid Git revision")
    demand(not output(*git_args("status", "--porcelain")),
           "dirty repository: commit and re-review before planning")
    demand(run(*git_args("merge-base", "--is-ancestor", BUILD_REV, "HEAD"), check=False).returncode == 0,
           "built revision is not an ancestor of the installer revision")
    demand(not output(*git_args("diff", "--name-only", BUILD_REV, "HEAD", "--", "nixos/system")),
           "Stage0 NixOS source changed since the realized build")
    demand(read_text(BUILD_STATE / "source-head") == BUILD_REV, "build/source revision mismatch")
    demand(read_text(BUILD_STATE / "closure-path") == SYSTEM, "build/system closure mismatch")
    demand(read_text(BUILD_STATE / "nix-image") == NIX_IMAGE, "Nix image mismatch")
    tools = read_text(BUILD_STATE / "stage0-tools").splitlines()
    demand(tools == [INSTALLER] and UTIL_LINUX.startswith("/nix/store/"),
           "realized official nixos-install path differs from reviewed, pinned output")
    return {"revision": revision, "build_revision": BUILD_REV,
            "system": SYSTEM, "installer": tools[0],
            "image": SEALED_IMAGE, "builder_image": NIX_IMAGE,
            "source_kind": "sealed-oci-stage0-v1",
            "script_sha256": digest(Path(__file__).read_bytes())}


def by_id_disk(name: str) -> str:
    demand(BY_ID.fullmatch(name), "only explicit, whole-NVMe /dev/disk/by-id/nvme-* paths are accepted")
    demand(os.path.islink(name), "by-id disk alias is not a symlink")
    target = os.path.realpath(name)
    demand(re.fullmatch(r"/dev/nvme[0-9]+n[0-9]+", target), "by-id target is not a whole NVMe disk")
    mode = os.stat(name).st_mode
    demand(stat.S_ISBLK(mode), "by-id alias does not resolve to a block device")
    return target


def part_path(disk_alias: str, number: int, observed: dict) -> str:
    alias = f"{disk_alias}-part{number}"
    demand(os.path.islink(alias), f"missing private partition alias part{number}")
    observed_path = observed.get("name", "")
    demand(os.path.realpath(alias) == observed_path, f"part{number} by-id target differs from lsblk")
    demand(stat.S_ISBLK(os.stat(alias).st_mode), "partition alias is not a block device")
    return alias


def disk_tree(disk_alias: str, exact_three: bool = True) -> tuple[dict, dict[int, dict]]:
    data = json.loads(output("lsblk", "--json", "--bytes", "--paths",
                             "--output", "NAME,KNAME,TYPE,MODEL,SERIAL,WWN,SIZE,PTTYPE,PARTTYPE,PARTLABEL,PARTUUID,FSTYPE,LABEL,UUID,MOUNTPOINTS,RO,RM",
                             disk_alias))
    nodes = data.get("blockdevices", [])
    demand(len(nodes) == 1 and nodes[0]["type"] == "disk", "expected exactly one disk")
    disk = nodes[0]
    children = disk.get("children", [])
    demand((len(children) == 3 if exact_three else len(children) >= 1) and
           all(x.get("type") == "part" for x in children),
           "unexpected GPT partition structure")
    parts = {}
    for child in children:
        observed_name = child.get("name", "")
        demand(observed_name.startswith(disk["name"] + "p"), "partition name not under observed disk")
        suffix = observed_name[len(disk["name"]) + 1:]
        demand(suffix.isdigit(), "partition observation lacks a numeric suffix")
        n = int(suffix)
        demand(n > 0 and (not exact_three or n in (1, 2, 3)) and n not in parts,
               "missing/duplicate GPT partition number")
        parts[n] = child
    demand(not exact_three or len(parts) == 3, "incomplete target partition set")
    return disk, parts


def no_mounts_and_holders(disk: dict, parts: dict[int, dict]) -> None:
    for node in (disk, *parts.values()):
        demand(not [v for v in (node.get("mountpoints") or []) if v],
               "target disk or partition is mounted")
        kname = Path(node.get("kname", "")).name
        demand(re.fullmatch(r"[A-Za-z0-9_-]+", kname), "invalid kernel observation")
        holder_dir = Path("/sys/class/block") / kname / "holders"
        demand(holder_dir.is_dir() and not any(holder_dir.iterdir()),
               "active device-mapper or kernel holder on the target")
        demand(not bool(node.get("ro")), "target is read-only")


def hidden_signatures(part_alias: str) -> None:
    data = json.loads(output("wipefs", "--no-act", "--json", part_alias))
    demand(not data.get("signatures"), "hidden filesystem/RAID/LUKS signature on prospective Stage0 root")


def mounted_source(target: str) -> str:
    return output("findmnt", "-n", "-o", "SOURCE", "--mountpoint", target)


def protected_mounts_on_wd(wd_disk: str) -> None:
    wd_kernel = Path(wd_disk).name
    for path in ("/", "/boot/efi"):
        src = mounted_source(path)
        demand(src.startswith("/dev/"), f"protected mount {path} not backed by a block device")
        stack = output("lsblk", "-s", "-n", "-o", "KNAME", src).splitlines()
        demand(wd_kernel in [name.strip() for name in stack],
               f"protected mount {path} is not proven to be on WD")
    demand(output("findmnt", "-n", "-o", "FSTYPE", "--mountpoint", "/boot/efi") == "vfat",
           "Pop!_OS WD ESP is not mounted as vfat")


def wd_esp_tree_fingerprint(root: Path = Path("/boot/efi")) -> str:
    h = hashlib.sha256()
    count, total = 0, 0
    demand(root.is_dir() and not root.is_symlink(), "WD ESP is missing or symlinked")
    for parent, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for entry in dirs:
            demand(not (Path(parent) / entry).is_symlink(), "WD ESP contains a directory symlink")
        for entry in files:
            p = Path(parent) / entry
            st = p.lstat()
            demand(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "unexpected WD ESP entry")
            count += 1
            total += st.st_size
            demand(count <= MAX_ESP_FILES and total <= MAX_ESP_BYTES, "WD ESP fingerprint safety limit")
            h.update(str(p.relative_to(root)).encode() + b"\0")
            h.update(str(st.st_size).encode() + b"\0")
            with p.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    h.update(chunk)
            h.update(b"\0")
    demand(count > 0, "protected WD ESP unexpectedly empty")
    return h.hexdigest()


def require_disk_guid(dump: str, identity: dict, disk_name: str) -> None:
    """Reject a lookalike NVMe with a changed GPT disk GUID before planning."""
    matches = re.findall(r"(?mi)^label-id:\s*([0-9a-f-]{36})\s*$", dump)
    demand(len(matches) == 1 and matches[0].lower() == identity["gpt_guid"],
           f"{disk_name} GPT disk GUID differs from verified physical preimage")


def live_snapshot(seagate: str, wd: str) -> dict:
    demand(seagate == SEAGATE_BY_ID and wd == WD_BY_ID,
           "only the exact contract-bound Seagate target and protected WD aliases are allowed")
    target, protected = by_id_disk(seagate), by_id_disk(wd)
    demand(target != protected and os.stat(seagate).st_rdev != os.stat(wd).st_rdev,
           "protected and target device aliases collide")
    disk, parts = disk_tree(seagate)
    wd_disk, wdparts = disk_tree(wd, exact_three=False)
    for observed, expected, name in (
            (disk, SEAGATE_IDENTITY, "Seagate target"),
            (wd_disk, WD_IDENTITY, "protected WD")):
        demand(observed.get("model") == expected["model"] and
               observed.get("serial") == expected["serial"] and
               (observed.get("wwn") or "").lower() == expected["wwn"] and
               int(observed.get("size") or 0) == expected["size"],
               f"{name} model/serial/WWN/exact byte size mismatch")
    demand(disk.get("pttype") == "gpt" and wd_disk.get("pttype") == "gpt",
           "expected GPT on both internal NVMe disks")
    no_mounts_and_holders(disk, parts)
    protected_mounts_on_wd(protected)
    p1, p2, p3 = parts[1], parts[2], parts[3]
    demand(p1.get("parttype", "").lower() == EFI_GUID and p1.get("fstype") == "vfat" and
           p1.get("label") == EFI_LABEL, "Seagate ESP identity/format mismatch")
    demand(p2.get("fstype") == "ext4" and p2.get("label") == RECOVERY_LABEL,
           "Seagate recovery identity mismatch")
    demand(p3.get("parttype", "").lower() == LUKS_GUID and
           p3.get("partlabel") == "NIXOS2_CRYPT" and
           not p3.get("fstype") and not p3.get("uuid") and
           int(p3.get("size") or 0) >= MIN_ROOT_SIZE,
           "Seagate p3 must be empty, Linux-LUKS-GPT-typed historical preimage")
    for n, p in parts.items():
        demand(p.get("partuuid") and re.fullmatch(r"[a-fA-F0-9-]{36}", p["partuuid"]),
               f"Seagate part{n} PARTUUID missing")
        part_path(seagate, n, p)
    hidden_signatures(seagate + "-part3")
    demand(not os.path.lexists("/dev/disk/by-label/" + ROOT_LABEL),
           "duplicate/occupied Stage0 root label")
    labels = json.loads(output("lsblk", "--json", "--output", "NAME,TYPE,LABEL"))
    def walk(devices):
        for item in devices:
            yield item
            yield from walk(item.get("children") or [])
    seen = [item.get("label") for item in walk(labels.get("blockdevices", []))]
    demand(ROOT_LABEL not in seen and seen.count(EFI_LABEL) == 1,
           "duplicate/occupied root or Seagate EFI filesystem label on host")
    demand(os.path.realpath("/dev/disk/by-label/" + EFI_LABEL) == p1["name"],
           "Seagate EFI filesystem label is not unique and target-bound")
    wd_gpt = output("sfdisk", "--dump", wd)
    seagate_gpt = output("sfdisk", "--dump", seagate)
    require_disk_guid(wd_gpt, WD_IDENTITY, "protected WD")
    require_disk_guid(seagate_gpt, SEAGATE_IDENTITY, "Seagate target")
    return {
        "seagate_by_id": seagate, "wd_by_id": wd,
        "seagate_real": target, "wd_real": protected,
        "seagate": disk, "seagate_parts": parts,
        "wd": wd_disk, "wd_parts": wdparts,
        "wd_gpt_sha256": digest(wd_gpt.encode()),
        "seagate_gpt_sha256": digest(seagate_gpt.encode()),
        "wd_esp_sha256": wd_esp_tree_fingerprint(),
        "efi_boot_sha256": digest(output("efibootmgr", "-v").encode()),
        "root_source": mounted_source("/"),
        "wd_efi_source": mounted_source("/boot/efi"),
    }


def create_plan(filename: Path, seagate: str, wd: str) -> None:
    source = check_source()
    snapshot = live_snapshot(seagate, wd)
    plan = {"schema_version": 1, "profile": "nonproductive-stage0",
            "source": source, "snapshot": snapshot,
            "expected_p3_gpt_rewrite": {"from": LUKS_GUID, "to": LINUX_GUID},
            "no_nvram_changes": True,
            "wd_protected": True, "required_root_label": ROOT_LABEL}
    payload = canonical(plan) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(filename, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"stage0": "PLAN_ONLY", "plan_sha256": digest(payload),
                      "head": source["revision"], "system": SYSTEM, "apply": "NOT_PERFORMED"},
                     sort_keys=True))


def stored_plan(filename: Path) -> tuple[dict, str]:
    # fstat/read on the SAME inode; lstat + read_bytes was a symlink/rename race.
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        demand(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
               (st.st_mode & 0o077) == 0, "Apply requires a root-owned private plan (0600)")
        payload = stream.read(65536)
    demand(len(payload) < 65536, "plan exceeds 64 KiB limit")
    plan = json.loads(payload)
    demand(plan.get("schema_version") == 1 and plan.get("profile") == "nonproductive-stage0",
           "wrong install plan kind")
    demand(plan.get("no_nvram_changes") is True and plan.get("wd_protected") is True and
           plan.get("required_root_label") == ROOT_LABEL and
           plan.get("expected_p3_gpt_rewrite") == {"from": LUKS_GUID, "to": LINUX_GUID},
           "unsafe stage0 plan")
    snapshot = plan.get("snapshot")
    demand(isinstance(snapshot, dict), "Stage0 plan missing hardware snapshot")
    # JSON object keys are strings; disk_tree() and other live observations
    # use integer GPT partition numbers. Normalize after hashing the raw
    # immutable plan, so future direct lookups cannot silently diverge.
    for category in ("seagate_parts", "wd_parts"):
        if category in snapshot:
            parts = snapshot[category]
            demand(isinstance(parts, dict) and all(
                isinstance(n, str) and re.fullmatch(r"[1-9][0-9]*", n)
                for n in parts), f"unsafe {category} indices")
            snapshot[category] = {int(n): details for n, details in parts.items()}
    return plan, digest(payload)


def validated_shadow_metadata(shadow: Path) -> os.stat_result:
    demand(shadow.is_file() and not shadow.is_symlink(), "installed shadow unavailable")
    existing = shadow.stat()
    demand(existing.st_uid == 0 and (existing.st_mode & 0o007) == 0 and
           (existing.st_mode & stat.S_IWGRP) == 0 and existing.st_nlink == 1,
           "installed shadow ownership or permissions are unsafe")
    return existing


def prepare_private_credential_hash() -> str:
    """Collect and validate the password BEFORE the first disk/ESP effect."""
    for attempt in range(3):
        password = getpass.getpass("Stage0 login password (not logged): ")
        repeat = getpass.getpass("Repeat Stage0 login password: ")
        valid = password == repeat and len(password) >= 16
        if valid:
            salt = secrets.token_urlsafe(12).replace("-", "a").replace("_", "b")[:16]
            hashed = output_hash(password, salt)
            del password, repeat
            demand(bool(re.fullmatch(r"\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{1,128}", hashed)),
                   "invalid private password hash")
            return hashed
        del password, repeat
        if attempt < 2:
            print("Stage0 password mismatch/short; retry (no disk changes)", file=sys.stderr)
    raise AdmissionError("Stage0 requires matching passwords of at least 16 characters")


def credential_bootstrap(shadow: Path, hashed: str) -> None:
    demand(bool(re.fullmatch(r"\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{1,128}", hashed)),
           "invalid private password hash")
    existing = validated_shadow_metadata(shadow)
    original = shadow.read_text()
    rows = original.splitlines(keepends=True)
    indexes = [i for i, line in enumerate(rows) if line.startswith("alex:")]
    demand(len(indexes) == 1, "installed login user missing or duplicated")
    tokens = rows[indexes[0]].rstrip("\n").split(":")
    demand(len(tokens) == 9, "unexpected NixOS shadow record")
    demand(tokens[1] in ("!", "!!", "*", "!*"),
           "installed login account already has a password; refuse overwrite")
    tokens[1] = hashed
    rows[indexes[0]] = ":".join(tokens) + "\n"
    fd, temp = tempfile.mkstemp(prefix=".shadow-stage0-", dir=str(shadow.parent))
    try:
        os.fchmod(fd, stat.S_IMODE(existing.st_mode) & 0o640)
        os.fchown(fd, existing.st_uid, existing.st_gid)
        with os.fdopen(fd, "w") as f:
            f.writelines(rows)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, shadow)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    checked = validated_shadow_metadata(shadow)
    demand((checked.st_mode & 0o007) == 0 and
           any(line.startswith("alex:$6$") for line in shadow.read_text().splitlines()),
           "password bootstrap verification failed")


def output_hash(password: str, salt: str) -> str:
    p = run("/usr/bin/openssl", "passwd", "-6", "-salt", salt, "-stdin",
            input_bytes=(password + "\n").encode())
    result = p.stdout.decode().strip()
    demand(result.startswith("$6$") and "\n" not in result, "password hashing failed")
    return result


def ensure_empty_mount_path(p: Path) -> None:
    demand(not p.is_symlink(), "mount path cannot be a symlink")
    if p.exists():
        demand(p.is_dir() and not any(p.iterdir()), "preexisting mount path is nonempty")
    else:
        p.mkdir(mode=0o700, parents=True)


def host_cmd(*argv: str) -> None:
    run(*argv)


def same_protected_fingerprint(before: dict) -> None:
    after = live_protected_state(before["wd_by_id"])
    for field in ("wd_gpt_sha256", "wd_esp_sha256", "efi_boot_sha256",
                  "root_source", "wd_efi_source"):
        demand(before[field] == after[field], f"protected WD/firmware drift: {field}")


def live_protected_state(wd: str) -> dict:
    protected = by_id_disk(wd)
    protected_mounts_on_wd(protected)
    return {"wd_gpt_sha256": digest(output("sfdisk", "--dump", wd).encode()),
            "wd_esp_sha256": wd_esp_tree_fingerprint(),
            "efi_boot_sha256": digest(output("efibootmgr", "-v").encode()),
            "root_source": mounted_source("/"),
            "wd_efi_source": mounted_source("/boot/efi")}


def verify_host_tools() -> None:
    """All storage executables must exist BEFORE the first GPT mutation."""
    os.environ["PATH"] = TRUSTED_HOST_PATH
    for name in APPLY_HOST_TOOLS:
        resolved = shutil.which(name, path=TRUSTED_HOST_PATH)
        demand(bool(resolved) and Path(resolved).is_file() and os.access(resolved, os.X_OK),
               f"required host tool missing or unusable before GPT write: {name}")
    for name in ("btrfs", "mkfs.btrfs"):
        demand(bool(output(name, "--version")), f"unusable host Btrfs tool: {name}")


def _oci_command(source: dict, executable: str, *args: str,
                 target: bool = False, installer: bool = False) -> tuple[str, ...]:
    """Run only the pinned image, never a host-shared Nix source volume.

    /sealed-nix is a content-addressed Docker image lower layer. The BusyBox
    bind is within this single disposable container; all writable Nix DB
    metadata lives in its private, --rm-discarded overlay. No --volume-from,
    original Docker volume or physical /dev mount is admitted.
    """
    demand(source.get("image") == SEALED_IMAGE and
           source.get("source_kind") == "sealed-oci-stage0-v1" and
           "volume" not in source, "unsealed or mutable Stage0 source")
    demand(executable.startswith("/nix/store/") or
           executable == "/nix/var/nix/profiles/default/bin/nix",
           "untrusted OCI executable")
    cmd = ["/usr/bin/docker", "run", "--rm", "--pull=never", "--network=none"]
    if not installer:
        cmd += ["--cap-drop=ALL", "--cap-add=CHOWN",
                "--security-opt=no-new-privileges"]
    # Mounting the image-local /sealed-nix onto /nix requires SYS_ADMIN.
    # The original installer already needed SYS_ADMIN and unconfined seccomp
    # for nixos-enter; these rights are contained in this one Docker namespace.
    cmd += ["--cap-add=SYS_ADMIN", "--security-opt=seccomp=unconfined",
            "--security-opt=apparmor=unconfined", "--pids-limit=768",
            "--memory=10g" if installer or target else "--memory=2g"]
    if target:
        cmd += ["--mount", f"type=bind,src={NIX_ROOT},dst=/mnt"]
    cmd += ["--entrypoint", "/busybox", source["image"], "sh", "-ec",
            '/busybox mount --bind /sealed-nix /nix; exec "$@"',
            "stage0-source", executable, *args]
    return tuple(cmd)


def verify_install_namespace(source: dict) -> None:
    """Preflight the actual pinned unshare+mount path, without host devices."""
    host_cmd(*_oci_command(source, UTIL_LINUX + "/bin/unshare",
                          "--mount", "--uts", "--mount-proc", "--",
                          UTIL_LINUX + "/bin/mount", "--make-rprivate", "/"))


def verify_source_store(source: dict) -> None:
    """Verify closures and independently pinned NAR identities, before GPT."""
    host_cmd(*_oci_command(
        source, "/nix/var/nix/profiles/default/bin/nix",
        "--extra-experimental-features", "nix-command",
        "store", "verify", "--recursive",
        source["system"], source["installer"], UTIL_LINUX))
    details = json.loads(output(*_oci_command(
        source, "/nix/var/nix/profiles/default/bin/nix",
        "--extra-experimental-features", "nix-command",
        "path-info", "--json", source["system"], source["installer"], UTIL_LINUX)))
    demand(isinstance(details, dict) and set(details) == set(SEALED_NAR),
           "sealed OCI source NAR entries missing/changed")
    for path, (nar_hash, nar_size) in SEALED_NAR.items():
        item = details.get(path)
        demand(isinstance(item, dict) and item.get("narHash") == nar_hash and
               item.get("narSize") == nar_size,
               "sealed OCI source NAR hash or size differs from reviewed build")


def copy_source_closure_to_target(source: dict) -> None:
    """Offline copy from a new OCI lower-layer snapshot into Seagate mount."""
    host_cmd(*_oci_command(
        source, "/nix/var/nix/profiles/default/bin/nix",
        "--extra-experimental-features", "nix-command",
        "copy", "--no-check-sigs", "--to", "local?root=/mnt",
        source["system"], target=True))


def verify_target_store(source: dict) -> None:
    """Verify byte-level integrity of the copied unsigned target closure.

    --no-trust disables the signature expectation for the locally built,
    unsigned Stage0 closure but NOT its recursive contents hash check.
    Source provenance is separately constrained by verified OCI/NAR seal.
    """
    host_cmd(*_oci_command(
        source, "/nix/var/nix/profiles/default/bin/nix",
        "--extra-experimental-features", "nix-command",
        "store", "verify", "--no-trust", "--recursive",
        "--store", "local?root=/mnt", source["system"], target=True))


def run_container(source: dict, *arguments: str) -> None:
    """Invoke pinned official nixos-install from independent sealed OCI source."""
    host_cmd(*_oci_command(
        source, source["installer"] + "/bin/nixos-install",
        "--root", "/mnt", "--system", source["system"],
        "--no-root-passwd", "--no-channel-copy", *arguments,
        target=True, installer=True))


def verify_installed_esp() -> None:
    boot = NIX_ROOT / "boot"
    fallback = boot / "EFI/BOOT/BOOTX64.EFI"
    demand(fallback.is_file() and fallback.stat().st_size > 0,
           "missing/empty Seagate removable-path EFI bootloader")
    entries = list((boot / "loader/entries").glob("nixos*.conf"))
    demand(entries, "no systemd-boot NixOS entry")
    for entry in entries:
        demand(entry.is_file() and not entry.is_symlink(), "unsafe EFI loader entry")
        fields: dict[str, list[str]] = {}
        for line in entry.read_text().splitlines():
            chunks = line.strip().split(maxsplit=1)
            if len(chunks) == 2 and chunks[0] in ("linux", "initrd", "options"):
                fields.setdefault(chunks[0], []).append(chunks[1])
        demand(all(len(fields.get(field, [])) == 1 for field in ("linux", "initrd", "options")),
               "boot entry missing/duplicate kernel, initrd or options")
        args = fields["options"][0].split()
        demand("root=fstab" in args and f"init={SYSTEM}/init" in args,
               "boot entry missing source-bound init= or evaluated root=fstab")
        for field in ("linux", "initrd"):
            # Relative paths, embedded whitespace and traversal are never permitted.
            reference = fields[field][0]
            demand(reference.startswith("/") and not reference.startswith("//") and
                   len(reference.split()) == 1 and
                   all(part not in ("", ".", "..") for part in reference[1:].split("/")),
                   "unsafe boot entry kernel/initrd path")
            artifact = boot / reference.lstrip("/")
            demand(artifact.is_file() and not artifact.is_symlink() and artifact.stat().st_size > 0,
                   f"missing/empty installed {field} image")
        demand("NIXOS2_CRYPT" not in fields["options"][0] and
               not any(arg.startswith("rd.luks") for arg in args),
               "nonproduction boot entry unexpectedly references LUKS")
    demand((NIX_ROOT / "etc/shadow").is_file(), "installed NixOS shadow not found")


def cleanup_target_mounts(mounts: list[Path]) -> None:
    """A failed unmount is never a successful Stage0 installation."""
    failures = []
    for path in reversed(mounts):
        try:
            host_cmd("umount", str(path))
            demand(not path.is_mount(), "mount remains active after umount")
        except AdmissionError:
            failures.append(str(path))
            print(f"ALARM: failed to unmount {path}; manual recovery required",
                  file=sys.stderr)
    demand(not failures, "Stage0 cleanup incomplete; installation NOT confirmed")


def _github_public_json(url: str) -> dict:
    """Read two fixed GitHub API resources over verified HTTPS; never trust local URLs."""
    request = url_request.Request(
        url, headers={"Accept": "application/vnd.github+json",
                      "User-Agent": "heim-pc-stage0-source-review",
                      "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with url_request.urlopen(request, timeout=10) as response:
            demand(response.status == 200 and response.geturl() == url,
                   "Stage0 physical Apply BLOCKED: GitHub review endpoint redirected/invalid")
            raw = response.read(65537)
    except (url_error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise AdmissionError(
            "Stage0 physical Apply BLOCKED: authenticated GitHub review unavailable"
        ) from exc
    demand(len(raw) <= 65536, "Stage0 physical Apply BLOCKED: GitHub review response oversized")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AdmissionError(
            "Stage0 physical Apply BLOCKED: GitHub review response invalid"
        ) from exc
    demand(isinstance(result, dict), "Stage0 physical Apply BLOCKED: GitHub review response not an object")
    return result


def require_authenticated_github_review(review: dict, source: dict) -> None:
    """Authenticate a current independent APPROVED review, not a root JSON claim.

    Public GitHub HTTPS is the authority for review identity, state and commit.
    On absent network, revoked/stale approval, foreign or self-review: deny.
    This is SOURCE review only; separate disk-loss/TTY/recovery authority remains.
    """
    match = re.fullmatch(
        r"https://github[.]com/heimgewebe/heim-pc/pull/238#pullrequestreview-([0-9]+)",
        review["review_url"])
    demand(match is not None, "Stage0 physical Apply BLOCKED: invalid GitHub review locator")
    review_id = int(match.group(1))
    remote_review = _github_public_json(
        f"https://api.github.com/repos/heimgewebe/heim-pc/pulls/238/reviews/{review_id}")
    pr = _github_public_json("https://api.github.com/repos/heimgewebe/heim-pc/pulls/238")
    reviewer = remote_review.get("user") or {}
    author = pr.get("user") or {}
    demand(isinstance(reviewer, dict) and isinstance(author, dict),
           "Stage0 physical Apply BLOCKED: malformed GitHub identities")
    demand(remote_review.get("id") == review_id and
           remote_review.get("html_url") == review["review_url"] and
           remote_review.get("state") == "APPROVED" and
           remote_review.get("commit_id") == source["revision"] and
           remote_review.get("author_association") in ("OWNER", "MEMBER", "COLLABORATOR") and
           reviewer.get("login") == review["reviewer"] and
           isinstance(reviewer.get("id"), int) and reviewer["id"] > 0 and
           isinstance(author.get("id"), int) and author["id"] != reviewer["id"] and
           pr.get("number") == 238 and
           isinstance(pr.get("head"), dict) and
           pr["head"].get("sha") == source["revision"] and
           pr["head"].get("ref") == "feat/nixos-seagate-no-usb-stage0-20261022" and
           isinstance(pr.get("base"), dict) and
           pr["base"].get("ref") == "main" and
           (pr.get("state") == "open" or
            (pr.get("state") == "closed" and pr.get("merged") is True)),
           "Stage0 physical Apply BLOCKED: GitHub approval absent, stale, dismissed, self-issued or unauthorized")


def require_immutable_install_source(source: dict) -> None:
    """Require an external, root-controlled revision-bound source release.

    Local Docker image IDs address immutable image CONFIG+layer digests under
    the trusted local Docker daemon. A root-owned release record ties this
    exact candidate back to the realized Nix build, reviewed source/script,
    independent evidence and BusyBox helper. It is deliberately NOT created
    automatically; until the hardware/source approver supplies it the physical
    Apply stays blocked. Host-root/daemon compromise is outside this model.
    """
    demand(source.get("source_kind") == "sealed-oci-stage0-v1" and
           source.get("image") == SEALED_IMAGE and
           source.get("builder_image") == NIX_IMAGE and
           source.get("build_revision") == BUILD_REV and
           source.get("system") == SYSTEM and
           source.get("installer") == INSTALLER and
           "volume" not in source,
           "Stage0 physical Apply BLOCKED: unsealed or mutable source identity")
    parent = SEALED_SOURCE_ATTESTATION.parent
    try:
        pstat = parent.lstat()
        demand(stat.S_ISDIR(pstat.st_mode) and pstat.st_uid == 0 and
               not (pstat.st_mode & 0o022),
               "Stage0 physical Apply BLOCKED: attestation directory unsafe")
        fd = os.open(SEALED_SOURCE_ATTESTATION,
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            st = os.fstat(stream.fileno())
            demand(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
                   st.st_nlink == 1 and not (st.st_mode & 0o077) and
                   st.st_size < 8192,
                   "Stage0 physical Apply BLOCKED: source seal is not private/root-owned")
            raw = stream.read(8192)
    except (FileNotFoundError, PermissionError, NotADirectoryError) as exc:
        raise AdmissionError(
            "Stage0 physical Apply BLOCKED: independent root-owned OCI source seal missing"
        ) from exc
    try:
        attestation = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AdmissionError("Stage0 physical Apply BLOCKED: invalid source seal JSON") from exc
    expected = {
        "schema_version": 1,
        "kind": "heim-pc-stage0-sealed-oci-source-v1",
        "image_id": SEALED_IMAGE,
        "original_nix_builder_image": NIX_IMAGE,
        "original_build_revision": BUILD_REV,
        "system_store": SYSTEM,
        "installer_store": INSTALLER,
        "util_linux_store": UTIL_LINUX,
        "system_nar_hash": SEALED_NAR[SYSTEM][0],
        "system_nar_size": SEALED_NAR[SYSTEM][1],
        "installer_nar_hash": SEALED_NAR[INSTALLER][0],
        "installer_nar_size": SEALED_NAR[INSTALLER][1],
        "util_linux_nar_hash": SEALED_NAR[UTIL_LINUX][0],
        "util_linux_nar_size": SEALED_NAR[UTIL_LINUX][1],
        "busybox_sha256": SEALED_BUSYBOX_SHA256,
        "source_prototype_report_sha256": SOURCE_PROTOTYPE_REPORT_SHA256,
        "source_scratch_report_sha256": SOURCE_SCRATCH_REPORT_SHA256,
        "reviewed_source_head": source["revision"],
        "reviewed_installer_script_sha256": source["script_sha256"],
    }
    demand(isinstance(attestation, dict) and
           set(attestation) == set(expected) | {"independent_review_receipt_sha256"} and
           all(attestation.get(k) == v for k, v in expected.items()) and
           isinstance(attestation.get("independent_review_receipt_sha256"), str) and
           bool(re.fullmatch(r"[0-9a-f]{64}",
                             attestation["independent_review_receipt_sha256"])),
           "Stage0 physical Apply BLOCKED: source attestation/provenance mismatch")
    # A reviewer SHA by itself can be an arbitrary 64-hex string. Require
    # the actual separately root-protected receipt and bind its exact bytes.
    review_path = SEALED_SOURCE_ATTESTATION.with_name("stage0-independent-source-review-v1.json")
    try:
        fd = os.open(review_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            review_stat = os.fstat(stream.fileno())
            demand(stat.S_ISREG(review_stat.st_mode) and
                   review_stat.st_uid == 0 and review_stat.st_nlink == 1 and
                   not (review_stat.st_mode & 0o077) and
                   0 < review_stat.st_size < 8192,
                   "Stage0 physical Apply BLOCKED: independent review receipt is unsafe")
            review_raw = stream.read(8192)
    except (FileNotFoundError, PermissionError, NotADirectoryError) as exc:
        raise AdmissionError(
            "Stage0 physical Apply BLOCKED: independent source review receipt missing"
        ) from exc
    demand(digest(review_raw) == attestation["independent_review_receipt_sha256"],
           "Stage0 physical Apply BLOCKED: independent review receipt hash mismatch")
    try:
        review = json.loads(review_raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AdmissionError("Stage0 physical Apply BLOCKED: review receipt malformed") from exc
    demand(isinstance(review, dict) and
           review.get("schema_version") == 1 and
           review.get("kind") == "heim-pc-stage0-source-security-review-v1" and
           review.get("source_head") == source["revision"] and
           review.get("installer_script_sha256") == source["script_sha256"] and
           review.get("image_id") == SEALED_IMAGE and
           review.get("disposition") == "APPROVE_SOURCE_ONLY" and
           isinstance(review.get("reviewer"), str) and
           3 <= len(review["reviewer"]) <= 128 and
           isinstance(review.get("review_url"), str) and
           bool(re.fullmatch(
               r"https://github[.]com/heimgewebe/heim-pc/pull/238#pullrequestreview-[0-9]+",
               review["review_url"])),
           "Stage0 physical Apply BLOCKED: independent review does not approve this source")
    # This must succeed before any Docker/source check or hardware snapshot.
    # A root-owned syntactically plausible review JSON is NOT approval.
    require_authenticated_github_review(review, source)
    # Before a hardware snapshot or GPT write, verify exact image identity
    # and the binary hash of the helper that will make the in-container bind.
    demand(output("/usr/bin/docker", "image", "inspect", "--format",
                  "{{.Id}}", SEALED_IMAGE) == SEALED_IMAGE,
           "Stage0 physical Apply BLOCKED: OCI image digest mismatch")
    fingerprint = output(
        "/usr/bin/docker", "run", "--rm", "--pull=never", "--network=none",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--entrypoint", "/busybox", SEALED_IMAGE,
        "sha256sum", "/busybox").split()
    demand(len(fingerprint) == 2 and
           fingerprint[0] == SEALED_BUSYBOX_SHA256 and
           fingerprint[1] == "/busybox",
           "Stage0 physical Apply BLOCKED: OCI mount helper integrity mismatch")


def apply_plan(filename: Path, confirmation: str) -> None:
    demand(os.geteuid() == 0, "Apply must be root")
    demand(sys.stdin.isatty() and sys.stderr.isatty(), "Apply requires a real interactive TTY")
    plan, plan_sha = stored_plan(filename)
    demand(confirmation == f"APPLY-STAGE0:{plan_sha}", "confirmation token mismatch")
    source = check_source()
    demand(source == plan["source"], "source revision/script/tool identity drift")
    # Closed hardware admission: never enter the verify/copy/privileged Docker
    # race while its root-controlled, immutable source seal is unavailable.
    require_immutable_install_source(source)
    snapshot = live_snapshot(plan["snapshot"]["seagate_by_id"], plan["snapshot"]["wd_by_id"])
    demand(canonical(snapshot) == canonical(plan["snapshot"]),
           "current hardware differs from private plan")
    p3 = snapshot["seagate_by_id"] + "-part3"
    p1 = snapshot["seagate_by_id"] + "-part1"
    demand(not NIX_ROOT.exists() or not any(NIX_ROOT.iterdir()), "installation mount path is in use")
    demand(not Path("/nix").is_mount(), "host /nix must remain outside Stage0")
    demand(Path("/usr/bin/openssl").is_file(), "private credential hashing unavailable")
    verify_host_tools()
    verify_source_store(source)
    verify_install_namespace(source)
    # Password errors must never strand a formatted Seagate with a locked user.
    hashed = prepare_private_credential_hash()

    # Block mutations begin only after every precondition above succeeded.
    mounts: list[Path] = []
    root_was_created = not NIX_ROOT.exists()
    try:
        ensure_empty_mount_path(NIX_ROOT)
        (NIX_ROOT / "boot").mkdir(mode=0o700)
        # Before any GPT effect, inspect the existing Seagate ESP read-only.
        # A writable VFAT probe may alter filesystem metadata even if it
        # merely checks for pre-existing bootloader files.
        host_cmd("mount", "-t", "vfat", "-o", "ro,umask=0077,nodev,nosuid",
                 p1, str(NIX_ROOT / "boot"))
        mounts.append(NIX_ROOT / "boot")
        demand(not (NIX_ROOT / "boot/EFI/BOOT/BOOTX64.EFI").exists(),
               "Seagate ESP already contains a fallback bootloader; refusing overwrite")
        demand(not (NIX_ROOT / "boot/loader/entries").exists() and
               not (NIX_ROOT / "boot/loader/loader.conf").exists() and
               not (NIX_ROOT / "boot/EFI/systemd/systemd-bootx64.efi").exists(),
               "Seagate ESP already contains bootloader configuration; refusing overwrite")
        host_cmd("umount", str(NIX_ROOT / "boot"))
        demand(not (NIX_ROOT / "boot").is_mount(), "ESP preflight mount still active")
        mounts.pop()
        # The Btrfs root is NOT mounted yet. Do not leave a host /boot stub.
        (NIX_ROOT / "boot").rmdir()
        demand(not any(NIX_ROOT.iterdir()), "ESP preflight left host files")

        # Correct the historical Linux-LUKS GPT type before plain Btrfs format.
        host_cmd("sgdisk", "--typecode=3:8300", "--change-name=3:NIXOS_STAGE0_ROOT",
                 snapshot["seagate_by_id"])
        host_cmd("udevadm", "settle", "--timeout=20")
        updated, updated_parts = disk_tree(snapshot["seagate_by_id"])
        demand(updated_parts[3].get("parttype", "").lower() == LINUX_GUID and
               updated_parts[3].get("partlabel") == ROOT_LABEL,
               "Seagate GPT type rewrite did not converge")
        demand(updated_parts[1] == snapshot["seagate_parts"][1] and
               updated_parts[2] == snapshot["seagate_parts"][2] and
               updated_parts[3].get("partuuid") == snapshot["seagate_parts"][3]["partuuid"] and
               updated_parts[3].get("size") == snapshot["seagate_parts"][3]["size"],
               "Seagate ESP/recovery partition changed or root geometry drifted")
        same_protected_fingerprint(snapshot)
        hidden_signatures(p3)
        host_cmd("mkfs.btrfs", "-L", ROOT_LABEL, p3)
        host_cmd("udevadm", "settle", "--timeout=20")
        host_cmd("mount", "-t", "btrfs", "-o", "compress=zstd", p3, str(NIX_ROOT))
        mounts.append(NIX_ROOT)
        for name in SUBVOLS:
            host_cmd("btrfs", "subvolume", "create", str(NIX_ROOT / name))
        host_cmd("umount", str(NIX_ROOT))
        mounts.pop()
        for target, name in (("", "@root"), ("nix", "@nix"), ("home", "@home"), ("persist", "@persist")):
            where = NIX_ROOT / target
            where.mkdir(mode=0o700, parents=True, exist_ok=True)
            host_cmd("mount", "-t", "btrfs", "-o", f"subvol={name},compress=zstd",
                     p3, str(where))
            mounts.append(where)
        (NIX_ROOT / "boot").mkdir(mode=0o700, exist_ok=True)
        host_cmd("mount", "-t", "vfat", "-o", "umask=0077,nodev,nosuid",
                 p1, str(NIX_ROOT / "boot"))
        mounts.append(NIX_ROOT / "boot")
        demand(os.path.realpath("/dev/disk/by-label/" + ROOT_LABEL) == updated_parts[3]["name"],
               "Stage0 root label is ambiguous after formatting")
        same_protected_fingerprint(snapshot)
        copy_source_closure_to_target(source)
        verify_target_store(source)
        run_container(source)
        verify_installed_esp()
        credential_bootstrap(NIX_ROOT / "etc/shadow", hashed)
        same_protected_fingerprint(snapshot)
    finally:
        cleanup_target_mounts(mounts)
        # Only remove the host directory we created, never non-empty/active
        # directories or any Btrfs directory while the target remains mounted.
        if NIX_ROOT.exists() and not NIX_ROOT.is_mount():
            residual = NIX_ROOT / "boot"
            if residual.exists():
                demand(residual.is_dir() and not residual.is_symlink() and
                       not residual.is_mount() and not any(residual.iterdir()),
                       "unsafe residual host ESP mount path")
                residual.rmdir()
            if root_was_created:
                demand(not any(NIX_ROOT.iterdir()), "Stage0 host mount path still occupied")
                NIX_ROOT.rmdir()
    print(json.dumps({"stage0": "INSTALLED_REQUIRES_PHYSICAL_BOOT_TEST",
                      "system": SYSTEM, "wd_and_nvram_unchanged": True},
                     sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--plan", action="store_true")
    operation.add_argument("--apply", action="store_true")
    parser.add_argument("--seagate-by-id")
    parser.add_argument("--wd-by-id")
    parser.add_argument("--plan-file", required=True, type=Path)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        os.environ["PATH"] = TRUSTED_HOST_PATH
        if args.plan:
            demand(args.seagate_by_id and args.wd_by_id and not args.confirm,
                   "plan requires both disk aliases and no confirmation token")
            create_plan(args.plan_file, args.seagate_by_id, args.wd_by_id)
        else:
            demand(not args.seagate_by_id and not args.wd_by_id,
                   "apply derives immutable disk identities exclusively from its saved plan")
            apply_plan(args.plan_file, args.confirm)
    except (AdmissionError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"STAGE0_FAIL_CLOSED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())