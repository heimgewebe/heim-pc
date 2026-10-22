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

ROOT = Path(__file__).resolve().parents[1]
BUILD_REV = "e68efce49eaba0014865fd1c4e0b62f692f016af"
BUILD_STATE = Path("/home/alex/.local/state/heim-pc-stage0-e68efce49eab")
BUILD_VOLUME = "heim-pc-nixos-stage0-e68efce49eab"
NIX_IMAGE = "sha256:98edc6813218e179ce84587373e0b52d4aa58babae2d26b51fb01e7fdacf815f"
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
STORE = re.compile(r"^/nix/store/[0-9a-z]{32}-nixos-(install|system-heim-pc-stage0)[a-zA-Z0-9._+-]*$")
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
        raise AdmissionError(f"command failed: {argv[0]} (exit={p.returncode})")
    return p


def output(*argv: str) -> str:
    return run(*argv).stdout.decode("utf-8", errors="strict").strip()


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def read_text(path: Path) -> str:
    demand(path.is_file() and not path.is_symlink(), f"missing/unsafe local build evidence: {path.name}")
    return path.read_text().strip()


def check_source() -> dict:
    revision = output("git", "-C", str(ROOT), "rev-parse", "HEAD")
    demand(re.fullmatch(r"[a-f0-9]{40}", revision), "invalid Git revision")
    demand(not output("git", "-C", str(ROOT), "status", "--porcelain"),
           "dirty repository: commit and re-review before planning")
    demand(run("git", "-C", str(ROOT), "merge-base", "--is-ancestor", BUILD_REV, "HEAD", check=False).returncode == 0,
           "built revision is not an ancestor of the installer revision")
    demand(not output("git", "-C", str(ROOT), "diff", "--name-only", BUILD_REV, "HEAD", "--", "nixos/system"),
           "Stage0 NixOS source changed since the realized build")
    demand(read_text(BUILD_STATE / "source-head") == BUILD_REV, "build/source revision mismatch")
    demand(read_text(BUILD_STATE / "closure-path") == SYSTEM, "build/system closure mismatch")
    demand(read_text(BUILD_STATE / "nix-image") == NIX_IMAGE, "Nix image mismatch")
    tools = read_text(BUILD_STATE / "stage0-tools").splitlines()
    demand(tools == [INSTALLER],
           "realized official nixos-install path differs from reviewed, pinned output")
    return {"revision": revision, "system": SYSTEM, "installer": tools[0],
            "image": NIX_IMAGE, "volume": BUILD_VOLUME,
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
                             "--output", "NAME,KNAME,TYPE,MODEL,SERIAL,SIZE,PTTYPE,PARTTYPE,PARTLABEL,PARTUUID,FSTYPE,LABEL,UUID,MOUNTPOINTS,RO,RM",
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


def live_snapshot(seagate: str, wd: str) -> dict:
    target, protected = by_id_disk(seagate), by_id_disk(wd)
    demand(target != protected and os.stat(seagate).st_rdev != os.stat(wd).st_rdev,
           "protected and target device aliases collide")
    disk, parts = disk_tree(seagate)
    wd_disk, wdparts = disk_tree(wd, exact_three=False)
    demand("ZP4000GP304001" in (disk.get("model") or "") and
           3_800_000_000_000 <= int(disk["size"]) <= 4_100_000_000_000,
           "Seagate model/size mismatch")
    demand("SN850X" in (wd_disk.get("model") or "") and
           1_800_000_000_000 <= int(wd_disk["size"]) <= 2_100_000_000_000,
           "protected WD model/size mismatch")
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
    st = filename.lstat()
    demand(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
           (st.st_mode & 0o077) == 0, "Apply requires a root-owned private plan (0600)")
    payload = filename.read_bytes()
    demand(len(payload) < 65536, "plan exceeds 64 KiB limit")
    plan = json.loads(payload)
    demand(plan.get("schema_version") == 1 and plan.get("profile") == "nonproductive-stage0",
           "wrong install plan kind")
    demand(plan.get("no_nvram_changes") is True and plan.get("wd_protected") is True,
           "unsafe stage0 plan")
    return plan, digest(payload)


def validated_shadow_metadata(shadow: Path) -> os.stat_result:
    demand(shadow.is_file() and not shadow.is_symlink(), "installed shadow unavailable")
    existing = shadow.stat()
    demand(existing.st_uid == 0 and (existing.st_mode & 0o007) == 0 and
           (existing.st_mode & stat.S_IWGRP) == 0 and existing.st_nlink == 1,
           "installed shadow ownership or permissions are unsafe")
    return existing


def credential_bootstrap(shadow: Path) -> None:
    existing = validated_shadow_metadata(shadow)
    original = shadow.read_text()
    rows = original.splitlines(keepends=True)
    indexes = [i for i, line in enumerate(rows) if line.startswith("alex:")]
    demand(len(indexes) == 1, "installed login user missing or duplicated")
    password = getpass.getpass("Stage0 login password (not logged): ")
    repeat = getpass.getpass("Repeat Stage0 login password: ")
    demand(password == repeat and len(password) >= 16,
           "Stage0 requires matching passwords of at least 16 characters")
    salt = secrets.token_urlsafe(12).replace("-", "a").replace("_", "b")[:16]
    hashed = output_hash(password, salt)
    del password, repeat
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


def verify_install_namespace(source: dict) -> None:
    """Prove chroot's mount propagation can run before touching Seagate GPT.

    The pinned NixOS nixos-enter uses unshare and mount --make-rprivate.
    Docker's default AppArmor profile blocks this even with SYS_ADMIN,
    so both this preflight and the real installer use the tested policy.
    The preflight has no target binds, host disks, or network.
    """
    cmd = [
        "/usr/bin/docker", "run", "--rm", "--network=none",
        "--cap-add=SYS_ADMIN", "--security-opt=seccomp=unconfined",
        "--security-opt=apparmor=unconfined", "--pids-limit=128",
        "--memory=2g",
        "--mount", f"type=volume,src={source['volume']},dst=/nix,readonly",
        "--entrypoint", "/nix/store/j2cwh4a23s7z65nyvjfck2axj2ci16ml-util-linux-minimal-2.42.2-bin/bin/unshare",
        source["image"], "--mount", "--uts", "--mount-proc", "--",
        "/nix/var/nix/profiles/default/bin/bash", "-c",
        "/nix/store/j2cwh4a23s7z65nyvjfck2axj2ci16ml-util-linux-minimal-2.42.2-bin/bin/mount --make-rprivate /",
    ]
    host_cmd(*cmd)


def verify_source_store(source: dict) -> None:
    """Fail before physical mutations if the existing Nix closure is corrupt."""
    cmd = [
        "/usr/bin/docker", "run", "--rm", "--network=none",
        "--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt", "no-new-privileges",
        "--cpus=3", "--memory=10g", "--pids-limit=512",
        "--mount", f"type=volume,src={source['volume']},dst=/nix",
        "--entrypoint", "/nix/var/nix/profiles/default/bin/nix",
        source["image"], "--extra-experimental-features", "nix-command",
        "store", "verify", "--recursive", source["system"], source["installer"],
    ]
    host_cmd(*cmd)


def copy_source_closure_to_target(source: dict) -> None:
    """Proven offline Nix copy: local unsigned build paths need --no-check-sigs.

    Source DB must be writable for Nix's local-store transaction/locks;
    the target remains isolated to the mounted Stage0 directory. Never
    permit a block device, host network or elevated SYS_ADMIN in this copy.
    """
    cmd = [
        "/usr/bin/docker", "run", "--rm", "--network=none",
        "--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt", "no-new-privileges",
        "--cpus=3", "--memory=10g", "--pids-limit=512",
        "--mount", f"type=volume,src={source['volume']},dst=/nix",
        "--mount", f"type=bind,src={NIX_ROOT},dst=/mnt",
        "--entrypoint", "/nix/var/nix/profiles/default/bin/nix",
        source["image"], "--extra-experimental-features", "nix-command",
        "copy", "--no-check-sigs", "--to", "local?root=/mnt",
        source["system"],
    ]
    host_cmd(*cmd)


def run_container(source: dict, *arguments: str) -> None:
    # The Nix store from the exact prebuilt Docker volume is readonly.
    # Only the bounded Seagate target mount is writable inside the container.
    command = [
        "/usr/bin/docker", "run", "--rm", "--network=none",
        "--cap-add=SYS_ADMIN", "--security-opt=seccomp=unconfined",
        "--security-opt=apparmor=unconfined",
        "--pids-limit=768", "--memory=10g",
        "--mount", f"type=volume,src={source['volume']},dst=/nix,readonly",
        "--mount", f"type=bind,src={NIX_ROOT},dst=/mnt",
        "--entrypoint", source["installer"] + "/bin/nixos-install",
        source["image"], "--root", "/mnt", "--system", source["system"],
        "--no-root-passwd", "--no-channel-copy", *arguments,
    ]
    host_cmd(*command)


def verify_installed_esp() -> None:
    boot = NIX_ROOT / "boot"
    demand((boot / "EFI/BOOT/BOOTX64.EFI").is_file(),
           "missing Seagate removable-path EFI bootloader")
    entries = list((boot / "loader/entries").glob("nixos*.conf"))
    demand(entries, "no systemd-boot NixOS entry")
    for entry in entries:
        data = entry.read_text()
        demand("initrd " in data and "linux " in data and "root=fstab" in data,
               "boot entry missing initrd, kernel or evaluated root=fstab")
        demand("NIXOS2_CRYPT" not in data and "rd.luks" not in data,
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


def require_immutable_install_source(source: dict) -> None:
    """Mandatory independent root-controlled seal is not yet implemented.

    A named Docker volume remains writable by another host/Docker client
    between verification and the privileged nixos-install launch. A
    container-local readonly mount, a Nix Store path pin and a recursive
    check are insufficient admission. This *intentionally* denies physical
    Apply until a reviewed, independently immutable source handoff exists.
    """
    demand(source.get("volume") == BUILD_VOLUME, "unrecognized Stage0 source volume")
    raise AdmissionError(
        "Stage0 physical Apply BLOCKED: Docker Nix source volume is mutable; "
        "independent root-owned immutable source seal and concurrency test required"
    )


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
    demand(output("docker", "image", "inspect", "-f", "{{.Id}}", source["image"]) == source["image"],
           "pinned Nix container image unavailable")
    vol = json.loads(output("docker", "volume", "inspect", source["volume"]))
    demand(len(vol) == 1 and vol[0].get("Driver") == "local", "unexpected Nix store volume")
    p3 = snapshot["seagate_by_id"] + "-part3"
    p1 = snapshot["seagate_by_id"] + "-part1"
    demand(not NIX_ROOT.exists() or not any(NIX_ROOT.iterdir()), "installation mount path is in use")
    demand(not Path("/nix").is_mount(), "host /nix must remain outside Stage0")
    demand(Path("/usr/bin/openssl").is_file(), "private credential hashing unavailable")
    verify_host_tools()
    verify_source_store(source)
    verify_install_namespace(source)

    # Block mutations begin only after every precondition above succeeded.
    mounts: list[Path] = []
    try:
        ensure_empty_mount_path(NIX_ROOT)
        (NIX_ROOT / "boot").mkdir(mode=0o700)
        host_cmd("mount", "-t", "vfat", "-o", "umask=0077,nodev,nosuid",
                 p1, str(NIX_ROOT / "boot"))
        mounts.append(NIX_ROOT / "boot")
        demand(not (NIX_ROOT / "boot/EFI/BOOT/BOOTX64.EFI").exists(),
               "Seagate ESP already contains a fallback bootloader; refusing overwrite")
        demand(not (NIX_ROOT / "boot/loader/entries").exists() and
               not (NIX_ROOT / "boot/loader/loader.conf").exists() and
               not (NIX_ROOT / "boot/EFI/systemd/systemd-bootx64.efi").exists(),
               "Seagate ESP already contains bootloader configuration; refusing overwrite")
        host_cmd("umount", str(NIX_ROOT / "boot"))
        mounts.pop()

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
        run_container(source)
        verify_installed_esp()
        credential_bootstrap(NIX_ROOT / "etc/shadow")
        same_protected_fingerprint(snapshot)
    finally:
        cleanup_target_mounts(mounts)
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