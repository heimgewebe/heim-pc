"""Read the actual systemd-boot EFI default without requiring /dev access.

The lifecycle-audit unit uses PrivateDevices=true.  bootctl itself needs the
underlying ESP block device, but the EFI variable and mounted entry files can
be read safely inside that existing sandbox.
"""

import hashlib
from pathlib import Path
import re
import sys


EFI_DEFAULT = Path(
    "/sys/firmware/efi/efivars/"
    "LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
)
LOADER_CONF = Path("/boot/loader/loader.conf")
ENTRIES = Path("/boot/loader/entries")
ENTRY_ID = re.compile(r"nixos-[A-Za-z0-9_.+\-]{1,180}\.conf\Z")
HASH_ENTRY = re.compile(r"nixos-([0-9a-f]{64})(?:\+[0-9]+(?:-[0-9]+)?)?\.conf\Z")
INIT_PATH = re.compile(
    r"init=(/nix/store/[a-z0-9]{32}-nixos-system-[A-Za-z0-9_.+\-]+)/init\Z"
)


def read_efi_default(
    efi_var: Path = EFI_DEFAULT,
    loader_conf: Path = LOADER_CONF,
    entries: Path = ENTRIES,
) -> tuple[str, str]:
    if efi_var.is_symlink():
        raise ValueError("EFI default variable is a symlink")
    variable = efi_var.read_bytes()
    if not 6 <= len(variable) <= 512 or len(variable) % 2:
        raise ValueError("EFI default variable length invalid")
    entry_id = variable[4:].decode("utf-16-le")
    if not entry_id.endswith("\0") or "\0" in entry_id[:-1]:
        raise ValueError("EFI default variable terminator invalid")
    entry_id = entry_id[:-1]
    if ENTRY_ID.fullmatch(entry_id) is None:
        raise ValueError("EFI default entry is not a NixOS entry")

    defaults = [
        line.split(maxsplit=1)[1]
        for line in loader_conf.read_text(encoding="utf-8").splitlines()
        if line.startswith("default ")
    ]
    if defaults != [entry_id]:
        raise ValueError("loader.conf and EFI default disagree")

    entry_hash = HASH_ENTRY.fullmatch(entry_id)
    entry = entries / entry_id
    if entry_hash and not entry.exists():
        # systemd-boot boot counting modifies the filename but retains the
        # stable content-hash ID in the EFI default variable.
        stem = entry_id[:-5]
        candidates = [
            path for path in entries.glob(stem + "+*.conf")
            if re.fullmatch(
                re.escape(stem) + r"\+[0-9]+(?:-[0-9]+)?\.conf", path.name
            )
        ]
        if len(candidates) != 1:
            raise ValueError("EFI default counted entries missing or ambiguous")
        entry = candidates[0]
    if entry.is_symlink() or not entry.is_file() or entry.stat().st_size > 65536:
        raise ValueError("EFI default entry missing or unsafe")
    entry_bytes = entry.read_bytes()
    if entry_hash and hashlib.sha256(entry_bytes).hexdigest() != entry_hash.group(1):
        raise ValueError("EFI default content hash mismatch")
    options = [
        line[8:]
        for line in entry_bytes.decode("utf-8").splitlines()
        if line.startswith("options ")
    ]
    if len(options) != 1:
        raise ValueError("EFI default has missing or ambiguous options")
    init_tokens = [word for word in options[0].split() if word.startswith("init=")]
    if len(init_tokens) != 1:
        raise ValueError("EFI default has missing or ambiguous init")
    matched = INIT_PATH.fullmatch(init_tokens[0])
    if matched is None:
        raise ValueError("EFI default init is not a NixOS system store closure")
    if efi_var.read_bytes() != variable:
        raise ValueError("EFI default changed during readback")
    return entry_id, matched.group(1)


if __name__ == "__main__":
    try:
        boot_entry, system = read_efi_default()
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"EFI boot default audit unavailable: {exc}", file=sys.stderr)
        sys.exit(1)
    print(boot_entry, system)
