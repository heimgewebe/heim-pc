#!/usr/bin/env python3
"""Diagnostic-only PE certificate-table inspection for NixOS boot safety.

In particular, an `sbverify --list` exit status of zero does NOT prove the
presence of a signature table, much less Secure Boot trust. This deliberately
limited parser consumes only caller-preopened stdin/fd. It never opens
pathnames or devices, invokes sbverify, reads firmware, modifies EFI variables,
enrolls TPM keys, writes an ESP, or authorizes a physical NixOS installation.

Even a structurally present WIN_CERTIFICATE is UNAUTHENTICATED: it is not
verified against UEFI db/dbx, a trusted signer, executable integrity or an
entire signed loader/kernel/initrd/cmdline chain. The CLI always exits nonzero
so it cannot accidentally become a successful admission gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import stat
import time
import struct
import sys
from typing import Any

MAX_IMAGE_BYTES = 256 * 1024 * 1024
MAX_CERTIFICATE_TABLE_BYTES = 8 * 1024 * 1024
MAX_CERTIFICATE_COUNT = 16
READ_CHUNK_BYTES = 1024 * 1024
PIPE_READ_TIMEOUT_SECONDS = 10.0

_NON_CLAIMS = [
    "certificate_table_is_not_cryptographic_verification",
    "preopened_fd_source_and_execution_authority_not_established",
    "firmware_pk_kek_db_dbx_policy_not_verified",
    "whole_loader_kernel_initrd_cmdline_not_authenticated",
    "unchanged_popos_fallback_bootability_not_proven",
    "physical_seagate_apply_and_tpm2_enrollment_not_authorized",
]


class PEFormatError(ValueError):
    """Untrusted input could not be given a safe structural interpretation."""


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise PEFormatError("pe_header_truncated")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise PEFormatError("pe_header_truncated")
    return struct.unpack_from("<I", data, offset)[0]


def _result(*, signature_table: str, certificate_count: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_pe_signature_table_diagnostic",
        "status": (
            "certificate_table_unauthenticated"
            if signature_table == "structurally_present"
            else "unsigned"
        ),
        "signature_table": signature_table,
        "certificate_count": certificate_count,
        "cryptographic_signature_verified": False,
        "firmware_key_policy_verified": False,
        "full_bootchain_authenticated": False,
        "physical_install_authorized": False,
        "does_not_establish": list(_NON_CLAIMS),
    }


def inspect_bytes(data: bytes) -> dict[str, Any]:
    """Inspect only PE32/PE32+ certificate-table structure, not signatures."""
    if not isinstance(data, bytes) or not (0x40 <= len(data) <= MAX_IMAGE_BYTES):
        raise PEFormatError("unsafe_input")
    if data[:2] != b"MZ":
        raise PEFormatError("dos_magic_invalid")
    pe_start = _u32(data, 0x3C)
    if pe_start < 0x40 or pe_start + 24 > len(data):
        raise PEFormatError("pe_header_truncated")
    if data[pe_start:pe_start + 4] != b"PE\x00\x00":
        raise PEFormatError("pe_magic_invalid")

    coff = pe_start + 4
    sections = _u16(data, coff + 2)
    optional_bytes = _u16(data, coff + 16)
    optional = coff + 20
    optional_end = optional + optional_bytes
    section_headers_end = optional_end + sections * 40
    if optional_end > len(data) or section_headers_end > len(data):
        raise PEFormatError("pe_header_truncated")

    # PE/COFF section-table raw ranges are FILE OFFSETS. Security-directory
    # certificate bytes must never be accepted as a section's own raw data,
    # even when the certificate lies past every section HEADER.
    section_raw_ranges: list[tuple[int, int]] = []
    for index in range(sections):
        section_header = optional_end + index * 40
        raw_size = _u32(data, section_header + 16)
        raw_offset = _u32(data, section_header + 20)
        if raw_size == 0:
            continue
        if (
            raw_offset < section_headers_end
            or raw_offset > len(data)
            or raw_size > len(data) - raw_offset
        ):
            raise PEFormatError("section_raw_range_invalid")
        section_raw_ranges.append((raw_offset, raw_offset + raw_size))

    magic = _u16(data, optional)
    if magic == 0x20B:  # PE32+
        directory_count_offset, directory_start = 108, 112
    elif magic == 0x10B:  # PE32
        directory_count_offset, directory_start = 92, 96
    else:
        raise PEFormatError("optional_magic_unsupported")
    if optional_bytes < directory_start:
        raise PEFormatError("pe_header_truncated")
    directory_count = _u32(data, optional + directory_count_offset)
    if directory_count <= 4:
        return _result(signature_table="absent", certificate_count=0)

    # IMAGE_DIRECTORY_ENTRY_SECURITY is index 4. Unlike ordinary directories,
    # its address is a FILE OFFSET, never an RVA. Its size includes alignment.
    entry = optional + directory_start + 4 * 8
    if entry + 8 > optional_end:
        raise PEFormatError("pe_header_truncated")
    certificate_start = _u32(data, entry)
    certificate_bytes = _u32(data, entry + 4)
    if not certificate_start and not certificate_bytes:
        return _result(signature_table="absent", certificate_count=0)
    if not certificate_start or not certificate_bytes:
        raise PEFormatError("certificate_table_inconsistent")
    if (
        certificate_bytes > MAX_CERTIFICATE_TABLE_BYTES
        or certificate_bytes < 16
        or certificate_start % 8 != 0
        or certificate_start < section_headers_end
        or certificate_start > len(data)
        or certificate_bytes > len(data) - certificate_start
    ):
        raise PEFormatError("certificate_table_out_of_bounds")
    certificate_end = certificate_start + certificate_bytes
    if any(
        raw_start < certificate_end and certificate_start < raw_end
        for raw_start, raw_end in section_raw_ranges
    ):
        raise PEFormatError("certificate_overlaps_section_data")
    # Attribute certificates must occur *after* mapped section raw data.
    # They need not be the final bytes of the file: PE files may also carry
    # trailing non-mapped debug material after the certificate directory.
    if section_raw_ranges and certificate_start < max(
        raw_end for _, raw_end in section_raw_ranges
    ):
        raise PEFormatError("certificate_precedes_section_data")

    cursor = certificate_start
    end = certificate_start + certificate_bytes
    count = 0
    while cursor < end:
        if end - cursor < 8:
            raise PEFormatError("certificate_header_truncated")
        length = _u32(data, cursor)
        revision = _u16(data, cursor + 4)
        kind = _u16(data, cursor + 6)
        # WIN_CERTIFICATE is a structural wrapper. A nonempty payload can
        # still contain completely fabricated or untrusted signature bytes.
        if length < 9:
            raise PEFormatError("certificate_length_invalid")
        if revision != 0x0200 or kind != 0x0002:
            raise PEFormatError("certificate_format_unsupported")
        aligned = (length + 7) & ~7
        if aligned > end - cursor:
            raise PEFormatError("certificate_length_out_of_bounds")
        if any(data[cursor + length:cursor + aligned]):
            raise PEFormatError("certificate_padding_invalid")
        cursor += aligned
        count += 1
        if count > MAX_CERTIFICATE_COUNT:
            raise PEFormatError("certificate_count_unbounded")
    if not count or cursor != end:
        raise PEFormatError("certificate_table_inconsistent")
    return _result(signature_table="structurally_present", certificate_count=count)



def inspect_fd(fd: int) -> dict[str, Any]:
    """Inspect a caller-provided regular/pipe fd without opening any path.

    The descriptor number received from a caller is not stable when other
    threads may close/reassign it. A private duplicate pins one open file
    description BEFORE validation; subsequent fstat/poll/read use that dup.

    A dup shares regular-file offsets with the caller, so read with pread()
    at explicit offsets. This also leaves the caller's offset unchanged.
    The caller/source and malicious same-process FD-table manipulation
    remain outside this non-authoritative structural diagnostic.
    """
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
        raise PEFormatError("unsafe_input")
    pinned_fd = -1
    try:
        pinned_fd = os.dup(fd)
        before = os.fstat(pinned_fd)
        regular = stat.S_ISREG(before.st_mode)
        pipe = stat.S_ISFIFO(before.st_mode)
        # A borrowed fd may have been replaced BEFORE dup(); reject every
        # unapproved inode type before the first data-read system call.
        if not regular and not pipe:
            raise PEFormatError("unsafe_input")
        # poll() is only readiness advice: a competing reader may drain a
        # pipe *after* poll and *before* read. Accept pipes only when the
        # caller already opened the description with O_NONBLOCK. A dup shares
        # file status flags, so NEVER call os.set_blocking/fcntl F_SETFL here.
        # Blocking pipes fail before any read, keeping the timeout truthful.
        if pipe and os.get_blocking(pinned_fd):
            raise PEFormatError("blocking_pipe_unsupported")
        if regular:
            if (
                before.st_nlink != 1
                or before.st_size < 0x40
                or before.st_size > MAX_IMAGE_BYTES
            ):
                raise PEFormatError("unsafe_input")
            if os.lseek(pinned_fd, 0, os.SEEK_CUR) != 0:
                raise PEFormatError("input_offset")
        chunks: list[bytes] = []
        total = 0
        # A pipe with a live writer may never reach EOF. Time-bounded
        # polling is retained; the caller's O_NONBLOCK mode is untouched.
        poller = select.poll() if pipe else None
        deadline = time.monotonic() + PIPE_READ_TIMEOUT_SECONDS if pipe else None
        if poller is not None:
            poller.register(
                pinned_fd,
                select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
            )
        while total <= MAX_IMAGE_BYTES:
            if poller is not None:
                assert deadline is not None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PEFormatError("input_timeout")
                events = poller.poll(max(1, min(1000, int(remaining * 1000))))
                if not events:
                    continue
                if events[0][1] & (select.POLLERR | select.POLLNVAL):
                    raise PEFormatError("unsafe_input")
            count = min(READ_CHUNK_BYTES, MAX_IMAGE_BYTES + 1 - total)
            if regular:
                part = os.pread(pinned_fd, count, total)
            else:
                try:
                    part = os.read(pinned_fd, count)
                except BlockingIOError:
                    # Spurious POLLIN, or a concurrent reader consumed bytes;
                    # O_NONBLOCK guarantees this path cannot sleep on read.
                    continue
            if not part:
                break
            total += len(part)
            chunks.append(part)
        after = os.fstat(pinned_fd)
        keys = ("st_dev", "st_ino", "st_size", "st_mode", "st_nlink")
        if regular:
            keys += ("st_mtime_ns", "st_ctime_ns")
        if (
            any(getattr(before, name) != getattr(after, name) for name in keys)
            or (regular and total != before.st_size)
            or total > MAX_IMAGE_BYTES
        ):
            raise PEFormatError("input_drift")
        data = b"".join(chunks)
        finding = inspect_bytes(data)
        finding["input_sha256"] = hashlib.sha256(data).hexdigest()
        finding["input_size"] = total
        return finding
    except OSError as exc:
        raise PEFormatError("unsafe_input") from exc
    finally:
        if pinned_fd >= 0:
            os.close(pinned_fd)


def main(argv: list[str] | None = None) -> int:
    # argparse's default --help exits 0 BEFORE main() can return 2, which
    # could be mistaken for admission by wrappers that check only exit status.
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument(
        "--stdin", action="store_true", required=True,
        help="inspect already-open standard input (regular file or pipe; NO path opening)",
    )
    parser.parse_args(argv)
    try:
        item = inspect_fd(0)
    except PEFormatError as exc:
        item = {
            **_result(signature_table="not_proven", certificate_count=0),
            "status": (
                "unavailable"
                if str(exc) in {"unsafe_input", "blocking_pipe_unsupported", "input_timeout"}
                else "malformed"
            ),
            "reason_code": str(exc),
        }
    report = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_pe_signature_table_diagnostic_report",
        "findings": [{"input_index": 0, **item}],
        "cryptographic_signature_verified": False,
        "firmware_key_policy_verified": False,
        "full_bootchain_authenticated": False,
        "physical_install_authorized": False,
        "does_not_establish": list(_NON_CLAIMS),
    }
    json.dump(report, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    # Deliberately nonzero even when a WIN_CERTIFICATE table is present.
    # This diagnostic must never become a successful Secure Boot admission.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())