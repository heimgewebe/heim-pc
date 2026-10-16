#!/usr/bin/env python3
"""Diagnostic-only PE certificate-table inspection for NixOS boot safety.

In particular, an `sbverify --list` exit status of zero does NOT prove the
presence of a signature table, much less Secure Boot trust. This deliberately
limited parser consumes only caller-preopened stdin/fd. It never opens PE
input pathnames or block devices, invokes sbverify, reads firmware,
modifies EFI variables,
enrolls TPM keys, writes an ESP, or authorizes a physical NixOS installation.

Even a structurally present WIN_CERTIFICATE is UNAUTHENTICATED: it is not
verified against UEFI db/dbx, a trusted signer, executable integrity or an
entire signed loader/kernel/initrd/cmdline chain. The CLI always exits nonzero
so it cannot accidentally become a successful admission gate.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import marshal
import os
import selectors
import stat
import struct
import subprocess
import sys
import time
from typing import Any

MAX_IMAGE_BYTES = 256 * 1024 * 1024
MAX_CERTIFICATE_TABLE_BYTES = 8 * 1024 * 1024
MAX_CERTIFICATE_COUNT = 16
MAX_SECTION_COUNT = 96
READ_CHUNK_BYTES = 1024 * 1024
# Bounded child-pipe read phase, not an end-to-end caller deadline.
# A blocked kernel I/O child might not be immediately
# killable: this limits the caller, not resource cleanup in D-state.
WORKER_DEADLINE_SECONDS = 5.0

# Code objects are captured ONCE after this module has loaded.  The worker
# receives these already-loaded bytes as bounded argv data; no pathname to
# this module is reopened between the parent snapshot and child execution.
# Interpreter/stdlib identity must be protected by the enclosing environment.
# Marshal is used exclusively with trusted same-interpreter code, never with
# untrusted image data or a network/CLI payload.
_WORKER_CODE = """
import base64
import hashlib
import json
import marshal
import os
import stat
import struct
import sys
import types

try:
    # Worker bytes are nonsecret reviewed code, not image data. Sending them
    # in argv instead of stdin preserves borrowed descriptor 0 unchanged.
    source = base64.b64decode(sys.argv[3], validate=True)
    if len(source) > 262144 or hashlib.sha256(source).hexdigest() != sys.argv[1]:
        raise ValueError("worker_payload_invalid")
    payload = marshal.loads(source)
    codes = payload["codes"]
    constants = payload["constants"]
    expected_codes = {"_u16", "_u32", "_result", "inspect_bytes", "_inspect_fd_raw"}
    expected_constants = {
        "MAX_IMAGE_BYTES", "MAX_CERTIFICATE_TABLE_BYTES",
        "MAX_CERTIFICATE_COUNT", "MAX_SECTION_COUNT", "READ_CHUNK_BYTES", "_NON_CLAIMS",
    }
    if (
        set(codes) != expected_codes or set(constants) != expected_constants
        or not all(isinstance(code, types.CodeType) for code in codes.values())
    ):
        raise ValueError("worker_payload_invalid")
    scope = {
        "__name__": "_pe_pinned_worker",
        "__builtins__": __builtins__,
        "os": os,
        "stat": stat,
        "struct": struct,
        "hashlib": hashlib,
        **constants,
    }
    class PEFormatError(ValueError):
        pass
    scope["PEFormatError"] = PEFormatError
    for name, code in codes.items():
        scope[name] = types.FunctionType(code, scope, name)
    try:
        report = scope["_inspect_fd_raw"](int(sys.argv[2]))
        print(json.dumps({"kind": "ok", "finding": report}, sort_keys=True))
    except PEFormatError as exc:
        print(json.dumps({"kind": "error", "code": str(exc)}))
except BaseException:
    print('{"kind":"error","code":"unsafe_input"}')
"""

_NON_CLAIMS = [
    "certificate_table_is_not_cryptographic_verification",
    "preopened_fd_source_and_execution_authority_not_established",
    "hard_end_to_end_deadline_or_fuse_nfs_support_not_established",
    "worker_interpreter_and_stdlib_provenance_not_established",
    "firmware_pk_kek_db_dbx_policy_not_verified",
    "whole_loader_kernel_initrd_cmdline_not_authenticated",
    "unchanged_popos_fallback_bootability_not_proven",
    "physical_seagate_apply_and_tpm2_enrollment_not_authorized",
]

# Never forward arbitrary, potentially path-bearing subprocess error strings.
_WORKER_ERROR_CODES = frozenset((
    "certificate_count_unbounded",
    "certificate_format_unsupported",
    "certificate_header_truncated",
    "certificate_length_invalid",
    "certificate_length_out_of_bounds",
    "certificate_overlaps_declared_headers",
    "certificate_overlaps_section_data",
    "certificate_padding_invalid",
    "certificate_precedes_section_data",
    "certificate_table_inconsistent",
    "certificate_table_out_of_bounds",
    "declared_headers_invalid",
    "dos_magic_invalid",
    "file_alignment_invalid",
    "input_drift",
    "input_offset",
    "machine_unsupported",
    "optional_magic_unsupported",
    "pe_header_truncated",
    "pe_magic_invalid",
    "pipe_input_unsupported",
    "read_deadline_exceeded",
    "section_alignment_invalid",
    "section_count_unbounded",
    "section_coff_only_fields_invalid",
    "section_low_alignment_rva_mismatch",
    "section_empty_raw_pointer_invalid",
    "section_raw_alignment_invalid",
    "section_raw_order_invalid",
    "section_raw_overlap",
    "section_raw_range_invalid",
    "section_virtual_order_invalid",
    "section_virtual_overlap",
    "section_virtual_range_invalid",
    "size_of_image_invalid",
    "unsafe_input",
    "unverified_certificate_gap",
    "unverified_certificate_overlay",
))


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
    if sections > MAX_SECTION_COUNT:
        raise PEFormatError("section_count_unbounded")
    optional_bytes = _u16(data, coff + 16)
    optional = coff + 20
    optional_end = optional + optional_bytes
    section_headers_end = optional_end + sections * 40
    if optional_end > len(data) or section_headers_end > len(data):
        raise PEFormatError("pe_header_truncated")
    # PE32 and PE32+ locate SizeOfHeaders at optional + 60. Unlike the
    # section table's end, it also includes the alignment/padding reserved
    # for on-disk headers. Validate this bound BEFORE reading section ranges.
    if optional_bytes < 64:
        raise PEFormatError("pe_header_truncated")
    # This bounded diagnostic accepts conventional executable PE FileAlignment
    # (power-of-two, 512..65536). Unusual low-alignment images require their
    # own reviewed layout policy; a structural positive must fail closed.
    file_alignment = _u32(data, optional + 36)
    if (
        not 0x200 <= file_alignment <= 0x10000
        or file_alignment & (file_alignment - 1)
    ):
        raise PEFormatError("file_alignment_invalid")
    # For this x86/x64 diagnostic profile, PE/COFF requires a power-of-two
    # SectionAlignment >= FileAlignment. Below the 4 KiB page boundary the
    # two alignments must be equal; raw file positions then match their RVAs.
    section_alignment = _u32(data, optional + 32)
    if (
        section_alignment < file_alignment
        or section_alignment & (section_alignment - 1)
        or (section_alignment < 0x1000 and section_alignment != file_alignment)
    ):
        raise PEFormatError("section_alignment_invalid")
    declared_headers_end = _u32(data, optional + 60)
    if (
        not (section_headers_end <= declared_headers_end <= len(data))
        or declared_headers_end % file_alignment
    ):
        raise PEFormatError("declared_headers_invalid")
    # SizeOfImage covers at least the aligned in-memory headers, and PE/COFF
    # requires it to be a multiple of the virtual SectionAlignment.
    size_of_image = _u32(data, optional + 56)
    minimum_image_size = (
        (declared_headers_end + section_alignment - 1) // section_alignment
    ) * section_alignment
    if (
        size_of_image < minimum_image_size
        or size_of_image % section_alignment
    ):
        raise PEFormatError("size_of_image_invalid")

    # PE/COFF section-table raw ranges are FILE OFFSETS. Security-directory
    # certificate bytes must never be accepted as a section's own raw data,
    # even when the certificate lies past every section HEADER.
    section_raw_ranges: list[tuple[int, int]] = []
    section_virtual_ranges: list[tuple[int, int]] = []
    # PE image section headers must describe adjacent ascending RVAs.
    # Initialized section data must follow that same order in the file.
    expected_virtual_address = minimum_image_size
    previous_raw_end = 0
    for index in range(sections):
        section_header = optional_end + index * 40
        virtual_size = _u32(data, section_header + 8)
        virtual_address = _u32(data, section_header + 12)
        raw_size = _u32(data, section_header + 16)
        raw_offset = _u32(data, section_header + 20)
        # COFF object-file relocation/line tables are never part of a PE
        # executable image section. Reject all four nonzero fields even when
        # a bogus pointer is aligned or falls in the certificate table.
        if (
            _u32(data, section_header + 24)  # PointerToRelocations
            or _u32(data, section_header + 28)  # PointerToLinenumbers
            or _u16(data, section_header + 32)  # NumberOfRelocations
            or _u16(data, section_header + 34)  # NumberOfLinenumbers
        ):
            raise PEFormatError("section_coff_only_fields_invalid")
        if raw_size:
            if (
                raw_offset < declared_headers_end
                or raw_offset > len(data)
                or raw_size > len(data) - raw_offset
            ):
                raise PEFormatError("section_raw_range_invalid")
            if raw_offset % file_alignment or raw_size % file_alignment:
                raise PEFormatError("section_raw_alignment_invalid")
        elif raw_offset:
            # A section with no file-backed bytes has no meaningful raw
            # pointer. Require the canonical zero value even when a nonzero
            # pointer happens to be file-aligned or inside the certificate.
            raise PEFormatError("section_empty_raw_pointer_invalid")
        # PE image sections live on SectionAlignment boundaries after the
        # in-memory headers. VirtualSize may exceed the file-backed portion,
        # while SizeOfRawData may be padded beyond VirtualSize.
        virtual_span = max(virtual_size, raw_size)
        if (
            not virtual_span
            or virtual_address < minimum_image_size
            or virtual_address % section_alignment
            or virtual_address > size_of_image
            or virtual_span > size_of_image - virtual_address
        ):
            raise PEFormatError("section_virtual_range_invalid")
        if any(
            virtual_address < prior_end and prior_start < virtual_address + virtual_span
            for prior_start, prior_end in section_virtual_ranges
        ):
            raise PEFormatError("section_virtual_overlap")
        if raw_size and section_alignment < 0x1000 and raw_offset != virtual_address:
            raise PEFormatError("section_low_alignment_rva_mismatch")
        if virtual_address != expected_virtual_address:
            raise PEFormatError("section_virtual_order_invalid")
        expected_virtual_address = (
            (virtual_address + virtual_span + section_alignment - 1)
            // section_alignment
        ) * section_alignment
        section_virtual_ranges.append((virtual_address, virtual_address + virtual_span))
        if not raw_size:
            continue
        # Reject ambiguous overlapping mapped file bytes even when both
        # sections individually precede a correctly placed certificate.
        if any(
            raw_offset < earlier_end and earlier_start < raw_offset + raw_size
            for earlier_start, earlier_end in section_raw_ranges
        ):
            raise PEFormatError("section_raw_overlap")
        if raw_offset < previous_raw_end:
            raise PEFormatError("section_raw_order_invalid")
        previous_raw_end = raw_offset + raw_size
        section_raw_ranges.append((raw_offset, previous_raw_end))

    # An aligned SizeOfImage larger than the last actually mapped virtual
    # section (or the aligned headers when no sections exist) is not covered
    # by the conservative structural-positive image profile.
    if size_of_image != expected_virtual_address:
        raise PEFormatError("size_of_image_invalid")

    magic = _u16(data, optional)
    if magic == 0x20B:  # PE32+ (AMD64 only in this reviewed subset)
        if _u16(data, coff) != 0x8664:
            raise PEFormatError("machine_unsupported")
        directory_count_offset, directory_start = 108, 112
    elif magic == 0x10B:  # PE32 (i386 only in this reviewed subset)
        if _u16(data, coff) != 0x014C:
            raise PEFormatError("machine_unsupported")
        directory_count_offset, directory_start = 92, 96
    else:
        raise PEFormatError("optional_magic_unsupported")
    if optional_bytes < directory_start:
        raise PEFormatError("pe_header_truncated")
    directory_count = _u32(data, optional + directory_count_offset)
    # All declared directories must fit inside SizeOfOptionalHeader, not
    # merely the security entry at index 4. Reject malformed absent too.
    if directory_count > (optional_bytes - directory_start) // 8:
        raise PEFormatError("pe_header_truncated")
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
    if certificate_start < declared_headers_end:
        raise PEFormatError("certificate_overlaps_declared_headers")
    certificate_end = certificate_start + certificate_bytes
    if any(
        raw_start < certificate_end and certificate_start < raw_end
        for raw_start, raw_end in section_raw_ranges
    ):
        raise PEFormatError("certificate_overlaps_section_data")
    # Attribute certificates must occur *after* mapped section raw data.
    # PE files may carry trailing nonmapped debug material, but this parser
    # deliberately does not parse or authenticate debug-directory entries:
    # such images are outside its fail-closed structural-positive subset.
    if section_raw_ranges and certificate_start < max(
        raw_end for _, raw_end in section_raw_ranges
    ):
        raise PEFormatError("certificate_precedes_section_data")
    # Without a parser that establishes ownership for nonmapped data, any
    # gap from the on-disk headers through mapped raw sections to the final
    # certificate is unverified overlay (including all-zero padding).
    covered_end = declared_headers_end
    for raw_start, raw_end in section_raw_ranges:
        if raw_start != covered_end:
            raise PEFormatError("unverified_certificate_gap")
        covered_end = raw_end
    if certificate_start != covered_end:
        raise PEFormatError("unverified_certificate_gap")
    # Without a reviewed nonmapped debug-directory parser, every byte after
    # the declared attribute-certificate table is unverified overlay data.
    # Never label unknown overlay as positive PE certificate structure.
    if certificate_end != len(data):
        raise PEFormatError("unverified_certificate_overlay")

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



def _inspect_fd_raw(fd: int) -> dict[str, Any]:
    """Worker-internal raw pread path for a preopened single-linked file.

    The borrowed descriptor may be reassigned by another thread, so dup()
    first and validate the private descriptor before any read. A dup shares
    file offsets, hence pread() pins every read to an explicit offset.

    Even a *currently* O_NONBLOCK FIFO is unsafe: another holder of the
    same open-file description can clear the flag between poll and read,
    leaving an unbounded blocking read. Reject all pipes before any read,
    without opening paths or changing the caller's descriptor flags.
    This remains a non-authoritative, diagnostic-only snapshot.
    """
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
        raise PEFormatError("unsafe_input")
    pinned_fd = -1
    try:
        pinned_fd = os.dup(fd)
        before = os.fstat(pinned_fd)
        if stat.S_ISFIFO(before.st_mode):
            raise PEFormatError("pipe_input_unsupported")
        if not stat.S_ISREG(before.st_mode):
            raise PEFormatError("unsafe_input")
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
        while total <= MAX_IMAGE_BYTES:
            count = min(READ_CHUNK_BYTES, MAX_IMAGE_BYTES + 1 - total)
            part = os.pread(pinned_fd, count, total)
            if not part:
                break
            total += len(part)
            chunks.append(part)
        after = os.fstat(pinned_fd)
        keys = (
            "st_dev", "st_ino", "st_size", "st_mode", "st_nlink",
            "st_mtime_ns", "st_ctime_ns",
        )
        if (
            any(getattr(before, name) != getattr(after, name) for name in keys)
            or total != before.st_size
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


def _read_worker_output_bounded(proc: subprocess.Popen[bytes]) -> bytes:
    """Bound child-pipe memory and the worker read phase, not Popen/exec.

    The only read is on a local child stdout PIPE. Stderr shares that pipe;
    neither can allocate unbounded parent buffers. The supplied image FD
    is not accessed or closed here. Kernel D-state lifecycle is supervised
    externally and unsupported FUSE/NFS has no end-to-end deadline.
    """
    if proc.stdout is None:
        raise PEFormatError("unsafe_input")
    deadline = time.monotonic() + WORKER_DEADLINE_SECONDS
    payload = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise PEFormatError("read_deadline_exceeded")
            chunk = os.read(
                proc.stdout.fileno(), min(READ_CHUNK_BYTES, 65537 - len(payload))
            )
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > 65536:
                raise PEFormatError("unsafe_input")
    try:
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        raise PEFormatError("read_deadline_exceeded") from exc
    return bytes(payload)


def inspect_fd(fd: int) -> dict[str, Any]:
    """Inspect a caller-preopened FD using a bounded child pipe-read phase.

    This is NOT an end-to-end deadline: Popen/exec and filesystem operations
    outside the child read wait may block. In particular no bounded FUSE/NFS
    operation is supported or guaranteed. The caller must supply an already
    opened regular local-file FD and supervise the task/cgroup lifecycle.
    A child stuck in uninterruptible kernel I/O can outlive SIGKILL.
    Interpreter and stdlib are trusted externally, not pinned by this module.
    The worker only produces non-authoritative certificate-table diagnostics.
    """
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0 or fd in (1, 2):
        raise PEFormatError("unsafe_input")

    # Inherit the borrowed FD directly. Do not dup or close any image FD
    # in the parent: close(2) on FUSE/NFS can invoke a blocking flush.
    # The child privately duplicates, checks and closes its own descriptor.
    proc: subprocess.Popen[bytes] | None = None
    try:
        # -I isolates environment/path, -S suppresses site/.pth hooks,
        # -B prevents bytecode writes. Interpreter+stdlib remain trusted
        # environmental dependencies, not cryptographically source-pinned.
        proc = subprocess.Popen(
            [
                sys.executable, "-I", "-S", "-B", "-c", _WORKER_CODE,
                hashlib.sha256(_PINNED_WORKER_PAYLOAD).hexdigest(), str(fd),
                base64.b64encode(_PINNED_WORKER_PAYLOAD).decode("ascii"),
            ],
            pass_fds=(fd,),
            stdin=None,  # FD 0 may be the borrowed PE image, never replace it
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # same bounded local stdout pipe
            bufsize=0,  # raw pipe FileIO.close has no buffered flush
            close_fds=True,
            env={"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        output = _read_worker_output_bounded(proc)
        if proc.returncode != 0:
            raise PEFormatError("unsafe_input")
        try:
            message = json.loads(output)
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise PEFormatError("unsafe_input") from exc
        if not isinstance(message, dict):
            raise PEFormatError("unsafe_input")
        if message.get("kind") == "error":
            reason = message.get("code")
            if (
                set(message) != {"kind", "code"}
                or not isinstance(reason, str)
                or reason not in _WORKER_ERROR_CODES
            ):
                raise PEFormatError("unsafe_input")
            raise PEFormatError(reason)
        if (
            set(message) != {"kind", "finding"}
            or message.get("kind") != "ok"
            or not isinstance(message["finding"], dict)
        ):
            raise PEFormatError("unsafe_input")
        # Reconstruct all authority and trust fields in the already-loaded
        # parent. Never return an arbitrary worker dictionary as an admission
        # claim even if the child process itself is corrupted.
        finding = message["finding"]
        signature = finding.get("signature_table")
        count = finding.get("certificate_count")
        if (
            signature not in {"absent", "structurally_present"}
            or type(count) is not int
            or not (0 <= count <= MAX_CERTIFICATE_COUNT)
            or ((count == 0) != (signature == "absent"))
        ):
            raise PEFormatError("unsafe_input")
        expected = _result(signature_table=signature, certificate_count=count)
        input_digest = finding.get("input_sha256")
        input_size = finding.get("input_size")
        if (
            set(finding) != set(expected) | {"input_sha256", "input_size"}
            or any(
                type(finding[key]) is not type(value) or finding[key] != value
                for key, value in expected.items()
            )
            or type(input_size) is not int
            or not (0x40 <= input_size <= MAX_IMAGE_BYTES)
            or not isinstance(input_digest, str)
            or len(input_digest) != 64
            or any(char not in "0123456789abcdef" for char in input_digest)
        ):
            raise PEFormatError("unsafe_input")
        return {**expected, "input_sha256": input_digest, "input_size": input_size}
    except OSError as exc:
        raise PEFormatError("unsafe_input") from exc
    finally:
        # Only pipes created by Popen belong to this parent. Close even on
        # timeout/invalid output to avoid accumulating descriptors. Unbuffered
        # pipes avoid a potentially blocking Python buffered-writer flush.
        # Never close the borrowed image FD in this process.
        if proc is not None:
            if proc.poll() is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass
            # D-state children may stay unreaped: the supervising task/cgroup
            # owns final cleanup, not a possibly unbounded wait in this caller.
            if proc.poll() is None:
                try:
                    proc.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    pass


class _RedactedArgumentParser(argparse.ArgumentParser):
    """Fail closed on any unsupported CLI shape without echoing private argv."""

    def error(self, message: str) -> None:
        # Default argparse interpolates every rejected argument into stderr,
        # including private /dev/disk/by-id or EFI paths. Never log them.
        del message
        print("invalid PE diagnostic arguments", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    # The default --help action exits 0; arbitrary/rejected CLI arguments can
    # also leak secrets through argparse.error. Both paths must fail nonzero.
    parser = _RedactedArgumentParser(description=__doc__, add_help=False)
    parser.add_argument(
        "--stdin", action="store_true", required=True,
        help="inspect caller-opened regular-file stdin only (NO path opening)",
    )
    parser.parse_args(argv)
    try:
        item = inspect_fd(0)
    except PEFormatError as exc:
        item = {
            **_result(signature_table="not_proven", certificate_count=0),
            "status": (
                "unavailable"
                if str(exc) in {
                    "unsafe_input", "pipe_input_unsupported",
                    "read_deadline_exceeded", "input_drift", "input_offset",
                }
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


# Snapshot the PE function code objects at module load without re-reading
# this module from __file__. This binds only these code objects, not Python,
# the standard library, interpreter launch, or arbitrary same-UID processes.
_PINNED_WORKER_PAYLOAD = marshal.dumps({
    "codes": {
        name: globals()[name].__code__
        for name in ("_u16", "_u32", "_result", "inspect_bytes", "_inspect_fd_raw")
    },
    "constants": {
        "MAX_IMAGE_BYTES": MAX_IMAGE_BYTES,
        "MAX_CERTIFICATE_TABLE_BYTES": MAX_CERTIFICATE_TABLE_BYTES,
        "MAX_CERTIFICATE_COUNT": MAX_CERTIFICATE_COUNT,
        "MAX_SECTION_COUNT": MAX_SECTION_COUNT,
        "READ_CHUNK_BYTES": READ_CHUNK_BYTES,
        "_NON_CLAIMS": tuple(_NON_CLAIMS),
    },
})
if len(_PINNED_WORKER_PAYLOAD) > 65536:
    # Linux execve limits each argv string to 128 KiB. The base64-encoded
    # payload must fit below that limit without falling back to FD0/stdio.
    raise RuntimeError("PE worker code payload too large")


if __name__ == "__main__":
    raise SystemExit(main())