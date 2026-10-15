"""Negative controls for the diagnostic-only PE/COFF certificate-table reader.

A PE certificate table (even if syntactically present) never authenticates
the kernel, initrd, command line, firmware db/dbx, or Pop!_OS fallback.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

import pytest

from scripts import nixos_pe_signature_diagnostic as pe


def fixture_pe(*, present: bool = False, pe32: bool = False) -> bytes:
    """Build small synthetic PE headers; no real signing keys or authentic PE."""
    image = bytearray(0x200 + (0x10 if present else 0))
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", image, coff, 0x014C if pe32 else 0x8664)
    struct.pack_into("<H", image, coff + 2, 0)  # zero sections
    optional = coff + 20
    struct.pack_into("<H", image, coff + 16, 0xE0 if pe32 else 0xF0)
    struct.pack_into("<H", image, optional, 0x10B if pe32 else 0x20B)
    struct.pack_into("<I", image, optional + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", image, optional + 36, 0x200)   # FileAlignment
    struct.pack_into("<I", image, optional + 56, 0x1000)  # SizeOfImage
    struct.pack_into("<I", image, optional + (92 if pe32 else 108), 16)
    directory = optional + (96 if pe32 else 112) + 4 * 8
    struct.pack_into("<I", image, optional + 60, 0x200)  # SizeOfHeaders
    if present:
        struct.pack_into("<II", image, directory, 0x200, 0x10)
        struct.pack_into("<IHH", image, 0x200, 0x10, 0x200, 0x0002)
        image[0x208:0x210] = b"NOTPKCS7"
    return bytes(image)


@pytest.mark.parametrize("pe32", [True, False])
def test_unsigned_image_detected_even_when_pe_headers_are_valid(pe32):
    finding = pe.inspect_bytes(fixture_pe(pe32=pe32))
    assert finding["signature_table"] == "absent"
    assert finding["status"] == "unsigned"
    assert finding["cryptographic_signature_verified"] is False
    assert finding["full_bootchain_authenticated"] is False
    assert finding["physical_install_authorized"] is False


@pytest.mark.parametrize("pe32", [True, False])
def test_structurally_present_table_is_never_cryptographic_or_boot_trust(pe32):
    finding = pe.inspect_bytes(fixture_pe(present=True, pe32=pe32))
    assert finding["signature_table"] == "structurally_present"
    assert finding["certificate_count"] == 1
    assert finding["cryptographic_signature_verified"] is False
    assert finding["firmware_key_policy_verified"] is False
    assert finding["full_bootchain_authenticated"] is False
    assert finding["physical_install_authorized"] is False


def test_synthetic_certificate_payload_is_not_mislabelled_as_signed_bootchain():
    finding = pe.inspect_bytes(fixture_pe(present=True))
    # The fabricated payload is explicitly NOT DER/PKCS#7; this function
    # diagnoses only table framing, never Authenticode verification.
    assert finding["signature_table"] == "structurally_present"
    assert "certificate_table_is_not_cryptographic_verification" in finding["does_not_establish"]


@pytest.mark.parametrize(
    "edit",
    [
        lambda b: b.__setitem__(slice(0, 2), b"NO"),
        lambda b: b.__setitem__(slice(0x80, 0x84), b"JUNK"),
        lambda b: struct.pack_into("<I", b, 0x3C, len(b) + 200),
        lambda b: struct.pack_into("<I", b, 0x98 + 144, 0x1FF),  # misaligned certificate
        lambda b: struct.pack_into("<I", b, 0x98 + 148, 0x4000),  # outside input
        lambda b: struct.pack_into("<I", b, 0x200, 0),  # zero-length WIN_CERTIFICATE
        lambda b: struct.pack_into("<H", b, 0x206, 1),  # unknown certificate type
        lambda b: struct.pack_into("<H", b, 0x204, 1),  # unsupported WIN_CERT revision
        lambda b: struct.pack_into("<H", b, 0x84 + 16, 30),  # truncated optional header
    ],
)
def test_malformed_headers_never_become_positive_signature_evidence(edit):
    data = bytearray(fixture_pe(present=True))
    edit(data)
    with pytest.raises(pe.PEFormatError):
        pe.inspect_bytes(bytes(data))


def test_truncated_certificate_directory_is_not_unsigned_success():
    data = bytearray(fixture_pe(present=True))
    struct.pack_into("<I", data, 0x98 + 148, 0)
    with pytest.raises(pe.PEFormatError, match="certificate_table_inconsistent"):
        pe.inspect_bytes(bytes(data))


def test_certificate_padding_cannot_hide_payload_bytes():
    data = bytearray(fixture_pe(present=True))
    struct.pack_into("<I", data, 0x200, 10)  # 8-byte header + 2 data bytes
    with pytest.raises(pe.PEFormatError, match="certificate_padding_invalid"):
        pe.inspect_bytes(bytes(data))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("headers_size", [0x400, 0x600])
def test_certificate_inside_declared_size_of_headers_is_invalid(pe32, headers_size):
    data = bytearray(fixture_pe(present=True, pe32=pe32))
    # Keep SizeOfHeaders file-aligned; the certificate still lies inside it.
    data.extend(bytes(headers_size - len(data)))
    struct.pack_into("<I", data, 0x98 + 60, headers_size)
    with pytest.raises(pe.PEFormatError, match="certificate_overlaps_declared_headers"):
        pe.inspect_bytes(bytes(data))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("headers_size", [0, 0x80, 0x218])
def test_malformed_size_of_headers_never_positive(pe32, headers_size):
    data = bytearray(fixture_pe(present=True, pe32=pe32))
    struct.pack_into("<I", data, 0x98 + 60, headers_size)
    with pytest.raises(pe.PEFormatError, match="declared_headers_invalid"):
        pe.inspect_bytes(bytes(data))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("section_alignment", [0, 0x100, 0x180, 0x800])
def test_invalid_section_alignment_cannot_be_cert_positive_or_unsigned(
    pe32, present, section_alignment,
):
    image = bytearray(fixture_pe(present=present, pe32=pe32))
    struct.pack_into("<I", image, 0x98 + 32, section_alignment)
    with pytest.raises(pe.PEFormatError, match="section_alignment_invalid"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
def test_low_section_alignment_equal_to_file_alignment_is_admitted(pe32):
    image = bytearray(fixture_pe(present=True, pe32=pe32))
    struct.pack_into("<I", image, 0x98 + 32, 0x200)
    finding = pe.inspect_bytes(bytes(image))
    assert finding["signature_table"] == "structurally_present"
    assert finding["full_bootchain_authenticated"] is False
    assert finding["physical_install_authorized"] is False


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("present", [False, True])
def test_size_of_headers_must_be_file_aligned(pe32, present):
    image = bytearray(fixture_pe(present=present, pe32=pe32))
    # Larger than all actual PE header bytes but not rounded to FileAlignment.
    struct.pack_into("<I", image, 0x98 + 60, 0x1C8)
    with pytest.raises(pe.PEFormatError, match="declared_headers_invalid"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("image_size", [0, 0x180, 0x1001])
def test_invalid_size_of_image_cannot_be_positive(pe32, present, image_size):
    image = bytearray(fixture_pe(present=present, pe32=pe32))
    struct.pack_into("<I", image, 0x98 + 56, image_size)
    with pytest.raises(pe.PEFormatError, match="size_of_image_invalid"):
        pe.inspect_bytes(bytes(image))


def reject_every_data_read(scoped):
    """Enforce no read/readv/pread on unsupported descriptor classes."""
    def forbid(*_args, **_kwargs):
        raise AssertionError("no data-read primitive may touch this descriptor")

    for name in ("read", "readv", "pread"):
        if hasattr(pe.os, name):
            scoped.setattr(pe.os, name, forbid)


def test_certificate_table_must_not_overlap_pe_headers():
    data = bytearray(fixture_pe(present=True))
    struct.pack_into("<I", data, 0x98 + 144, 0x100)
    with pytest.raises(pe.PEFormatError, match="certificate_table_out_of_bounds"):
        pe.inspect_bytes(bytes(data))


@pytest.mark.parametrize("pe32", [True, False])
@pytest.mark.parametrize("raw_offset", [0x1C0, 0x1F0])
def test_section_bytes_inside_declared_header_padding_are_invalid(pe32, raw_offset):
    # Section headers finish before 0x1c0, but SizeOfHeaders still reserves
    # the entire [0, 0x200) file range. Certificate at 0x200 is separate.
    data = bytearray(fixture_pe(present=True, pe32=pe32))
    struct.pack_into("<H", data, 0x84 + 2, 1)
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<II", data, section + 16, 0x10, raw_offset)
    with pytest.raises(pe.PEFormatError, match="section_raw_range_invalid"):
        pe.inspect_bytes(bytes(data))


def fixture_pe_section_and_later_certificate(
    *, pe32: bool, raw_offset: int = 0x200, raw_size: int = 0x200,
) -> bytes:
    """Synthetic section followed by certificate at file offset 0x400."""
    data = bytearray(fixture_pe(present=True, pe32=pe32))
    certificate = bytes(data[0x200:0x210])
    data.extend(bytes(0x200))  # end at 0x410
    data[0x200:0x210] = bytes(0x10)
    data[0x400:0x410] = certificate
    directory = 0x98 + (96 if pe32 else 112) + 4 * 8
    struct.pack_into("<II", data, directory, 0x400, 0x10)
    struct.pack_into("<H", data, 0x84 + 2, 1)
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<II", data, section + 16, raw_size, raw_offset)
    struct.pack_into("<II", data, section + 8, 0x200, 0x1000)
    struct.pack_into("<I", data, 0x98 + 56, 0x2000)  # mapped section end
    return bytes(data)


def fixture_pe_two_sections(*, pe32: bool, overlapping: bool) -> bytes:
    """Two 0x200-aligned section ranges, followed by a synthetic certificate."""
    image = bytearray(fixture_pe(present=True, pe32=pe32))
    certificate = bytes(image[0x200:0x210])
    image.extend(bytes(0x610 - len(image)))
    image[0x200:0x210] = bytes(0x10)
    image[0x600:0x610] = certificate
    directory = 0x98 + (96 if pe32 else 112) + 4 * 8
    struct.pack_into("<II", image, directory, 0x600, 0x10)
    struct.pack_into("<H", image, 0x84 + 2, 2)
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<II", image, section + 16,
                     0x400 if overlapping else 0x200, 0x200)
    struct.pack_into("<II", image, section + 40 + 16, 0x200, 0x400)
    struct.pack_into("<II", image, section + 8, 0x200, 0x1000)
    struct.pack_into("<II", image, section + 40 + 8, 0x200, 0x2000)
    struct.pack_into("<I", image, 0x98 + 56, 0x3000)
    return bytes(image)


@pytest.mark.parametrize("pe32", [False, True])
def test_overlapping_raw_sections_never_positive(pe32):
    with pytest.raises(pe.PEFormatError, match="section_raw_overlap"):
        pe.inspect_bytes(fixture_pe_two_sections(pe32=pe32, overlapping=True))


@pytest.mark.parametrize("pe32", [False, True])
def test_two_nonoverlapping_raw_sections_remain_diagnostic_only(pe32):
    finding = pe.inspect_bytes(fixture_pe_two_sections(pe32=pe32, overlapping=False))
    assert finding["signature_table"] == "structurally_present"
    assert finding["cryptographic_signature_verified"] is False
    assert finding["physical_install_authorized"] is False


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("layout", ["reversed_virtual_headers", "virtual_gap", "first_virtual_gap"])
def test_pe_sections_must_be_adjacent_and_ascending(pe32, layout):
    image = bytearray(fixture_pe_two_sections(pe32=pe32, overlapping=False))
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    if layout == "reversed_virtual_headers":
        struct.pack_into("<I", image, section + 12, 0x2000)
        struct.pack_into("<I", image, section + 40 + 12, 0x1000)
    elif layout == "virtual_gap":
        struct.pack_into("<I", image, section + 40 + 12, 0x3000)
        struct.pack_into("<I", image, 0x98 + 56, 0x4000)
    else:
        struct.pack_into("<I", image, section + 12, 0x2000)
        struct.pack_into("<I", image, section + 40 + 12, 0x3000)
        struct.pack_into("<I", image, 0x98 + 56, 0x4000)
    with pytest.raises(pe.PEFormatError, match="section_virtual_order_invalid"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
def test_nonoverlapping_section_raw_data_must_follow_rva_order(pe32):
    image = bytearray(fixture_pe_two_sections(pe32=pe32, overlapping=False))
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<I", image, section + 20, 0x400)
    struct.pack_into("<I", image, section + 40 + 20, 0x200)
    with pytest.raises(pe.PEFormatError, match="section_raw_order_invalid"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("virtual_address", [0, 0x200, 0x1100])
def test_invalid_section_virtual_address_never_positive(pe32, virtual_address):
    image = bytearray(fixture_pe_section_and_later_certificate(pe32=pe32))
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<I", image, section + 12, virtual_address)
    with pytest.raises(pe.PEFormatError, match="section_virtual_range_invalid"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("overrun", ["mapped_end", "virtual_size"])
def test_section_virtual_span_cannot_escape_size_of_image(pe32, overrun):
    image = bytearray(fixture_pe_section_and_later_certificate(pe32=pe32))
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    if overrun == "mapped_end":
        struct.pack_into("<I", image, 0x98 + 56, 0x1000)
    else:
        struct.pack_into("<I", image, section + 8, 0x2000)
    with pytest.raises(pe.PEFormatError, match="section_virtual_range_invalid"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
def test_low_alignment_matching_raw_offset_and_rva_stays_diagnostic(pe32):
    image = bytearray(fixture_pe_section_and_later_certificate(pe32=pe32))
    struct.pack_into("<I", image, 0x98 + 32, 0x200)
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<I", image, section + 12, 0x200)
    finding = pe.inspect_bytes(bytes(image))
    assert finding["signature_table"] == "structurally_present"
    assert finding["physical_install_authorized"] is False


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("raw_offset,raw_size", [(0x210, 0x10), (0x200, 0x30)])
def test_file_alignment_violations_never_positive(pe32, raw_offset, raw_size):
    image = fixture_pe_section_and_later_certificate(
        pe32=pe32, raw_offset=raw_offset, raw_size=raw_size,
    )
    with pytest.raises(pe.PEFormatError, match="section_raw_alignment_invalid"):
        pe.inspect_bytes(image)


@pytest.mark.parametrize("pe32", [False, True])
def test_file_aligned_raw_section_before_certificate_is_diagnostic_only(pe32):
    finding = pe.inspect_bytes(
        fixture_pe_section_and_later_certificate(pe32=pe32)
    )
    assert finding["signature_table"] == "structurally_present"
    assert finding["physical_install_authorized"] is False
    assert finding["full_bootchain_authenticated"] is False


@pytest.mark.parametrize("pe32", [False, True])
def test_low_alignment_section_rva_must_match_disk_position(pe32):
    image = bytearray(fixture_pe_section_and_later_certificate(pe32=pe32))
    struct.pack_into("<I", image, 0x98 + 32, 0x200)
    with pytest.raises(pe.PEFormatError, match="section_low_alignment_rva_mismatch"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("alignment", [0, 0x180, 0x100, 0x20000])
def test_invalid_file_alignment_never_positive(pe32, alignment):
    image = bytearray(fixture_pe(present=True, pe32=pe32))
    struct.pack_into("<I", image, 0x98 + 36, alignment)
    with pytest.raises(pe.PEFormatError, match="file_alignment_invalid"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [True, False])
def test_certificate_table_overlaps_raw_section_rejected(pe32):
    data = bytearray(fixture_pe(present=True, pe32=pe32))
    # Aligned raw section [0x200,0x400) overlaps certificate [0x200,0x210).
    data.extend(bytes(0x1F0))
    struct.pack_into("<H", data, 0x84 + 2, 1)
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<II", data, section + 16, 0x200, 0x200)
    struct.pack_into("<II", data, section + 8, 0x200, 0x1000)
    struct.pack_into("<I", data, 0x98 + 56, 0x2000)
    with pytest.raises(pe.PEFormatError, match="certificate_overlaps_section_data"):
        pe.inspect_bytes(bytes(data))


@pytest.mark.parametrize("pe32", [True, False])
def test_certificate_table_after_section_raw_data_remains_diagnostic_only(pe32):
    finding = pe.inspect_bytes(
        fixture_pe_section_and_later_certificate(pe32=pe32)
    )
    assert finding["signature_table"] == "structurally_present"
    assert finding["cryptographic_signature_verified"] is False
    assert finding["full_bootchain_authenticated"] is False
    assert finding["physical_install_authorized"] is False


@pytest.mark.parametrize("pe32", [False, True])
def test_certificate_before_later_raw_section_is_invalid(pe32):
    image = bytearray(fixture_pe(present=True, pe32=pe32))
    # Certificate [0x200,0x210) precedes aligned raw section [0x400,0x600).
    image.extend(bytes(0x620 - len(image)))
    struct.pack_into("<H", image, 0x84 + 2, 1)
    header = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<II", image, header + 16, 0x200, 0x400)
    struct.pack_into("<II", image, header + 8, 0x200, 0x1000)
    struct.pack_into("<I", image, 0x98 + 56, 0x2000)
    with pytest.raises(pe.PEFormatError, match="certificate_precedes_section_data"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
def test_unverified_trailing_debug_after_certificate_fails_closed(pe32):
    # A valid PE can carry separately declared trailing debug information.
    # This deliberately narrow parser does NOT authenticate/parse those
    # debug-directory entries, so even zero padding after cert is unknown.
    image = bytearray(fixture_pe(present=True, pe32=pe32))
    image.extend(bytes(32))
    with pytest.raises(pe.PEFormatError, match="unverified_certificate_overlay"):
        pe.inspect_bytes(bytes(image))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("overlay", [b"ATTACK", bytes(1), bytes(16)])
def test_undeclared_overlay_after_certificate_rejected(pe32, overlay):
    image = fixture_pe(present=True, pe32=pe32) + overlay
    with pytest.raises(pe.PEFormatError, match="unverified_certificate_overlay"):
        pe.inspect_bytes(image)


@pytest.mark.parametrize("pe32", [True, False])
def test_invalid_raw_section_extent_is_never_accepted(pe32):
    data = bytearray(fixture_pe(present=True, pe32=pe32))
    struct.pack_into("<H", data, 0x84 + 2, 1)
    section = 0x98 + (0xE0 if pe32 else 0xF0)
    struct.pack_into("<II", data, section + 16, 0x50, 0x200)
    with pytest.raises(pe.PEFormatError, match="section_raw_range_invalid"):
        pe.inspect_bytes(bytes(data))


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("present", [False, True])
def test_claimed_directory_count_cannot_outgrow_optional_header(pe32, present):
    data = bytearray(fixture_pe(present=present, pe32=pe32))
    # Only security-entry index 4 fits, but the header falsely declares 16.
    # Checking only entry 4 used to return present (or absent) on bad PE.
    directory_start = 96 if pe32 else 112
    struct.pack_into("<H", data, 0x84 + 16, directory_start + 5 * 8)
    with pytest.raises(pe.PEFormatError, match="pe_header_truncated"):
        pe.inspect_bytes(bytes(data))


def test_nonblocking_pipe_must_be_rejected_before_read_despite_shared_flags(monkeypatch):
    # A separate fd referring to the same open description can clear
    # O_NONBLOCK after poll() and cause an unbounded blocking read.
    fd, writer = os.pipe()
    peer = os.dup(fd)
    try:
        os.set_blocking(fd, False)
        os.write(writer, fixture_pe(present=True))
        with monkeypatch.context() as scoped:
            reject_every_data_read(scoped)
            with pytest.raises(pe.PEFormatError, match="pipe_input_unsupported"):
                pe._inspect_fd_raw(fd)
    finally:
        os.close(peer)
        os.close(fd)
        os.close(writer)


def test_certificate_directory_count_less_than_five_means_unsigned():
    data = bytearray(fixture_pe(present=True))
    struct.pack_into("<I", data, 0x98 + 108, 4)
    report = pe.inspect_bytes(bytes(data))
    assert report["status"] == "unsigned"
    assert report["physical_install_authorized"] is False


def test_multiple_hardlinked_names_fail_closed(tmp_path):
    image = tmp_path / "loader.efi"
    alias = tmp_path / "alias.efi"
    image.write_bytes(fixture_pe(present=True))
    os.link(image, alias)
    # The diagnostic NEVER opens the path; the test harness supplies an fd.
    with image.open("rb") as opened:
        with pytest.raises(pe.PEFormatError, match="unsafe_input"):
            pe.inspect_fd(opened.fileno())


def test_preopened_regular_fd_binds_exact_byte_digest(tmp_path):
    image = tmp_path / "image.efi"
    content = fixture_pe()
    image.write_bytes(content)
    with image.open("rb") as opened:
        finding = pe.inspect_fd(opened.fileno())
    assert finding["status"] == "unsigned"
    assert finding["input_sha256"] == pe.hashlib.sha256(content).hexdigest()
    assert finding["input_size"] == len(content)
    assert finding["physical_install_authorized"] is False


def test_borrowed_fd_swapped_to_device_after_initial_fstat_is_not_read(tmp_path, monkeypatch):
    # Simulate another thread replacing the BORROWED descriptor number just
    # after the first file-identity read, before the diagnostic consumes bytes.
    # A private dup must stay pinned to the original regular file.
    data = fixture_pe(present=True)
    source = tmp_path / "image.efi"
    source.write_bytes(data)
    caller_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    harmless_device = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    original_fstat = os.fstat
    original_pread = os.pread
    swapped = False
    pread_seen = False

    def swap_borrowed_after_stat(fd):
        nonlocal swapped
        info = original_fstat(fd)
        if not swapped:
            swapped = True
            os.dup2(harmless_device, caller_fd)
        return info

    def prohibit_device_pread(fd, amount, offset):
        nonlocal pread_seen
        pread_seen = True
        if not stat.S_ISREG(original_fstat(fd).st_mode):
            raise AssertionError("diagnostic used pread on a swapped-to-device fd")
        return original_pread(fd, amount, offset)

    try:
        with monkeypatch.context() as local:
            local.setattr(pe.os, "fstat", swap_borrowed_after_stat)
            local.setattr(pe.os, "pread", prohibit_device_pread)
            finding = pe._inspect_fd_raw(caller_fd)
        assert swapped
        assert pread_seen
        assert finding["input_sha256"] == pe.hashlib.sha256(data).hexdigest()
        assert finding["physical_install_authorized"] is False
    finally:
        os.close(caller_fd)
        os.close(harmless_device)


def test_shared_regular_file_description_offset_drift_cannot_swap_snapshot(tmp_path, monkeypatch):
    data = fixture_pe(present=True)
    image = tmp_path / "offset-race.efi"
    image.write_bytes(data)
    caller_fd = os.open(image, os.O_RDONLY | os.O_CLOEXEC)
    other_fd = os.dup(caller_fd)
    original_pread = os.pread
    pread_calls = 0

    def shift_shared_offset_before_pread(fd, amount, offset):
        nonlocal pread_calls
        pread_calls += 1
        os.lseek(other_fd, 23, os.SEEK_SET)
        return original_pread(fd, amount, offset)

    try:
        with monkeypatch.context() as local:
            local.setattr(pe.os, "pread", shift_shared_offset_before_pread)
            finding = pe._inspect_fd_raw(caller_fd)
        assert pread_calls > 0
        assert os.lseek(other_fd, 0, os.SEEK_CUR) == 23
        assert finding["input_sha256"] == pe.hashlib.sha256(data).hexdigest()
        assert finding["input_size"] == len(data)
        assert finding["physical_install_authorized"] is False
    finally:
        os.close(other_fd)
        os.close(caller_fd)


def test_regular_input_is_positional_and_does_not_change_borrowed_offset(tmp_path):
    image = tmp_path / "offset-stability.efi"
    image.write_bytes(fixture_pe())
    fd = os.open(image, os.O_RDONLY | os.O_CLOEXEC)
    try:
        assert os.lseek(fd, 0, os.SEEK_CUR) == 0
        pe.inspect_fd(fd)
        assert os.lseek(fd, 0, os.SEEK_CUR) == 0
    finally:
        os.close(fd)


def test_preopened_regular_file_must_start_at_zero(tmp_path):
    image = tmp_path / "offset.efi"
    image.write_bytes(fixture_pe())
    with image.open("rb") as opened:
        opened.read(2)
        with pytest.raises(pe.PEFormatError, match="input_offset"):
            pe.inspect_fd(opened.fileno())


def test_preopened_directory_fd_rejected_before_any_data_read(tmp_path, monkeypatch):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with monkeypatch.context() as scoped:
            reject_every_data_read(scoped)
            with pytest.raises(pe.PEFormatError, match="unsafe_input"):
                pe._inspect_fd_raw(fd)
    finally:
        os.close(fd)


def test_preopened_character_device_fd_cannot_be_read(monkeypatch):
    # /dev/null is harmless to open in this TEST; the diagnostic itself
    # must only inspect the passed descriptor and never read/open devices.
    fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    try:
        with monkeypatch.context() as scoped:
            reject_every_data_read(scoped)
            scoped.setattr(pe.os, "open", lambda *_: (_ for _ in ()).throw(
                AssertionError("diagnostic must never open paths")
            ))
            with pytest.raises(pe.PEFormatError, match="unsafe_input"):
                pe._inspect_fd_raw(fd)
    finally:
        os.close(fd)


def test_preopened_pipe_is_rejected_before_any_read(monkeypatch):
    payload = fixture_pe(present=True)
    read_fd, write_fd = os.pipe()
    try:
        os.set_blocking(read_fd, False)
        os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1
        with monkeypatch.context() as scoped:
            scoped.setattr(pe.os, "open", lambda *_: (_ for _ in ()).throw(
                AssertionError("diagnostic must never open paths")
            ))
            reject_every_data_read(scoped)
            with pytest.raises(pe.PEFormatError, match="pipe_input_unsupported"):
                pe._inspect_fd_raw(read_fd)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


@pytest.mark.parametrize(
    "help_args",
    [
        ["-h"],
        ["--help"],
        ["--stdin", "-h"],
        ["--stdin", "--help"],
    ],
)
def test_cli_help_never_exits_successfully(help_args):
    # A health/admission wrapper treating exit 0 as authorization must NEVER
    # succeed when argparse handles -h before running the diagnostic.
    done = subprocess.run(
        [sys.executable, "-B", "-m", "scripts.nixos_pe_signature_diagnostic", *help_args],
        capture_output=True, timeout=15, check=False,
    )
    assert done.returncode == 2, done.stdout.decode(errors="replace")
    assert b"physical_install_authorized" not in done.stdout


@pytest.mark.parametrize("partial", [False, True])
def test_unclosed_pipe_writer_rejected_immediately(monkeypatch, partial):
    # An unclosed pipe can outlive any readiness poll. Reject all FIFOs
    # regardless of whether they already contain untrusted PE bytes.
    import time

    fd, writer = os.pipe()
    try:
        os.set_blocking(fd, False)
        if partial:
            os.write(writer, fixture_pe(present=True))
        started = time.monotonic()
        with pytest.raises(pe.PEFormatError, match="pipe_input_unsupported"):
            pe.inspect_fd(fd)
        assert time.monotonic() - started < 2.0
    finally:
        os.close(fd)
        os.close(writer)


def test_blocking_pipe_is_refused_before_any_read(monkeypatch):
    pipe_fd, writer = os.pipe()  # default: blocking
    try:
        os.write(writer, b"MZ")
        with monkeypatch.context() as scoped:
            reject_every_data_read(scoped)
            with pytest.raises(pe.PEFormatError, match="pipe_input_unsupported"):
                pe._inspect_fd_raw(pipe_fd)
    finally:
        os.close(pipe_fd)
        os.close(writer)


def test_shared_pipe_open_description_cannot_change_input_admission(monkeypatch):
    fd, writer = os.pipe()
    other_fd = os.dup(fd)
    try:
        os.set_blocking(fd, False)
        assert not os.get_blocking(other_fd)
        # Same file description: another fd can remove O_NONBLOCK.
        os.set_blocking(other_fd, True)
        assert os.get_blocking(fd)
        with monkeypatch.context() as scoped:
            reject_every_data_read(scoped)
            with pytest.raises(pe.PEFormatError, match="pipe_input_unsupported"):
                pe._inspect_fd_raw(fd)
    finally:
        os.close(other_fd)
        os.close(fd)
        os.close(writer)


def test_cli_blocking_stdin_pipe_is_explicitly_unavailable():
    done = subprocess.run(
        [sys.executable, "-B", "-m", "scripts.nixos_pe_signature_diagnostic", "--stdin"],
        input=fixture_pe(present=True), capture_output=True, timeout=15,
    )
    assert done.returncode == 2
    result = json.loads(done.stdout)
    finding = result["findings"][0]
    assert finding["status"] == "unavailable"
    assert finding["reason_code"] == "pipe_input_unsupported"
    assert result["physical_install_authorized"] is False


@pytest.mark.parametrize("present", [False, True])
def test_cli_stdin_never_returns_success_as_uefi_or_disk_authority(tmp_path, present):
    # A shell may open a regular image and redirect it to --stdin; the PE
    # diagnostic opens no files, and accepts no potentially blocking pipe.
    file = tmp_path / "synthetic-image.efi"
    file.write_bytes(fixture_pe(present=present))
    command = [
        sys.executable, "-B", "-m", "scripts.nixos_pe_signature_diagnostic",
        "--stdin",
    ]
    with file.open("rb") as fd:
        done = subprocess.run(
            command, stdin=fd, check=False,
            capture_output=True, timeout=15,
        )
    assert done.returncode == 2, done.stderr
    result = json.loads(done.stdout)
    assert result["schema_version"] == 1
    assert result["physical_install_authorized"] is False
    assert result["full_bootchain_authenticated"] is False
    assert result["findings"][0]["signature_table"] == (
        "structurally_present" if present else "absent"
    )
    assert b"/dev/" not in done.stdout


@pytest.mark.parametrize(
    "bad_args",
    [
        ["--stdin", "--pe-image", "/dev/disk/by-id/nvme-PRIVATE_SERIAL"],
        ["--pe-image", "/dev/disk/by-id/nvme-PRIVATE_SERIAL"],
        ["--stdin", "--unknown=/dev/disk/by-id/nvme-PRIVATE_SERIAL"],
    ],
)
def test_rejected_private_path_never_echoed_to_any_log(bad_args):
    done = subprocess.run(
        [sys.executable, "-B", "-m", "scripts.nixos_pe_signature_diagnostic", *bad_args],
        input=b"", capture_output=True, timeout=10, check=False,
    )
    assert done.returncode == 2
    assert b"PRIVATE_SERIAL" not in done.stdout + done.stderr
    assert b"/dev/disk/by-id/" not in done.stdout + done.stderr


def test_cli_refuses_path_arguments_before_opening_anything(tmp_path):
    image = tmp_path / "image.efi"
    image.write_bytes(fixture_pe(present=True))
    done = subprocess.run(
        [
            sys.executable, "-B", "-m", "scripts.nixos_pe_signature_diagnostic",
            "--pe-image", str(image),
        ],
        check=False, capture_output=True, timeout=15,
    )
    assert done.returncode == 2
    assert done.stdout == b""


def test_cli_empty_stdin_fails_closed_without_path_reads():
    done = subprocess.run(
        [sys.executable, "-B", "-m", "scripts.nixos_pe_signature_diagnostic", "--stdin"],
        input=b"", check=False, capture_output=True, timeout=15,
    )
    assert done.returncode == 2
    report = json.loads(done.stdout)
    assert report["findings"][0]["status"] == "unavailable"
    assert report["physical_install_authorized"] is False
def test_stalled_regular_backend_cannot_wedge_caller(tmp_path, monkeypatch):
    """An actually sleeping worker must be killed without awaiting its I/O."""
    import time

    image = tmp_path / "timeout.efi"
    image.write_bytes(fixture_pe(present=True))
    # Simulate a child stuck inside a single blocking pread; no FUSE needed.
    monkeypatch.setattr(pe, "_WORKER_CODE", "import time; time.sleep(60)", raising=False)
    monkeypatch.setattr(pe, "WORKER_DEADLINE_SECONDS", 0.15, raising=False)
    started = time.monotonic()
    with image.open("rb") as opened:
        with pytest.raises(pe.PEFormatError, match="read_deadline_exceeded"):
            pe.inspect_fd(opened.fileno())
    assert time.monotonic() - started < 2.5