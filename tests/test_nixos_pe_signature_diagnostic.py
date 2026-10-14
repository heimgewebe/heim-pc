"""Negative controls for the diagnostic-only PE/COFF certificate-table reader.

A PE certificate table (even if syntactically present) never authenticates
the kernel, initrd, command line, firmware db/dbx, or Pop!_OS fallback.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
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
    struct.pack_into("<I", image, optional + (92 if pe32 else 108), 16)
    directory = optional + (96 if pe32 else 112) + 4 * 8
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


def test_certificate_table_must_not_overlap_pe_headers():
    data = bytearray(fixture_pe(present=True))
    struct.pack_into("<I", data, 0x98 + 144, 0x100)
    with pytest.raises(pe.PEFormatError, match="certificate_table_out_of_bounds"):
        pe.inspect_bytes(bytes(data))


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
    with pytest.raises(pe.PEFormatError, match="unsafe_input"):
        pe.inspect_file(image)


def test_readonly_file_probe_binds_exact_byte_digest(tmp_path):
    image = tmp_path / "image.efi"
    content = fixture_pe()
    image.write_bytes(content)
    finding = pe.inspect_file(image)
    assert finding["status"] == "unsigned"
    assert finding["input_sha256"] == pe.hashlib.sha256(content).hexdigest()
    assert finding["input_size"] == len(content)
    assert finding["physical_install_authorized"] is False


def test_symlink_to_valid_pe_is_not_followed(tmp_path):
    image = tmp_path / "image.efi"
    link = tmp_path / "alias.efi"
    image.write_bytes(fixture_pe(present=True))
    link.symlink_to(image)
    with pytest.raises(pe.PEFormatError, match="unsafe_input"):
        pe.inspect_file(link)


def test_directories_are_rejected(tmp_path):
    with pytest.raises(pe.PEFormatError, match="unsafe_input"):
        pe.inspect_file(tmp_path)


@pytest.mark.parametrize("present", [False, True])
def test_cli_never_returns_success_as_uefi_or_disk_authority(tmp_path, present):
    path = tmp_path / "test.efi"
    path.write_bytes(fixture_pe(present=present))
    command = [
        sys.executable, "-B", "-m", "scripts.nixos_pe_signature_diagnostic",
        "--pe-image", str(path),
    ]
    done = subprocess.run(command, check=False, capture_output=True, text=True)
    assert done.returncode == 2, done.stderr
    result = json.loads(done.stdout)
    assert result["schema_version"] == 1
    assert result["physical_install_authorized"] is False
    assert result["full_bootchain_authenticated"] is False
    assert result["findings"][0]["signature_table"] == (
        "structurally_present" if present else "absent"
    )
    assert str(path) not in done.stdout


def test_cli_rejects_unreadable_and_missing_image_fail_closed(tmp_path):
    absent = tmp_path / "missing.efi"
    done = subprocess.run(
        [sys.executable, "-B", "-m", "scripts.nixos_pe_signature_diagnostic", "--pe-image", str(absent)],
        check=False, capture_output=True, text=True,
    )
    assert done.returncode == 2
    result = json.loads(done.stdout)
    assert result["findings"][0]["status"] == "unavailable"
    assert result["physical_install_authorized"] is False