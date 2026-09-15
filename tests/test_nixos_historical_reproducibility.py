import importlib.util
import lzma
import stat
import struct
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "nixos_historical_reproducibility.py"
spec = importlib.util.spec_from_file_location("nixos_historical_reproducibility_tests", MODULE_PATH)
hist = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hist)


def _hwdb_with_children(characters: list[int]) -> bytes:
    assert len(characters) == 2
    header_size = 80
    node_size = 24
    child_size = 16
    value_size = 32
    root_size = node_size + len(characters) * child_size
    leaf_size = node_size
    nodes_len = root_size + 2 * leaf_size
    strings = b"\0"
    string_start = header_size + nodes_len
    file_size = string_start + len(strings)
    root_offset = header_size
    first_leaf = root_offset + root_size
    second_leaf = first_leaf + leaf_size

    data = bytearray(file_size)
    data[:8] = b"KSLPHHRH"
    struct.pack_into(
        "<9Q",
        data,
        8,
        260,
        file_size,
        header_size,
        node_size,
        child_size,
        value_size,
        root_offset,
        nodes_len,
        len(strings),
    )
    struct.pack_into("<Q", data, root_offset, string_start)
    data[root_offset + 8] = len(characters)
    struct.pack_into("<Q", data, root_offset + 16, 0)
    for index, (character, target) in enumerate(
        zip(characters, (first_leaf, second_leaf))
    ):
        child_offset = root_offset + node_size + index * child_size
        data[child_offset] = character
        struct.pack_into("<Q", data, child_offset + 8, target)
    for leaf in (first_leaf, second_leaf):
        struct.pack_into("<Q", data, leaf, string_start)
        data[leaf + 8] = 0
        struct.pack_into("<Q", data, leaf + 16, 0)
    data[-1:] = strings
    return bytes(data)


def _hwdb_with_wildcard_value(*, null_wildcard_prefix: bool) -> bytes:
    header_size = 80
    node_size = 24
    child_size = 16
    value_size = 32
    root_size = node_size + child_size
    wildcard_size = node_size + value_size
    nodes_len = root_size + wildcard_size
    string_start = header_size + nodes_len
    strings = b"\0 KEY\0expected-value\0fixture.hwdb\0"
    file_size = string_start + len(strings)
    root_offset = header_size
    wildcard_offset = root_offset + root_size
    key_offset = string_start + 1
    value_offset = key_offset + len(b" KEY\0")
    filename_offset = value_offset + len(b"expected-value\0")

    data = bytearray(file_size)
    data[:8] = b"KSLPHHRH"
    struct.pack_into(
        "<9Q",
        data,
        8,
        260,
        file_size,
        header_size,
        node_size,
        child_size,
        value_size,
        root_offset,
        nodes_len,
        len(strings),
    )
    struct.pack_into("<Q", data, root_offset, string_start)
    data[root_offset + 8] = 1
    struct.pack_into("<Q", data, root_offset + 16, 0)
    data[root_offset + node_size] = ord("*")
    struct.pack_into("<Q", data, root_offset + node_size + 8, wildcard_offset)

    struct.pack_into(
        "<Q",
        data,
        wildcard_offset,
        0 if null_wildcard_prefix else string_start,
    )
    data[wildcard_offset + 8] = 0
    struct.pack_into("<Q", data, wildcard_offset + 16, 1)
    value_entry = wildcard_offset + node_size
    struct.pack_into(
        "<QQQ",
        data,
        value_entry,
        key_offset,
        value_offset,
        filename_offset,
    )
    struct.pack_into("<I", data, value_entry + 24, 1)
    struct.pack_into("<H", data, value_entry + 28, 1)
    data[string_start:] = strings
    return bytes(data)


def _minimal_elf_with_internal_padding() -> bytes:
    section_names = b"\0.shstrtab\0.debug_line_str\0"
    debug_strings = b"source.c\0"
    section_count = 3
    section_offset = 64
    section_entry_size = 64
    section_table_end = section_offset + section_count * section_entry_size
    shstr_offset = section_table_end + 8
    debug_offset = shstr_offset + len(section_names)
    data = bytearray(debug_offset + len(debug_strings))

    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 0x10, 1, 62, 1)
    struct.pack_into("<Q", data, 0x18, 0)
    struct.pack_into("<Q", data, 0x20, 0)
    struct.pack_into("<Q", data, 0x28, section_offset)
    struct.pack_into("<I", data, 0x30, 0)
    struct.pack_into(
        "<6H", data, 0x34, 64, 0, 0, section_entry_size, section_count, 1
    )

    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_offset + section_entry_size,
        1,
        3,
        0,
        0,
        shstr_offset,
        len(section_names),
        0,
        0,
        1,
        0,
    )
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_offset + 2 * section_entry_size,
        len(b"\0.shstrtab\0"),
        3,
        0,
        0,
        debug_offset,
        len(debug_strings),
        0,
        0,
        1,
        0,
    )
    data[shstr_offset : shstr_offset + len(section_names)] = section_names
    data[debug_offset : debug_offset + len(debug_strings)] = debug_strings
    return bytes(data)


def test_hwdb_projection_rejects_unsorted_children(tmp_path):
    path = tmp_path / "hwdb.bin"
    path.write_bytes(_hwdb_with_children([ord("a"), ord("b")]))
    assert hist._hwdb_projection(path)["node_count"] == 3
    path.write_bytes(_hwdb_with_children([ord("b"), ord("a")]))
    with pytest.raises(hist.HistoricalReproducibilityError, match="strictly increasing"):
        hist._hwdb_projection(path)


def test_hwdb_projection_rejects_duplicate_children(tmp_path):
    path = tmp_path / "hwdb.bin"
    path.write_bytes(_hwdb_with_children([ord("a"), ord("a")]))
    with pytest.raises(hist.HistoricalReproducibilityError, match="strictly increasing"):
        hist._hwdb_projection(path)


def test_hwdb_projection_rejects_null_prefix_in_wildcard_node(tmp_path):
    path = tmp_path / "hwdb.bin"
    path.write_bytes(_hwdb_with_wildcard_value(null_wildcard_prefix=False))
    projection = hist._hwdb_projection(path)
    assert projection["record_count"] == 1
    assert projection["records_sha256"] == hist.sha256_json([
        {
            "match": "*",
            "key": " KEY",
            "value": "expected-value",
            "filename": "fixture.hwdb",
            "line": 1,
            "priority": 1,
        }
    ])

    path.write_bytes(_hwdb_with_wildcard_value(null_wildcard_prefix=True))
    with pytest.raises(
        hist.HistoricalReproducibilityError,
        match="string offset is outside the string table",
    ):
        hist._hwdb_projection(path)


def test_elf_semantic_digest_rejects_nonzero_internal_padding():
    data = bytearray(_minimal_elf_with_internal_padding())
    assert len(hist._elf_semantic_digest(bytes(data))) == 64
    data[64 + 3 * 64 + 3] = 1
    with pytest.raises(hist.HistoricalReproducibilityError, match="padding contains non-zero"):
        hist._elf_semantic_digest(bytes(data))


def test_decompress_module_rejects_lzma_alone_container(tmp_path):
    payload = _minimal_elf_with_internal_padding()
    path = tmp_path / "driver.ko.xz"
    path.write_bytes(lzma.compress(payload, format=lzma.FORMAT_ALONE))

    with pytest.raises(hist.HistoricalReproducibilityError, match="compression is invalid"):
        hist._decompress_module(path)


def test_decompress_module_rejects_trailing_data_after_xz(tmp_path):
    payload = _minimal_elf_with_internal_padding()
    path = tmp_path / "driver.ko.xz"
    path.write_bytes(lzma.compress(payload, format=lzma.FORMAT_XZ) + b"trailer")

    with pytest.raises(hist.HistoricalReproducibilityError, match="trailing data"):
        hist._decompress_module(path)

    path.write_bytes(lzma.compress(payload, format=lzma.FORMAT_XZ))
    assert hist._decompress_module(path) == payload


def test_nvidia_projection_binds_module_executable_status(monkeypatch, tmp_path):
    root = tmp_path / "nvidia"
    root.mkdir()
    module = root / "driver.ko.xz"
    module.write_bytes(b"synthetic")
    module.chmod(0o644)
    elf = _minimal_elf_with_internal_padding()
    monkeypatch.setattr(hist, "_decompress_module", lambda _path: elf)

    projection = hist._nvidia_projection(root, {module.name}, False)
    assert projection["module_executable"] is False

    module.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    with pytest.raises(hist.HistoricalReproducibilityError, match="executable status"):
        hist._nvidia_projection(root, {module.name}, False)
