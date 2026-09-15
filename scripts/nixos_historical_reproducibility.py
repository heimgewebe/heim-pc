#!/usr/bin/env python3
"""Fail-closed semantic verifier for one reviewed historical NixOS rebuild.

The normal production attestation path remains byte-exact.  This module handles
only a repository-reviewed exception for the sealed T003 source revision.  It
reconstructs the independent Nix closure from the managed store database,
requires every non-exception entry to remain byte-exact, and applies narrowly
specified semantic projections to exactly two known non-reproducible outputs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import lzma
import os
import re
import sqlite3
import stat
import struct
from pathlib import Path
from typing import Any


class HistoricalReproducibilityError(RuntimeError):
    pass


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NIX_PATH_RE = re.compile(r"^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+$")
_NIX_HASH_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
_NAR_HASH_RE = re.compile(r"^sha256-[A-Za-z0-9+/]{43}=$")
_BUILD_ROOT_MARKER = "/nix/var/nix/builds/"
_BUILD_ROOT_TEXT_RE = re.compile(r"/nix/var/nix/builds/nix-[0-9]+-[0-9]+")
_BUILD_ROOT_BYTES_RE = re.compile(rb"/nix/var/nix/builds/nix-[0-9]+-[0-9]+")
_HWDB_SIGNATURE = b"KSLPHHRH"
_MAX_HWDB_BYTES = 32 * 1024 * 1024
_MAX_MODULE_COMPRESSED_BYTES = 128 * 1024 * 1024
_MAX_MODULE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise HistoricalReproducibilityError(f"{label} is not a SHA-256 digest")
    return value


def _require_nix_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or _NIX_PATH_RE.fullmatch(value) is None:
        raise HistoricalReproducibilityError(f"{label} is not a canonical Nix store path")
    return value


def _regular_file(path: Path, *, max_bytes: int | None = None) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise HistoricalReproducibilityError(f"required file is unavailable: {path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink < 1:
        raise HistoricalReproducibilityError(f"required file identity is unsafe: {path.name}")
    if max_bytes is not None and (info.st_size < 0 or info.st_size > max_bytes):
        raise HistoricalReproducibilityError(f"required file is outside its size bound: {path.name}")
    return info


def _safe_store_root(store_root: Path) -> Path:
    store_root = Path(store_root)
    if (
        not store_root.is_absolute()
        or os.path.normpath(str(store_root)) != str(store_root)
        or store_root.is_symlink()
        or not store_root.is_dir()
    ):
        raise HistoricalReproducibilityError("independent managed Nix store root is unsafe")
    store_dir = store_root / "store"
    db_dir = store_root / "var" / "nix" / "db"
    for path in (store_dir, db_dir):
        try:
            info = path.lstat()
        except OSError as exc:
            raise HistoricalReproducibilityError("independent managed Nix store is incomplete") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise HistoricalReproducibilityError("independent managed Nix store directory is unsafe")
    _regular_file(db_dir / "db.sqlite")
    return store_root


def _store_member(store_root: Path, nix_path: str) -> Path:
    nix_path = _require_nix_path(nix_path, "accepted exception path")
    member = store_root / "store" / Path(nix_path).name
    if member.parent != store_root / "store":
        raise HistoricalReproducibilityError("Nix store member escaped the managed store")
    return member


def _normalize_build_root_text(value: str) -> str:
    if _BUILD_ROOT_MARKER not in value:
        return value
    matches = list(_BUILD_ROOT_TEXT_RE.finditer(value))
    if len(matches) != 1:
        raise HistoricalReproducibilityError("unexpected transient Nix build-root spelling")
    normalized = _BUILD_ROOT_TEXT_RE.sub("<NIX_BUILD_ROOT>", value)
    if _BUILD_ROOT_MARKER in normalized:
        raise HistoricalReproducibilityError("unrecognized transient Nix build-root residue")
    return normalized


def _normalize_build_root_bytes(value: bytes) -> bytes:
    marker = _BUILD_ROOT_MARKER.encode("ascii")
    if marker not in value:
        return value
    matches = list(_BUILD_ROOT_BYTES_RE.finditer(value))
    if len(matches) != 1:
        raise HistoricalReproducibilityError("unexpected transient Nix build-root bytes")
    normalized = _BUILD_ROOT_BYTES_RE.sub(b"<NIX_BUILD_ROOT>", value)
    if marker in normalized:
        raise HistoricalReproducibilityError("unrecognized transient Nix build-root byte residue")
    return normalized


def load_acceptance(path: Path) -> tuple[dict[str, Any], str]:
    path = Path(path)
    _regular_file(path, max_bytes=128 * 1024)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HistoricalReproducibilityError("historical reproducibility acceptance is invalid JSON") from exc
    required = {
        "schema_version", "kind", "source_revision", "system_path",
        "candidate_closure_manifest_sha256", "candidate_closure_path_count",
        "stable_closure_projection_sha256", "exceptions", "semantic_projections",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise HistoricalReproducibilityError("historical reproducibility acceptance shape is invalid")
    if value.get("schema_version") != 1 or value.get("kind") != "heim_pc.nixos_historical_reproducibility_acceptance":
        raise HistoricalReproducibilityError("historical reproducibility acceptance identity mismatch")
    if not isinstance(value.get("source_revision"), str) or re.fullmatch(r"[0-9a-f]{40}", value["source_revision"]) is None:
        raise HistoricalReproducibilityError("historical reproducibility source revision is invalid")
    _require_nix_path(value.get("system_path"), "historical reproducibility system path")
    _require_sha256(value.get("candidate_closure_manifest_sha256"), "candidate closure manifest")
    _require_sha256(value.get("stable_closure_projection_sha256"), "stable closure projection")
    if type(value.get("candidate_closure_path_count")) is not int or value["candidate_closure_path_count"] < 1:
        raise HistoricalReproducibilityError("historical reproducibility closure count is invalid")

    exceptions = value.get("exceptions")
    if not isinstance(exceptions, list) or len(exceptions) != 2:
        raise HistoricalReproducibilityError("historical reproducibility requires exactly two exceptions")
    exception_paths: set[str] = set()
    for item in exceptions:
        if not isinstance(item, dict) or set(item) != {"path", "candidate_record"}:
            raise HistoricalReproducibilityError("historical reproducibility exception shape is invalid")
        exception_path = _require_nix_path(item.get("path"), "historical reproducibility exception path")
        if exception_path in exception_paths:
            raise HistoricalReproducibilityError("historical reproducibility exception paths are not unique")
        exception_paths.add(exception_path)
        record = item.get("candidate_record")
        if not isinstance(record, dict) or set(record) != {"narHash", "narSize", "references", "deriver"}:
            raise HistoricalReproducibilityError("historical reproducibility candidate record shape is invalid")
        if not isinstance(record.get("narHash"), str) or _NAR_HASH_RE.fullmatch(record["narHash"]) is None:
            raise HistoricalReproducibilityError("historical reproducibility candidate NAR hash is invalid")
        if type(record.get("narSize")) is not int or record["narSize"] < 0:
            raise HistoricalReproducibilityError("historical reproducibility candidate NAR size is invalid")
        _require_nix_path(record.get("deriver"), "historical reproducibility exception deriver")
        references = record.get("references")
        if not isinstance(references, list) or references != sorted(set(references)):
            raise HistoricalReproducibilityError("historical reproducibility exception references are invalid")
        for reference in references:
            _require_nix_path(reference, "historical reproducibility exception reference")

    projections = value.get("semantic_projections")
    if not isinstance(projections, dict) or set(projections) != {"hwdb", "nvidia"}:
        raise HistoricalReproducibilityError("historical reproducibility semantic projection shape is invalid")
    hwdb = projections["hwdb"]
    if not isinstance(hwdb, dict) or set(hwdb) != {"kind", "tool_version", "node_count", "record_count", "records_sha256"}:
        raise HistoricalReproducibilityError("hwdb acceptance shape is invalid")
    if hwdb.get("kind") != "systemd-hwdb-v260-build-root-normalized" or hwdb.get("tool_version") != 260:
        raise HistoricalReproducibilityError("hwdb acceptance identity is invalid")
    for key in ("node_count", "record_count"):
        if type(hwdb.get(key)) is not int or hwdb[key] < 1:
            raise HistoricalReproducibilityError("hwdb acceptance count is invalid")
    _require_sha256(hwdb.get("records_sha256"), "hwdb records")

    nvidia = projections["nvidia"]
    if not isinstance(nvidia, dict) or set(nvidia) != {
        "kind", "inventory_count", "inventory_sha256", "module_executable",
        "module_semantic_sha256",
    }:
        raise HistoricalReproducibilityError("NVIDIA acceptance shape is invalid")
    if nvidia.get("kind") != "nvidia-kernel-modules-elf-semantic-v1":
        raise HistoricalReproducibilityError("NVIDIA acceptance identity is invalid")
    if type(nvidia.get("inventory_count")) is not int or nvidia["inventory_count"] < 1:
        raise HistoricalReproducibilityError("NVIDIA acceptance inventory count is invalid")
    if type(nvidia.get("module_executable")) is not bool:
        raise HistoricalReproducibilityError("NVIDIA acceptance executable status is invalid")
    _require_sha256(nvidia.get("inventory_sha256"), "NVIDIA inventory")
    modules = nvidia.get("module_semantic_sha256")
    if not isinstance(modules, dict) or len(modules) != 5:
        raise HistoricalReproducibilityError("NVIDIA acceptance module set is invalid")
    for relative, digest in modules.items():
        if (
            not isinstance(relative, str)
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or not relative.endswith(".ko.xz")
        ):
            raise HistoricalReproducibilityError("NVIDIA acceptance module path is invalid")
        _require_sha256(digest, "NVIDIA module semantic digest")
    return json.loads(json.dumps(value)), sha256_file(path)


def _closure_records(store_root: Path, system_path: str) -> dict[str, dict[str, Any]]:
    store_root = _safe_store_root(store_root)
    system_path = _require_nix_path(system_path, "independent system path")
    db_path = store_root / "var" / "nix" / "db" / "db.sqlite"
    try:
        db = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise HistoricalReproducibilityError("cannot open independent Nix database read-only") from exc
    try:
        rows: dict[str, dict[str, Any]] = {}
        id_to_path: dict[int, str] = {}
        for path, identity, raw_hash, nar_size, deriver in db.execute(
            "select path,id,hash,narSize,deriver from ValidPaths"
        ):
            if not isinstance(path, str) or _NIX_PATH_RE.fullmatch(path) is None:
                continue
            if type(identity) is not int or identity <= 0 or identity in id_to_path:
                raise HistoricalReproducibilityError("independent Nix path identity is invalid")
            match = _NIX_HASH_RE.fullmatch(str(raw_hash))
            if match is None or type(nar_size) is not int or nar_size < 0:
                raise HistoricalReproducibilityError("independent Nix path metadata is invalid")
            deriver_value = None if deriver is None else str(deriver)
            if deriver_value is not None:
                _require_nix_path(deriver_value, "independent Nix deriver")
            rows[path] = {
                "id": identity,
                "narHash": "sha256-" + base64.b64encode(bytes.fromhex(match.group(1))).decode("ascii"),
                "narSize": nar_size,
                "deriver": deriver_value,
            }
            id_to_path[identity] = path
        refs: dict[int, list[int]] = {}
        for referrer, reference in db.execute("select referrer,reference from Refs"):
            if type(referrer) is not int or type(reference) is not int:
                raise HistoricalReproducibilityError("independent Nix reference identity is invalid")
            refs.setdefault(referrer, []).append(reference)
    except sqlite3.Error as exc:
        raise HistoricalReproducibilityError("cannot read independent Nix database") from exc
    finally:
        db.close()
    if system_path not in rows:
        raise HistoricalReproducibilityError("independent Nix database lacks the system path")

    seen: set[str] = set()
    stack = [system_path]
    while stack:
        path = stack.pop()
        if path in seen:
            continue
        row = rows.get(path)
        if row is None:
            raise HistoricalReproducibilityError("independent Nix closure contains an unknown path")
        seen.add(path)
        for reference_id in refs.get(row["id"], []):
            reference_path = id_to_path.get(reference_id)
            if reference_path is None:
                raise HistoricalReproducibilityError("independent Nix closure reference is unresolved")
            stack.append(reference_path)

    result: dict[str, dict[str, Any]] = {}
    for path in sorted(seen):
        row = rows[path]
        references: list[str] = []
        for reference_id in refs.get(row["id"], []):
            reference_path = id_to_path.get(reference_id)
            if reference_path is None:
                raise HistoricalReproducibilityError("independent Nix closure reference is unresolved")
            references.append(reference_path)
        if len(references) != len(set(references)):
            raise HistoricalReproducibilityError("independent Nix closure contains duplicate references")
        result[path] = {
            "path": path,
            "narHash": row["narHash"],
            "narSize": row["narSize"],
            "references": sorted(references),
            "deriver": row["deriver"],
        }
    return result


def _stable_projection(records: dict[str, dict[str, Any]], exception_paths: set[str]) -> str:
    entries = [
        {
            "path": record["path"],
            "narHash": record["narHash"],
            "narSize": record["narSize"],
            "references": record["references"],
        }
        for path, record in sorted(records.items())
        if path not in exception_paths
    ]
    return sha256_json({"schema_version": 1, "entries": entries})


def _closure_manifest_sha256(records: dict[str, dict[str, Any]]) -> str:
    entries = [
        {
            "path": record["path"],
            "narHash": record["narHash"],
            "narSize": record["narSize"],
            "references": record["references"],
        }
        for _path, record in sorted(records.items())
    ]
    return sha256_json({"schema_version": 1, "entries": entries})


def _bounded_read(path: Path, max_bytes: int) -> bytes:
    info = _regular_file(path, max_bytes=max_bytes)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise HistoricalReproducibilityError(f"cannot read bounded file: {path.name}") from exc
    if len(data) != info.st_size or len(data) > max_bytes:
        raise HistoricalReproducibilityError(f"bounded file changed while reading: {path.name}")
    return data


def _hwdb_projection(path: Path) -> dict[str, Any]:
    data = _bounded_read(path, _MAX_HWDB_BYTES)
    if len(data) < 80 or data[:8] != _HWDB_SIGNATURE:
        raise HistoricalReproducibilityError("hwdb binary signature is invalid")
    try:
        tool_version, file_size, header_size, node_size, child_size, value_size, root_offset, nodes_len, strings_len = struct.unpack_from(
            "<9Q", data, 8
        )
    except struct.error as exc:
        raise HistoricalReproducibilityError("hwdb header is truncated") from exc
    if (
        tool_version != 260
        or file_size != len(data)
        or header_size != 80
        or node_size != 24
        or child_size != 16
        or value_size != 32
        or nodes_len <= 0
        or strings_len <= 0
        or header_size + nodes_len + strings_len != len(data)
    ):
        raise HistoricalReproducibilityError("hwdb v260 layout is outside the reviewed contract")
    node_start = header_size
    node_end = header_size + nodes_len
    string_start = node_end
    if not node_start <= root_offset < node_end:
        raise HistoricalReproducibilityError("hwdb root offset is invalid")

    def cstring(offset: int) -> str:
        if not string_start <= offset < len(data):
            raise HistoricalReproducibilityError("hwdb string offset is outside the string table")
        end = data.find(b"\0", offset)
        if end < 0:
            raise HistoricalReproducibilityError("hwdb string is unterminated")
        try:
            return data[offset:end].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise HistoricalReproducibilityError("hwdb string is not UTF-8") from exc

    seen: set[int] = set()
    records: list[dict[str, Any]] = []

    def walk(offset: int, prefix: str) -> None:
        if offset in seen:
            raise HistoricalReproducibilityError("hwdb trie contains a cycle or shared node")
        if offset < node_start or offset + node_size > node_end:
            raise HistoricalReproducibilityError("hwdb node offset is outside the node table")
        seen.add(offset)
        try:
            prefix_offset = struct.unpack_from("<Q", data, offset)[0]
            child_count = data[offset + 8]
            value_count = struct.unpack_from("<Q", data, offset + 16)[0]
        except (IndexError, struct.error) as exc:
            raise HistoricalReproducibilityError("hwdb node is truncated") from exc
        pattern = prefix + (cstring(prefix_offset) if prefix_offset else "")
        child_base = offset + node_size
        value_base = child_base + child_count * child_size
        end = value_base + value_count * value_size
        if end > node_end:
            raise HistoricalReproducibilityError("hwdb node payload exceeds the node table")
        children: list[tuple[int, int]] = []
        for index in range(child_count):
            child_offset = child_base + index * child_size
            character = data[child_offset]
            target = struct.unpack_from("<Q", data, child_offset + 8)[0]
            if target < node_start or target >= node_end:
                raise HistoricalReproducibilityError("hwdb child target is outside the node table")
            children.append((character, target))
        if any(
            previous[0] >= current[0]
            for previous, current in zip(children, children[1:])
        ):
            raise HistoricalReproducibilityError(
                "hwdb child characters are not strictly increasing"
            )
        for index in range(value_count):
            value_offset = value_base + index * value_size
            key_offset, data_offset, filename_offset = struct.unpack_from("<QQQ", data, value_offset)
            line_number = struct.unpack_from("<I", data, value_offset + 24)[0]
            file_priority = struct.unpack_from("<H", data, value_offset + 28)[0]
            filename = cstring(filename_offset) if filename_offset else ""
            records.append({
                "match": pattern,
                "key": cstring(key_offset),
                "value": cstring(data_offset),
                "filename": _normalize_build_root_text(filename),
                "line": line_number,
                "priority": file_priority,
            })
        for character, child_offset in children:
            walk(child_offset, pattern + chr(character))

    walk(root_offset, "")
    records.sort(
        key=lambda item: (
            item["match"], item["key"], item["value"], item["filename"],
            item["line"], item["priority"],
        )
    )
    return {
        "kind": "systemd-hwdb-v260-build-root-normalized",
        "tool_version": tool_version,
        "node_count": len(seen),
        "record_count": len(records),
        "records_sha256": sha256_json(records),
    }


def _decompress_module(path: Path) -> bytes:
    raw = _bounded_read(path, _MAX_MODULE_COMPRESSED_BYTES)
    if not raw:
        raise HistoricalReproducibilityError("NVIDIA module is empty")
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        data = decoder.decompress(raw, max_length=_MAX_MODULE_UNCOMPRESSED_BYTES + 1)
    except lzma.LZMAError as exc:
        raise HistoricalReproducibilityError("NVIDIA module compression is invalid") from exc
    if len(data) > _MAX_MODULE_UNCOMPRESSED_BYTES:
        raise HistoricalReproducibilityError("NVIDIA module exceeds the decompression bound")
    if not decoder.eof:
        raise HistoricalReproducibilityError(
            "NVIDIA module XZ stream is truncated or exceeds the decompression bound"
        )
    if decoder.unused_data:
        raise HistoricalReproducibilityError(
            "NVIDIA module contains trailing data after the XZ stream"
        )
    return data


def _cstring(blob: bytes, offset: int, label: str) -> bytes:
    if offset < 0 or offset >= len(blob):
        raise HistoricalReproducibilityError(f"{label} string offset is invalid")
    end = blob.find(b"\0", offset)
    if end < 0:
        raise HistoricalReproducibilityError(f"{label} string is unterminated")
    return blob[offset:end]


def _elf_semantic_digest(data: bytes) -> str:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:7] != b"\x02\x01\x01":
        raise HistoricalReproducibilityError("NVIDIA module is not ELF64 little-endian")
    if data[7:16] != b"\0" * 9:
        raise HistoricalReproducibilityError("NVIDIA module ELF identity padding is unexpected")
    try:
        e_type, e_machine, e_version = struct.unpack_from("<HHI", data, 0x10)
        e_entry = struct.unpack_from("<Q", data, 0x18)[0]
        e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
        section_offset = struct.unpack_from("<Q", data, 0x28)[0]
        e_flags = struct.unpack_from("<I", data, 0x30)[0]
        e_ehsize, e_phentsize, e_phnum, section_entry_size, section_count, section_string_index = struct.unpack_from(
            "<6H", data, 0x34
        )
    except struct.error as exc:
        raise HistoricalReproducibilityError("NVIDIA module ELF header is truncated") from exc
    if (
        e_type != 1
        or e_machine != 62
        or e_version != 1
        or e_entry != 0
        or e_phoff != 0
        or e_flags != 0
        or e_ehsize != 64
        or e_phentsize != 0
        or e_phnum != 0
        or section_entry_size != 64
        or section_count < 1
        or section_string_index >= section_count
        or section_offset < 64
        or section_offset + section_entry_size * section_count > len(data)
    ):
        raise HistoricalReproducibilityError("NVIDIA module ELF header is outside the reviewed ET_REL shape")
    sections: list[tuple[int, ...]] = []
    try:
        for index in range(section_count):
            sections.append(
                struct.unpack_from("<IIQQQQIIQQ", data, section_offset + index * section_entry_size)
            )
    except struct.error as exc:
        raise HistoricalReproducibilityError("NVIDIA module section table is truncated") from exc
    for header in sections:
        _name, section_type, _flags, _address, offset, size, _link, _info, _align, _entsize = header
        if section_type != 8 and (offset > len(data) or size > len(data) - offset):
            raise HistoricalReproducibilityError("NVIDIA module section payload is out of bounds")
    string_header = sections[section_string_index]
    if string_header[1] != 3 or string_header[4] + string_header[5] > len(data):
        raise HistoricalReproducibilityError("NVIDIA module section-name string table is invalid")
    section_names_blob = data[string_header[4] : string_header[4] + string_header[5]]
    section_names: list[str] = []
    for header in sections:
        try:
            section_names.append(_cstring(section_names_blob, header[0], "ELF section-name").decode("ascii", "strict"))
        except UnicodeDecodeError as exc:
            raise HistoricalReproducibilityError("NVIDIA module section name is not ASCII") from exc
    if len(section_names) != len(set(section_names)):
        raise HistoricalReproducibilityError("NVIDIA module section names are not unique")
    try:
        debug_line_index = section_names.index(".debug_line_str")
    except ValueError as exc:
        raise HistoricalReproducibilityError("NVIDIA module lacks .debug_line_str") from exc
    debug_header = sections[debug_line_index]
    debug_blob = data[debug_header[4] : debug_header[4] + debug_header[5]]
    normalized_debug_strings: list[str] = []
    cursor = 0
    while cursor < len(debug_blob):
        raw = _cstring(debug_blob, cursor, "NVIDIA debug-line")
        try:
            normalized_debug_strings.append(
                _normalize_build_root_bytes(raw).decode("utf-8", "strict")
            )
        except UnicodeDecodeError as exc:
            raise HistoricalReproducibilityError("NVIDIA debug-line string is not UTF-8") from exc
        cursor += len(raw) + 1
    normalized_debug_strings.sort()

    records: list[dict[str, Any]] = []
    file_regions: list[tuple[int, int]] = [
        (0, 64),
        (section_offset, section_offset + section_entry_size * section_count),
    ]
    for index, header in enumerate(sections):
        _name_offset, section_type, flags, address, offset, size, link, info, alignment, entry_size = header
        name = section_names[index]
        payload = b"" if section_type == 8 else data[offset : offset + size]
        if section_type != 8 and size:
            file_regions.append((offset, offset + size))
        record: dict[str, Any] = {
            "index": index,
            "name": name,
            "type": section_type,
            "flags": flags,
            "address": address,
            "link": link,
            "info": info,
            "align": alignment,
            "entsize": entry_size,
        }
        if name == ".debug_line_str":
            record.update({
                "policy": "string-multiset-build-root-normalized",
                "string_count": len(normalized_debug_strings),
                "strings_sha256": sha256_json(normalized_debug_strings),
            })
        elif name in {".rela.debug_info", ".rela.debug_line"}:
            if section_type != 4 or entry_size != 24 or size % 24 or link >= section_count or info >= section_count:
                raise HistoricalReproducibilityError("NVIDIA debug relocation section shape is invalid")
            symbol_header = sections[link]
            if symbol_header[1] != 2 or symbol_header[9] != 24 or symbol_header[5] % 24:
                raise HistoricalReproducibilityError("NVIDIA debug relocation symbol table is invalid")
            symbol_string_index = symbol_header[6]
            if symbol_string_index >= section_count:
                raise HistoricalReproducibilityError("NVIDIA symbol string table index is invalid")
            symbol_string_header = sections[symbol_string_index]
            if symbol_string_header[1] != 3 or symbol_string_header[4] + symbol_string_header[5] > len(data):
                raise HistoricalReproducibilityError("NVIDIA symbol string table is invalid")
            symbol_strings = data[
                symbol_string_header[4] : symbol_string_header[4] + symbol_string_header[5]
            ]
            symbols: list[tuple[str, int, int, int, int, int]] = []
            symbol_base = symbol_header[4]
            for symbol_offset in range(0, symbol_header[5], 24):
                try:
                    name_offset, symbol_info, symbol_other, section_index, symbol_value, symbol_size = struct.unpack_from(
                        "<IBBHQQ", data, symbol_base + symbol_offset
                    )
                except struct.error as exc:
                    raise HistoricalReproducibilityError("NVIDIA symbol table is truncated") from exc
                try:
                    symbol_name = (
                        _cstring(symbol_strings, name_offset, "NVIDIA symbol").decode("utf-8", "strict")
                        if name_offset else ""
                    )
                except UnicodeDecodeError as exc:
                    raise HistoricalReproducibilityError("NVIDIA symbol name is not UTF-8") from exc
                symbols.append(
                    (symbol_name, symbol_info, symbol_other, section_index, symbol_value, symbol_size)
                )
            relocations: list[dict[str, Any]] = []
            for relocation_offset in range(0, size, 24):
                try:
                    target_offset, raw_info, addend = struct.unpack_from("<QQq", payload, relocation_offset)
                except struct.error as exc:
                    raise HistoricalReproducibilityError("NVIDIA relocation table is truncated") from exc
                symbol_index = raw_info >> 32
                relocation_type = raw_info & 0xFFFFFFFF
                if symbol_index >= len(symbols):
                    raise HistoricalReproducibilityError("NVIDIA relocation symbol index is invalid")
                symbol_name, symbol_info, symbol_other, target_section_index, symbol_value, symbol_size = symbols[symbol_index]
                target_section = section_names[target_section_index] if target_section_index < section_count else None
                relocation: dict[str, Any] = {
                    "r_offset": target_offset,
                    "r_type": relocation_type,
                    "symbol_name": symbol_name,
                    "symbol_info": symbol_info,
                    "symbol_other": symbol_other,
                    "symbol_section": target_section,
                    "symbol_value": symbol_value,
                    "symbol_size": symbol_size,
                }
                if target_section == ".debug_line_str":
                    resolved_offset = symbol_value + addend
                    raw_target = _cstring(debug_blob, resolved_offset, "NVIDIA relocation target")
                    try:
                        resolved = _normalize_build_root_bytes(raw_target).decode("utf-8", "strict")
                    except UnicodeDecodeError as exc:
                        raise HistoricalReproducibilityError("NVIDIA relocation target is not UTF-8") from exc
                    relocation["addend_policy"] = "resolved-normalized-debug-line-string"
                    relocation["target_string"] = resolved
                else:
                    relocation["addend_policy"] = "exact"
                    relocation["addend"] = addend
                relocations.append(relocation)
            record.update({
                "policy": "semantic-rela",
                "target": section_names[info],
                "entry_count": len(relocations),
                "relocations_sha256": sha256_json(relocations),
            })
        elif name == ".note.gnu.build-id":
            if section_type != 7 or not (flags & 0x2) or size != 36:
                raise HistoricalReproducibilityError("NVIDIA GNU build-id note shape is invalid")
            try:
                name_size, description_size, note_type = struct.unpack_from("<III", payload, 0)
            except struct.error as exc:
                raise HistoricalReproducibilityError("NVIDIA GNU build-id note is truncated") from exc
            if (name_size, description_size, note_type) != (4, 20, 3) or payload[12:16] != b"GNU\0":
                raise HistoricalReproducibilityError("NVIDIA GNU build-id note identity is invalid")
            record.update({
                "policy": "derived-build-id-shape",
                "size": size,
                "note_shape": [4, 20, 3, "GNU"],
            })
        else:
            record.update({
                "policy": "exact",
                "size": size,
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        records.append(record)
    file_regions.sort()
    cursor = 0
    for start, end in file_regions:
        if start < cursor:
            raise HistoricalReproducibilityError(
                "NVIDIA module ELF on-disk regions overlap"
            )
        if start > cursor and any(data[cursor:start]):
            raise HistoricalReproducibilityError(
                "NVIDIA module ELF padding contains non-zero bytes"
            )
        cursor = end
    if cursor != len(data):
        raise HistoricalReproducibilityError("NVIDIA module contains unbound bytes outside the ELF structure")
    return sha256_json(records)


def _nvidia_projection(
    path: Path,
    expected_modules: set[str],
    expected_module_executable: bool,
) -> dict[str, Any]:
    if type(expected_module_executable) is not bool:
        raise HistoricalReproducibilityError("NVIDIA expected executable status is invalid")
    try:
        root_info = path.lstat()
    except OSError as exc:
        raise HistoricalReproducibilityError("NVIDIA exception output is unavailable") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise HistoricalReproducibilityError("NVIDIA exception output is not a safe directory")
    inventory: list[dict[str, Any]] = []
    observed_modules: set[str] = set()
    module_digests: dict[str, str] = {}
    for base, directories, files in os.walk(path, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        base_path = Path(base)
        for name in [*directories, *files]:
            member = base_path / name
            relative = str(member.relative_to(path))
            info = member.lstat()
            if stat.S_ISDIR(info.st_mode):
                inventory.append({"path": relative, "kind": "dir", "mode": stat.S_IMODE(info.st_mode)})
            elif stat.S_ISLNK(info.st_mode):
                inventory.append({"path": relative, "kind": "symlink", "target": os.readlink(member)})
            elif stat.S_ISREG(info.st_mode):
                if relative in expected_modules:
                    observed_modules.add(relative)
                    if bool(info.st_mode & 0o111) != expected_module_executable:
                        raise HistoricalReproducibilityError(
                            "NVIDIA module executable status differs from reviewed acceptance"
                        )
                    module_digests[relative] = _elf_semantic_digest(_decompress_module(member))
                else:
                    raw = _bounded_read(member, _MAX_MODULE_COMPRESSED_BYTES)
                    inventory.append({
                        "path": relative,
                        "kind": "file",
                        "mode": stat.S_IMODE(info.st_mode),
                        "size": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    })
            else:
                raise HistoricalReproducibilityError("NVIDIA exception output contains an unsupported file type")
    if observed_modules != expected_modules:
        raise HistoricalReproducibilityError("NVIDIA exception module set differs from reviewed acceptance")
    inventory.sort(key=lambda item: item["path"])
    return {
        "kind": "nvidia-kernel-modules-elf-semantic-v1",
        "inventory_count": len(inventory),
        "inventory_sha256": sha256_json(inventory),
        "module_executable": expected_module_executable,
        "module_semantic_sha256": {key: module_digests[key] for key in sorted(module_digests)},
    }


def verify_historical_rebuild(
    *,
    acceptance_path: Path,
    candidate_artifact: dict[str, Any],
    independent_artifact: dict[str, Any],
    independent_store_root: Path,
) -> dict[str, Any]:
    acceptance, acceptance_sha256 = load_acceptance(acceptance_path)
    if (
        candidate_artifact.get("source_revision") != acceptance["source_revision"]
        or candidate_artifact.get("system_path") != acceptance["system_path"]
        or candidate_artifact.get("closure_manifest_sha256") != acceptance["candidate_closure_manifest_sha256"]
        or candidate_artifact.get("closure_path_count") != acceptance["candidate_closure_path_count"]
    ):
        raise HistoricalReproducibilityError("candidate does not match the reviewed historical acceptance identity")
    if (
        independent_artifact.get("source_revision") != acceptance["source_revision"]
        or independent_artifact.get("system_path") != acceptance["system_path"]
        or independent_artifact.get("closure_path_count") != acceptance["candidate_closure_path_count"]
    ):
        raise HistoricalReproducibilityError("independent rebuild does not match the reviewed historical acceptance identity")

    store_root = _safe_store_root(Path(independent_store_root))
    records = _closure_records(store_root, acceptance["system_path"])
    if len(records) != acceptance["candidate_closure_path_count"]:
        raise HistoricalReproducibilityError("independent closure path count differs from reviewed acceptance")
    reconstructed_manifest_sha256 = _closure_manifest_sha256(records)
    independent_manifest_sha256 = _require_sha256(
        independent_artifact.get("closure_manifest_sha256"),
        "independent rebuild closure manifest",
    )
    if reconstructed_manifest_sha256 != independent_manifest_sha256:
        raise HistoricalReproducibilityError(
            "independent artifact closure manifest is not bound to its managed Nix store"
        )
    if reconstructed_manifest_sha256 == acceptance["candidate_closure_manifest_sha256"]:
        raise HistoricalReproducibilityError(
            "historical reproducibility acceptance requires a real closure manifest variance"
        )
    accepted_exceptions = {item["path"]: item for item in acceptance["exceptions"]}
    exception_paths = set(accepted_exceptions)
    stable_sha256 = _stable_projection(records, exception_paths)
    if stable_sha256 != acceptance["stable_closure_projection_sha256"]:
        raise HistoricalReproducibilityError("independent stable closure projection differs from reviewed acceptance")
    for path, item in accepted_exceptions.items():
        observed = records.get(path)
        if observed is None:
            raise HistoricalReproducibilityError("independent closure lacks a reviewed exception path")
        candidate_record = item["candidate_record"]
        if observed["references"] != candidate_record["references"] or observed["deriver"] != candidate_record["deriver"]:
            raise HistoricalReproducibilityError("independent exception graph/deriver differs from reviewed acceptance")

    hwdb_item = next(
        item for item in acceptance["exceptions"] if item["path"].endswith("-hwdb.bin")
    )
    nvidia_item = next(
        item for item in acceptance["exceptions"] if "-nvidia-kernel-modules-" in item["path"]
    )
    observed_hwdb = _hwdb_projection(_store_member(store_root, hwdb_item["path"]))
    expected_hwdb = acceptance["semantic_projections"]["hwdb"]
    if observed_hwdb != expected_hwdb:
        raise HistoricalReproducibilityError("independent hwdb semantics differ from reviewed acceptance")
    expected_nvidia = acceptance["semantic_projections"]["nvidia"]
    expected_modules = set(expected_nvidia["module_semantic_sha256"])
    observed_nvidia = _nvidia_projection(
        _store_member(store_root, nvidia_item["path"]),
        expected_modules,
        expected_nvidia["module_executable"],
    )
    if observed_nvidia != expected_nvidia:
        raise HistoricalReproducibilityError("independent NVIDIA module semantics differ from reviewed acceptance")

    projection = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_historical_reproducibility_verification",
        "acceptance_sha256": acceptance_sha256,
        "source_revision": acceptance["source_revision"],
        "system_path": acceptance["system_path"],
        "candidate_closure_manifest_sha256": acceptance["candidate_closure_manifest_sha256"],
        "independent_closure_manifest_sha256": reconstructed_manifest_sha256,
        "closure_path_count": len(records),
        "stable_closure_projection_sha256": stable_sha256,
        "exception_paths": sorted(exception_paths),
        "hwdb_records_sha256": observed_hwdb["records_sha256"],
        "nvidia_inventory_sha256": observed_nvidia["inventory_sha256"],
        "nvidia_module_semantic_sha256": observed_nvidia["module_semantic_sha256"],
    }
    return {**projection, "verification_sha256": sha256_json(projection)}


def validate_verification_evidence(
    *,
    acceptance_path: Path,
    candidate_artifact: dict[str, Any],
    value: Any,
) -> dict[str, Any]:
    required = {
        "schema_version", "kind", "acceptance_sha256", "source_revision",
        "system_path", "candidate_closure_manifest_sha256",
        "independent_closure_manifest_sha256", "closure_path_count",
        "stable_closure_projection_sha256", "exception_paths",
        "hwdb_records_sha256", "nvidia_inventory_sha256",
        "nvidia_module_semantic_sha256", "verification_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise HistoricalReproducibilityError(
            "historical reproducibility verification evidence shape is invalid"
        )
    acceptance, acceptance_sha256 = load_acceptance(acceptance_path)
    projection = dict(value)
    verification_sha256 = projection.pop("verification_sha256", None)
    _require_sha256(verification_sha256, "historical reproducibility verification")
    if sha256_json(projection) != verification_sha256:
        raise HistoricalReproducibilityError(
            "historical reproducibility verification digest is invalid"
        )
    if (
        value.get("schema_version") != 1
        or value.get("kind")
        != "heim_pc.nixos_historical_reproducibility_verification"
        or value.get("acceptance_sha256") != acceptance_sha256
        or value.get("source_revision") != acceptance["source_revision"]
        or value.get("system_path") != acceptance["system_path"]
        or value.get("candidate_closure_manifest_sha256")
        != acceptance["candidate_closure_manifest_sha256"]
        or value.get("closure_path_count")
        != acceptance["candidate_closure_path_count"]
        or value.get("stable_closure_projection_sha256")
        != acceptance["stable_closure_projection_sha256"]
        or value.get("exception_paths")
        != sorted(item["path"] for item in acceptance["exceptions"])
        or value.get("hwdb_records_sha256")
        != acceptance["semantic_projections"]["hwdb"]["records_sha256"]
        or value.get("nvidia_inventory_sha256")
        != acceptance["semantic_projections"]["nvidia"]["inventory_sha256"]
        or value.get("nvidia_module_semantic_sha256")
        != acceptance["semantic_projections"]["nvidia"]["module_semantic_sha256"]
    ):
        raise HistoricalReproducibilityError(
            "historical reproducibility verification evidence does not match acceptance"
        )
    independent_closure_sha256 = value.get("independent_closure_manifest_sha256")
    _require_sha256(
        independent_closure_sha256, "independent historical closure manifest"
    )
    if independent_closure_sha256 == acceptance["candidate_closure_manifest_sha256"]:
        raise HistoricalReproducibilityError(
            "historical reproducibility evidence must represent a real manifest variance"
        )
    if (
        candidate_artifact.get("source_revision") != acceptance["source_revision"]
        or candidate_artifact.get("system_path") != acceptance["system_path"]
        or candidate_artifact.get("closure_manifest_sha256")
        != acceptance["candidate_closure_manifest_sha256"]
        or candidate_artifact.get("closure_path_count")
        != acceptance["candidate_closure_path_count"]
    ):
        raise HistoricalReproducibilityError(
            "historical reproducibility verification is not bound to current candidate"
        )
    return json.loads(json.dumps(value))
