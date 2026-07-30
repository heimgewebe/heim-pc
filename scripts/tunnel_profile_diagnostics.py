#!/usr/bin/env python3
"""Diagnose and repair local tunnel-client health-listener collisions safely.

The tool deliberately reads only profile YAML files from one bounded directory and
reports profile names plus health listener endpoints. Other profile fields, including
credentials and headers, are never emitted.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
from typing import Any, Iterable


DEFAULT_PROFILE_DIR = Path.home() / ".config" / "tunnel-client"
CANONICAL_LISTENERS = {
    "grabowski": "127.0.0.1:18080",
    "heim-pc-dashboard": "127.0.0.1:18081",
    "grabowski-johannes": "127.0.0.1:18083",
}
PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
HEALTH_HEADER_RE = re.compile(r"^health:\s*(?:#.*)?(?:\r?\n)?\Z")
LISTEN_LINE_RE = re.compile(
    r"^(?P<indent> +)listen_addr\s*:\s*(?P<value>[^#\r\n]*?)"
    r"(?:\s+#.*)?(?P<newline>\r?\n)?\Z"
)


class TunnelProfileError(RuntimeError):
    """Fail-closed profile diagnostic or repair error."""


@dataclass(frozen=True, order=True)
class ProfileListener:
    profile: str
    listen_addr: str


def normalize_listen_addr(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TunnelProfileError("health.listen_addr must be a non-empty string")
    candidate = value.strip()
    if candidate.startswith("["):
        close = candidate.find("]")
        if close < 0 or close + 1 >= len(candidate) or candidate[close + 1] != ":":
            raise TunnelProfileError("health.listen_addr must use [IPv6]:port")
        host = candidate[1:close]
        port_text = candidate[close + 2 :]
    else:
        if candidate.count(":") != 1:
            raise TunnelProfileError(
                "health.listen_addr must use IPv4:port or [IPv6]:port"
            )
        host, port_text = candidate.rsplit(":", 1)
    try:
        address = ipaddress.ip_address(host)
        port = int(port_text, 10)
    except (ValueError, TypeError) as exc:
        raise TunnelProfileError(
            "health.listen_addr contains an invalid IP address or port"
        ) from exc
    if not 1 <= port <= 65535:
        raise TunnelProfileError("health.listen_addr port must be between 1 and 65535")
    rendered_host = (
        f"[{address.compressed}]" if address.version == 6 else address.compressed
    )
    return f"{rendered_host}:{port}"


def _profile_path(profile_dir: Path, profile: str) -> Path:
    if PROFILE_NAME_RE.fullmatch(profile) is None:
        raise TunnelProfileError("profile name contains unsupported characters")
    return profile_dir / f"{profile}.yaml"


def _safe_profile_files(profile_dir: Path) -> list[Path]:
    if profile_dir.is_symlink() or not profile_dir.is_dir():
        raise TunnelProfileError(f"unsafe or missing profile directory: {profile_dir}")
    files: list[Path] = []
    for path in sorted(profile_dir.glob("*.yaml")):
        if path.is_symlink() or not path.is_file():
            raise TunnelProfileError(f"unsafe profile entry: {path.name}")
        files.append(path)
    return files


def _health_listener_match(text: str) -> tuple[int, re.Match[str]]:
    lines = text.splitlines(keepends=True)
    health_indexes = [
        index for index, line in enumerate(lines) if HEALTH_HEADER_RE.fullmatch(line)
    ]
    if len(health_indexes) != 1:
        raise TunnelProfileError(
            "profile must contain exactly one top-level health mapping"
        )
    start = health_indexes[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        line = lines[index]
        if line.strip() and not line.startswith((" ", "\t", "#")):
            end = index
            break
    matches: list[tuple[int, re.Match[str]]] = []
    for index in range(start, end):
        match = LISTEN_LINE_RE.fullmatch(lines[index])
        if match is not None:
            matches.append((index, match))
    if len(matches) != 1:
        raise TunnelProfileError(
            "health mapping must contain exactly one indented listen_addr line"
        )
    return matches[0]


def _extract_health_listener(text: str) -> str:
    _index, match = _health_listener_match(text)
    value = match.group("value").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    if not value or any(character in value for character in {"\n", "\r", "\x00"}):
        raise TunnelProfileError("health.listen_addr scalar is invalid")
    return normalize_listen_addr(value)


def _load_profile_text(path: Path) -> tuple[str, str, os.stat_result]:
    if path.is_symlink() or not path.is_file():
        raise TunnelProfileError(f"unsafe profile file: {path.name}")
    before = path.stat(follow_symlinks=False)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise TunnelProfileError(f"cannot load profile: {path.name}") from exc
    after = path.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise TunnelProfileError(f"profile changed while being read: {path.name}")
    return text, _extract_health_listener(text), after


def load_profile_listeners(profile_dir: Path) -> list[ProfileListener]:
    listeners: list[ProfileListener] = []
    for path in _safe_profile_files(profile_dir):
        _text, listen_addr, _metadata = _load_profile_text(path)
        listeners.append(ProfileListener(profile=path.stem, listen_addr=listen_addr))
    return sorted(listeners)


def diagnose(profile_dir: Path) -> dict[str, Any]:
    listeners = load_profile_listeners(profile_dir)
    by_endpoint: dict[str, list[str]] = {}
    for item in listeners:
        by_endpoint.setdefault(item.listen_addr, []).append(item.profile)
    duplicates = [
        {"listen_addr": endpoint, "profiles": sorted(profiles)}
        for endpoint, profiles in sorted(by_endpoint.items())
        if len(profiles) > 1
    ]
    mismatches = [
        {
            "profile": item.profile,
            "actual": item.listen_addr,
            "expected": CANONICAL_LISTENERS[item.profile],
        }
        for item in listeners
        if item.profile in CANONICAL_LISTENERS
        and item.listen_addr != CANONICAL_LISTENERS[item.profile]
    ]
    missing_known_profiles = sorted(
        set(CANONICAL_LISTENERS) - {item.profile for item in listeners}
    )
    status = "pass" if not duplicates and not mismatches else "fail"
    return {
        "schema_version": 1,
        "kind": "heim_pc_tunnel_profile_diagnostics",
        "status": status,
        "profiles": [
            {"profile": item.profile, "listen_addr": item.listen_addr}
            for item in listeners
        ],
        "duplicates": duplicates,
        "canonical_mismatches": mismatches,
        "missing_known_profiles": missing_known_profiles,
    }


def _socket_target(listen_addr: str) -> tuple[int, tuple[Any, ...]]:
    normalized = normalize_listen_addr(listen_addr)
    if normalized.startswith("["):
        close = normalized.index("]")
        return socket.AF_INET6, (
            normalized[1:close],
            int(normalized[close + 2 :]),
            0,
            0,
        )
    host, port_text = normalized.rsplit(":", 1)
    return socket.AF_INET, (host, int(port_text))


def endpoint_is_available(listen_addr: str) -> bool:
    family, target = _socket_target(listen_addr)
    probe = socket.socket(family, socket.SOCK_STREAM)
    try:
        probe.bind(target)
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _replace_health_listener(text: str, new_listen_addr: str) -> str:
    lines = text.splitlines(keepends=True)
    index, match = _health_listener_match(text)
    newline = match.group("newline") or ("\n" if text.endswith("\n") else "")
    lines[index] = f'{match.group("indent")}listen_addr: "{new_listen_addr}"{newline}'
    return "".join(lines)


def _atomic_replace(
    path: Path, original: bytes, replacement: bytes, metadata: os.stat_result
) -> None:
    if path.is_symlink() or not path.is_file():
        raise TunnelProfileError(f"unsafe profile file before write: {path.name}")
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise TunnelProfileError(
            f"cannot re-read profile before write: {path.name}"
        ) from exc
    if hashlib.sha256(current).digest() != hashlib.sha256(original).digest():
        raise TunnelProfileError(f"profile changed before write: {path.name}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        try:
            os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
        except PermissionError:
            pass
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(replacement)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink() or not path.is_file():
            raise TunnelProfileError(f"unsafe profile file at commit: {path.name}")
        if (
            hashlib.sha256(path.read_bytes()).digest()
            != hashlib.sha256(original).digest()
        ):
            raise TunnelProfileError(f"profile changed at commit: {path.name}")
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def repair_profile(
    profile_dir: Path,
    *,
    profile: str,
    expected_current: str,
    new_listen_addr: str,
) -> dict[str, Any]:
    expected = normalize_listen_addr(expected_current)
    desired = normalize_listen_addr(new_listen_addr)
    canonical = CANONICAL_LISTENERS.get(profile)
    if canonical is not None and desired != canonical:
        raise TunnelProfileError(
            f"requested listener does not match the canonical assignment for {profile}"
        )
    listeners = load_profile_listeners(profile_dir)
    current_by_profile = {item.profile: item.listen_addr for item in listeners}
    current = current_by_profile.get(profile)
    if current is None:
        raise TunnelProfileError(f"profile not found: {profile}")
    if current != expected:
        raise TunnelProfileError(f"profile listener changed since preflight: {profile}")
    conflicts = sorted(
        item.profile
        for item in listeners
        if item.profile != profile and item.listen_addr == desired
    )
    if conflicts:
        raise TunnelProfileError(
            f"requested listener is assigned to another profile: {','.join(conflicts)}"
        )
    if current == desired:
        return {
            "schema_version": 1,
            "kind": "heim_pc_tunnel_profile_repair",
            "status": "unchanged",
            "profile": profile,
            "listen_addr": desired,
        }
    if not endpoint_is_available(desired):
        raise TunnelProfileError("requested listener is already in use")
    path = _profile_path(profile_dir, profile)
    text, parsed_current, metadata = _load_profile_text(path)
    if parsed_current != current:
        raise TunnelProfileError(f"profile listener changed before write: {profile}")
    replacement_text = _replace_health_listener(text, desired)
    if _extract_health_listener(replacement_text) != desired:
        raise TunnelProfileError(
            "generated profile does not contain the requested listener"
        )
    _atomic_replace(
        path, text.encode("utf-8"), replacement_text.encode("utf-8"), metadata
    )
    _readback_text, readback_listener, _readback_metadata = _load_profile_text(path)
    if readback_listener != desired:
        raise TunnelProfileError("profile repair readback failed")
    return {
        "schema_version": 1,
        "kind": "heim_pc_tunnel_profile_repair",
        "status": "repaired",
        "profile": profile,
        "previous_listen_addr": current,
        "listen_addr": desired,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Diagnose duplicate tunnel-client health listeners without exposing secrets."
    )
    parser.add_argument("--profile-dir", type=Path, default=DEFAULT_PROFILE_DIR)
    parser.add_argument("--repair-profile")
    parser.add_argument("--expected-current")
    parser.add_argument("--listen-addr")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    repair_requested = any(
        value is not None
        for value in (args.repair_profile, args.expected_current, args.listen_addr)
    )
    try:
        if repair_requested:
            if not all(
                value is not None
                for value in (
                    args.repair_profile,
                    args.expected_current,
                    args.listen_addr,
                )
            ):
                raise TunnelProfileError(
                    "repair requires --repair-profile, --expected-current and --listen-addr"
                )
            result = repair_profile(
                args.profile_dir,
                profile=args.repair_profile,
                expected_current=args.expected_current,
                new_listen_addr=args.listen_addr,
            )
            exit_code = 0
        else:
            result = diagnose(args.profile_dir)
            exit_code = 0 if result["status"] == "pass" else 1
    except TunnelProfileError as exc:
        result = {
            "schema_version": 1,
            "kind": "heim_pc_tunnel_profile_diagnostics_error",
            "status": "error",
            "error": str(exc),
        }
        exit_code = 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
