#!/usr/bin/env python3
"""Report bounded default-route Ethernet negotiation evidence without changing the link."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config/network-identity.v1.json"
PROC_ROUTE = Path("/proc/net/route")
SYS_CLASS_NET = Path("/sys/class/net")
SPEED_RE = re.compile(r"^(\d+)(?:baseT)/(?:Half|Full)$")


class DiagnosticError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise DiagnosticError(f"cannot load network policy: {exc}") from exc
    if not isinstance(value, dict):
        raise DiagnosticError("network policy must be an object")
    if value.get("schema_version") != 1 or value.get("kind") != "heim_pc_network_identity_policy":
        raise DiagnosticError("unsupported network policy identity")
    interface = value.get("expected_default_interface")
    minimum = value.get("minimum_link_speed_mbps")
    if not isinstance(interface, str) or not interface:
        raise DiagnosticError("network policy expected_default_interface is invalid")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 100:
        raise DiagnosticError("network policy minimum_link_speed_mbps is invalid")
    return {
        "raw_sha256": sha256(raw),
        "expected_default_interface": interface,
        "minimum_link_speed_mbps": minimum,
    }


def default_route_interface(route_data: str) -> str:
    lines = route_data.splitlines()
    if not lines:
        raise DiagnosticError("route table is empty")
    candidates: list[tuple[int, str]] = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8 or fields[1] != "00000000" or fields[7] != "00000000":
            continue
        try:
            flags = int(fields[3], 16)
            metric = int(fields[6])
        except ValueError as exc:
            raise DiagnosticError("route table contains invalid numeric fields") from exc
        if flags & 0x1 and flags & 0x2:
            candidates.append((metric, fields[0]))
    if not candidates:
        raise DiagnosticError("no active IPv4 default route found")
    candidates.sort()
    return candidates[0][1]


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def read_int(path: Path) -> int | None:
    value = read_text(path)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def ethtool_output(interface: str) -> str:
    completed = subprocess.run(
        ["ethtool", interface],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise DiagnosticError(f"ethtool failed for {interface}: {detail[:500]}")
    return completed.stdout


def parse_ethtool(text: str) -> dict[str, Any]:
    supported: list[str] = []
    advertised: list[str] = []
    section: str | None = None
    scalars: dict[str, str] = {}
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("Supported link modes:"):
            section = "supported"
            remainder = stripped.split(":", 1)[1].strip()
            if remainder:
                supported.extend(remainder.split())
            continue
        if stripped.startswith("Advertised link modes:"):
            section = "advertised"
            remainder = stripped.split(":", 1)[1].strip()
            if remainder:
                advertised.extend(remainder.split())
            continue
        if raw_line.startswith("\t                        ") and section:
            tokens = stripped.split()
            if tokens and all("baseT" in token for token in tokens):
                (supported if section == "supported" else advertised).extend(tokens)
                continue
        section = None
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            scalars[key] = value.strip()
    def maximum(modes: list[str]) -> int | None:
        speeds = [int(match.group(1)) for mode in modes if (match := SPEED_RE.fullmatch(mode))]
        return max(speeds) if speeds else None
    speed_text = scalars.get("Speed")
    negotiated = None
    if speed_text and speed_text.endswith("Mb/s"):
        try:
            negotiated = int(speed_text.removesuffix("Mb/s"))
        except ValueError:
            negotiated = None
    return {
        "supported_link_modes": supported,
        "advertised_link_modes": advertised,
        "maximum_supported_mbps": maximum(supported),
        "maximum_advertised_mbps": maximum(advertised),
        "negotiated_speed_mbps": negotiated,
        "duplex": scalars.get("Duplex"),
        "auto_negotiation": scalars.get("Auto-negotiation"),
        "link_detected": scalars.get("Link detected"),
        "port": scalars.get("Port"),
    }


def classify(
    *,
    interface: str,
    expected_interface: str,
    minimum_mbps: int,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    speed = evidence.get("negotiated_speed_mbps")
    advertised = evidence.get("maximum_advertised_mbps")
    autoneg = evidence.get("auto_negotiation")
    link = evidence.get("link_detected")
    issues: list[str] = []
    if interface != expected_interface:
        issues.append("unexpected_default_interface")
    if link != "yes":
        issues.append("link_not_detected")
    if speed is None:
        issues.append("negotiated_speed_unknown")
    elif speed < minimum_mbps:
        issues.append("negotiated_speed_below_policy")
    if autoneg != "on":
        issues.append("auto_negotiation_disabled")
    if advertised is None:
        issues.append("advertised_speed_unknown")
    elif advertised < minimum_mbps:
        issues.append("local_adapter_not_advertising_policy_speed")
    if not issues:
        status = "healthy"
        likely_fault_domain = None
    elif (
        "negotiated_speed_below_policy" in issues
        and autoneg == "on"
        and isinstance(advertised, int)
        and advertised >= minimum_mbps
        and link == "yes"
    ):
        status = "degraded"
        likely_fault_domain = "physical_medium_or_link_partner"
    else:
        status = "degraded"
        likely_fault_domain = "local_configuration_or_unresolved"
    return {
        "status": status,
        "issues": issues,
        "likely_fault_domain": likely_fault_domain,
    }


def collect(
    *,
    policy_path: Path = POLICY_PATH,
    route_path: Path = PROC_ROUTE,
    sys_class_net: Path = SYS_CLASS_NET,
) -> dict[str, Any]:
    policy = load_policy(policy_path)
    try:
        route_data = route_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DiagnosticError(f"cannot read route table: {exc}") from exc
    interface = default_route_interface(route_data)
    interface_root = sys_class_net / interface
    if interface_root.is_symlink():
        interface_root = interface_root.resolve()
    if not interface_root.exists() or not interface_root.is_dir():
        raise DiagnosticError(f"default interface sysfs path is unavailable: {interface}")
    ethtool = parse_ethtool(ethtool_output(interface))
    counters = {
        name: read_int(interface_root / "statistics" / name)
        for name in (
            "rx_errors",
            "tx_errors",
            "rx_dropped",
            "tx_dropped",
            "rx_crc_errors",
            "rx_missed_errors",
        )
    }
    evidence = {
        **ethtool,
        "carrier": read_int(interface_root / "carrier"),
        "operstate": read_text(interface_root / "operstate"),
        "sysfs_speed_mbps": read_int(interface_root / "speed"),
        "sysfs_duplex": read_text(interface_root / "duplex"),
        "mtu": read_int(interface_root / "mtu"),
        "statistics": counters,
    }
    assessment = classify(
        interface=interface,
        expected_interface=policy["expected_default_interface"],
        minimum_mbps=policy["minimum_link_speed_mbps"],
        evidence=evidence,
    )
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": "heim_pc_network_link_diagnostic",
        "generated_at_unix": int(time.time()),
        "default_interface": interface,
        "policy": policy,
        "evidence": evidence,
        "assessment": assessment,
        "mutations_performed": [],
        "does_not_establish": [
            "exact_faulty_cable_pair",
            "link_partner_port_capability",
            "safe_remote_link_flap",
            "physical_repair_completion",
        ],
    }
    receipt["receipt_sha256"] = sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    try:
        receipt = collect(policy_path=args.policy)
    except (DiagnosticError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(
            json.dumps({"kind": "heim_pc_network_link_diagnostic_error", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    if args.strict and receipt["assessment"]["status"] != "healthy":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
