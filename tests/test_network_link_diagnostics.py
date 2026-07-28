from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "network_link_diagnostics",
    ROOT / "scripts" / "network_link_diagnostics.py",
)
assert SPEC and SPEC.loader
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


ETHTOOL_100 = """Settings for enp6s0:
\tSupported link modes:   10baseT/Half 10baseT/Full
\t                        100baseT/Half 100baseT/Full
\t                        1000baseT/Full
\t                        2500baseT/Full
\tAdvertised link modes:  10baseT/Half 10baseT/Full
\t                        100baseT/Half 100baseT/Full
\t                        1000baseT/Full
\t                        2500baseT/Full
\tSpeed: 100Mb/s
\tDuplex: Full
\tPort: Twisted Pair
\tAuto-negotiation: on
\tLink detected: yes
"""


class NetworkLinkDiagnosticsTests(unittest.TestCase):
    def test_default_route_selects_lowest_metric_gateway_route(self) -> None:
        route_data = """Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
other0 00000000 0100000A 0003 0 0 500 00000000 0 0 0
enp6s0 00000000 01B2A8C0 0003 0 0 100 00000000 0 0 0
"""
        self.assertEqual(diagnostics.default_route_interface(route_data), "enp6s0")

    def test_default_route_requires_active_gateway(self) -> None:
        route_data = """Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
enp6s0 00000000 00000000 0001 0 0 100 00000000 0 0 0
"""
        with self.assertRaisesRegex(diagnostics.DiagnosticError, "no active"):
            diagnostics.default_route_interface(route_data)

    def test_ethtool_parser_extracts_negotiation_contract(self) -> None:
        parsed = diagnostics.parse_ethtool(ETHTOOL_100)
        self.assertEqual(parsed["maximum_supported_mbps"], 2500)
        self.assertEqual(parsed["maximum_advertised_mbps"], 2500)
        self.assertEqual(parsed["negotiated_speed_mbps"], 100)
        self.assertEqual(parsed["duplex"], "Full")
        self.assertEqual(parsed["auto_negotiation"], "on")
        self.assertEqual(parsed["link_detected"], "yes")

    def test_slow_link_with_high_local_advertisement_points_outward(self) -> None:
        evidence = diagnostics.parse_ethtool(ETHTOOL_100)
        assessment = diagnostics.classify(
            interface="enp6s0",
            expected_interface="enp6s0",
            minimum_mbps=1000,
            evidence=evidence,
        )
        self.assertEqual(assessment["status"], "degraded")
        self.assertIn("negotiated_speed_below_policy", assessment["issues"])
        self.assertEqual(
            assessment["likely_fault_domain"],
            "physical_medium_or_link_partner",
        )

    def test_unexpected_interface_keeps_fault_local_or_unresolved(self) -> None:
        evidence = diagnostics.parse_ethtool(ETHTOOL_100)
        assessment = diagnostics.classify(
            interface="enp7s0",
            expected_interface="enp6s0",
            minimum_mbps=1000,
            evidence=evidence,
        )
        self.assertIn("unexpected_default_interface", assessment["issues"])
        self.assertIn("negotiated_speed_below_policy", assessment["issues"])
        self.assertEqual(assessment["likely_fault_domain"], "local_configuration_or_unresolved")

    def test_healthy_link_passes_without_fault_domain(self) -> None:
        evidence = diagnostics.parse_ethtool(ETHTOOL_100.replace("100Mb/s", "2500Mb/s"))
        assessment = diagnostics.classify(
            interface="enp6s0",
            expected_interface="enp6s0",
            minimum_mbps=1000,
            evidence=evidence,
        )
        self.assertEqual(assessment["status"], "healthy")
        self.assertEqual(assessment["issues"], [])
        self.assertIsNone(assessment["likely_fault_domain"])

    def test_disabled_autoneg_is_classified_as_local_or_unresolved(self) -> None:
        evidence = diagnostics.parse_ethtool(ETHTOOL_100.replace("Auto-negotiation: on", "Auto-negotiation: off"))
        assessment = diagnostics.classify(
            interface="enp6s0",
            expected_interface="enp6s0",
            minimum_mbps=1000,
            evidence=evidence,
        )
        self.assertIn("auto_negotiation_disabled", assessment["issues"])
        self.assertEqual(
            assessment["likely_fault_domain"],
            "local_configuration_or_unresolved",
        )


if __name__ == "__main__":
    unittest.main()
