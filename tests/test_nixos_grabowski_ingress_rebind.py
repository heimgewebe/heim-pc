"""Regression: a native NixOS Grabowski switch must rebind the existing MCP ingress."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "nixos/system/modules"
SCRIPT = MODULES / "grabowski-ingress-rebind.py"
PACKAGE = MODULES / "grabowski-operator-package.nix"
PRODUCTION = MODULES / "grabowski-production.nix"


def _script():
    spec = importlib.util.spec_from_file_location("nixos_grabowski_ingress_rebind", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("NixOS ingress rebind script is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionSourceTests(unittest.TestCase):
    def test_use_existing_versioned_cas_publisher_not_new_daemon(self):
        package = PACKAGE.read_text()
        production = PRODUCTION.read_text()
        self.assertIn("extracted/tools/grabowski_transport_ingress.py", package)
        self.assertIn("grabowski_transport_ingress.py", package)
        self.assertIn("ExecStartPost =", production)
        self.assertIn("grabowski-ingress-rebind.py", production)
        self.assertIn("nixos-integrity-manifest.json", production)
        self.assertIn("systemd.services.grabowski-operator", production)


class RebindTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = self.root / "nixos-integrity-manifest.json"
        self.selector = self.root / "operator-routing-selector.json"
        self.release = "57f3310ff63c-srcsetc54299092f97-lock264e747ad05a-contract650f923c4cfb"
        self.head = "57f3310ff63cc3218def6da0b424c8390f1dd5f9"
        self.agent_sha = "6235fde59895c8add3590115f5d94b8dd8f432e2fef5645d4461691822c97142"
        self.tools = ["z_tool", "a_tool", "m_tool"]
        self.manifest.write_text(json.dumps({
            "release_id": self.release,
            "repo_head": self.head,
            "agent_instructions_sha256": self.agent_sha,
            "entrypoint_contract": {"expected_tools": self.tools}
        }))
        self.module = _script()

    def _expected(self):
        return {
            "release_id": self.release,
            "repo_head": self.head,
            "registered_names_sha256": hashlib.sha256(
                json.dumps(sorted(self.tools), separators=(",", ":")).encode()
            ).hexdigest(),
            "agent_instructions_sha256": self.agent_sha,
        }

    class FakeIngress:
        def __init__(self, selector):
            self.selector = selector
            self.calls = []

        def read_routing_selector(self, path):
            return dict(self.selector)

        def publish_routing_selector(self, **kwargs):
            self.calls.append(kwargs)
            return {
                "selected_slot": kwargs["selected_slot"],
                "runtime_binding": kwargs["runtime_binding"],
                "selector_sha256": "f" * 64,
            }

    def test_missing_ingress_selector_does_not_block_first_boot(self):
        fake = self.FakeIngress(None)
        result = self.module.reconcile(self.manifest, self.selector, fake)
        self.assertEqual("ingress_not_configured", result["status"])
        self.assertEqual([], fake.calls)

    def test_matching_runtime_never_republishes(self):
        self.selector.write_text("test")
        fake = self.FakeIngress({
            "selected_slot": "canonical", "runtime_binding": self._expected(),
            "selector_sha256": "a" * 64,
        })
        result = self.module.reconcile(self.manifest, self.selector, fake)
        self.assertEqual("already_bound", result["status"])
        self.assertEqual([], fake.calls)

    def test_old_runtime_is_rebound_using_exact_cas_to_current_nix_manifest(self):
        self.selector.write_text("test")
        fake = self.FakeIngress({
            "selected_slot": "canonical",
            "runtime_binding": {"release_id": "old"},
            "selector_sha256": "a" * 64,
        })
        result = self.module.reconcile(self.manifest, self.selector, fake)
        self.assertEqual("rebound", result["status"])
        self.assertEqual(1, len(fake.calls))
        call = fake.calls[0]
        self.assertEqual(self.selector, call["path"])
        self.assertEqual("a" * 64, call["expected_selector_sha256"])
        self.assertEqual("canonical", call["selected_slot"])
        self.assertEqual(self._expected(), call["runtime_binding"])
        self.assertIn(self.head[:12], call["cutover_id"])

    def test_existing_green_cutover_is_never_hijacked(self):
        self.selector.write_text("test")
        fake = self.FakeIngress({
            "selected_slot": "green", "runtime_binding": {"release_id": "old"},
            "selector_sha256": "a" * 64,
        })
        self.assertEqual(
            "noncanonical_route",
            self.module.reconcile(self.manifest, self.selector, fake)["status"],
        )
        self.assertEqual([], fake.calls)

    def test_corrupt_or_ambiguous_tool_catalog_is_rejected(self):
        self.selector.write_text("test")
        fake = self.FakeIngress({
            "selected_slot": "canonical", "runtime_binding": {"release_id": "old"},
            "selector_sha256": "a" * 64,
        })
        for tools in ([], ["duplicate", "duplicate"], ["ok", 1]):
            with self.subTest(tools=tools):
                data = json.loads(self.manifest.read_text())
                data["entrypoint_contract"]["expected_tools"] = tools
                self.manifest.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    self.module.reconcile(self.manifest, self.selector, fake)
        self.assertEqual([], fake.calls)

    def test_cas_conflict_is_propagated_not_mislabeled_as_success(self):
        self.selector.write_text("test")
        class Race(self.FakeIngress):
            def publish_routing_selector(self, **kwargs):
                raise RuntimeError("routing selector CAS precondition failed")
        fake = Race({
            "selected_slot": "canonical", "runtime_binding": {"release_id": "old"},
            "selector_sha256": "a" * 64,
        })
        with self.assertRaisesRegex(RuntimeError, "CAS precondition"):
            self.module.reconcile(self.manifest, self.selector, fake)


if __name__ == "__main__":
    unittest.main()
