import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "manifest" / "mobile-transfer-targets.v1.json"


class MobileTransferTargetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text())

    def test_contract_identity_and_freshness_boundary(self):
        self.assertEqual(self.contract["schemaVersion"], 1)
        self.assertEqual(self.contract["kind"], "heim_pc_mobile_transfer_targets")
        self.assertTrue(self.contract["availabilityRequiresFreshRead"])
        self.assertIn("target_online_now", self.contract["doesNotEstablish"])

    def test_ipad_and_a54_are_distinct_mobile_targets(self):
        targets = {item["id"]: item for item in self.contract["targets"]}
        self.assertEqual(set(targets), {"ipad", "a54"})
        self.assertEqual(targets["ipad"]["taildropTarget"], "ipad-10th-gen-wifi")
        self.assertEqual(targets["a54"]["taildropTarget"], "a54-von-alexander")
        self.assertIn("remote_primary", targets["ipad"]["roles"])
        self.assertIn("remote_fallback", targets["a54"]["roles"])
        self.assertEqual(targets["a54"]["transports"], ["tailscale_taildrop"])

    def test_routing_distinguishes_shared_exchange_from_direct_delivery(self):
        routing = self.contract["routing"]
        self.assertEqual(routing["sharedPersistentWorkspace"]["eligibleTargets"], ["ipad"])
        direct = routing["directOneShotDelivery"]
        self.assertEqual(direct["eligibleTargets"], ["ipad", "a54"])
        self.assertEqual(direct["remoteFallbackOrder"], ["ipad", "a54"])
        self.assertEqual(direct["heimPcInbox"], "${HOME}/Incoming/Taildrop")

    def test_all_routing_targets_exist(self):
        target_ids = {item["id"] for item in self.contract["targets"]}
        for route in self.contract["routing"].values():
            self.assertTrue(set(route["eligibleTargets"]).issubset(target_ids))


if __name__ == "__main__":
    unittest.main()
