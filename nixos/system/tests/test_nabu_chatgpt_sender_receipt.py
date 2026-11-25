"""Offline native-message framing and bounded content-free receipt persistence."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "nabu" / "chatgpt_sender_receipt.py"
spec = importlib.util.spec_from_file_location("nabu_receipt_host", SOURCE)
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class ReceiptHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "receipts.json"
        self.nonce = "ab" * 12
        self.now = 1795425000

    def record(self, stage, nonce=None, now=None):
        return host.record_receipt(self.path, {"nonce": nonce or self.nonce, "stage": stage},
                                   now=self.now if now is None else now)

    def test_exact_nonce_monotonic_confirmed_status_and_private_file(self):
        self.record("click_attempted")
        self.record("send_unconfirmed", now=self.now + 1)
        self.record("message_verified", now=self.now + 2)
        self.record("claim_denied", now=self.now + 3)
        self.assertEqual(json.loads(self.path.read_text()), {
            self.nonce: {"stage": "message_verified", "at": self.now + 2}})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_prune_stale_and_keep_bounded_records(self):
        self.record("message_sent", now=self.now - 3601)
        for i in range(65):
            self.record("message_sent", nonce=f"{i:024x}")
        data = json.loads(self.path.read_text())
        self.assertEqual(len(data), 64)
        self.assertNotIn(self.nonce, data)
        self.assertIn(f"{64:024x}", data)

    def test_reject_extra_fields_and_unknown_stage_without_write(self):
        for value in ({"nonce": self.nonce, "stage": "message_sent", "prompt": "secret"},
                      {"nonce": "../outside", "stage": "message_sent"},
                      {"nonce": self.nonce, "stage": "command"},
                      {"nonce": self.nonce, "stage": []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                host.record_receipt(self.path, value, now=self.now)
        self.assertFalse(self.path.exists())

    def test_native_message_framing(self):
        payload = json.dumps({"nonce": self.nonce, "stage": "message_sent"}).encode()
        output = io.BytesIO()
        self.assertEqual(host.serve(io.BytesIO(struct.pack("=I", len(payload)) + payload),
                                    output, self.path), 0)
        result = output.getvalue()
        self.assertEqual(struct.unpack("=I", result[:4])[0], len(result[4:]))
        self.assertEqual(json.loads(result[4:]), {"recorded": True})
        self.assertEqual(json.loads(self.path.read_text())[self.nonce]["stage"], "message_sent")

    def test_malformed_frames_have_no_effect(self):
        for data in (b"", b"abc", struct.pack("=I", 1025), struct.pack("=I", 10) + b"x"):
            self.assertEqual(host.serve(io.BytesIO(data), io.BytesIO(), self.path), 2)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
