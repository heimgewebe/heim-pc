"""Offline contract for Nabu's private locally installed ChatGPT sender."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "nabu" / "setup_chatgpt_sender.py"
spec = importlib.util.spec_from_file_location("nabu_sender_setup", SOURCE)
assert spec is not None and spec.loader is not None
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class NabuChatGPTSenderSetupTests(unittest.TestCase):
    def test_install_reuses_key_and_installs_only_one_origin(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "private" / "key"
            directory = Path(folder) / "extension"
            with mock.patch.object(setup, "KEY_PATH", key), \
                 mock.patch.object(setup, "EXTENSION_DIR", directory), \
                 mock.patch.object(setup, "NATIVE_HOST_MANIFEST", Path(folder) / "native" / "host.json"):
                result = setup.install()
                private = key.read_text().strip()
                self.assertEqual(len(private), 64)
                self.assertFalse(key.stat().st_mode & 0o077)
                content = (directory / "content.js").read_text()
                self.assertIn(private, content)
                background = (directory / "background.js").read_text()
                self.assertIn("nabu-signed-send-claim-v1", background)
                self.assertNotIn(private, background)
                self.assertIn('"service_worker": "background.js"',
                              (directory / "manifest.json").read_text())
                self.assertNotIn(setup.MARKER, content)
                self.assertNotIn(private, str(result))
                self.assertTrue(result["chrome_activation_required"])
                self.assertFalse(result["chatgpt_send_verified"])
                self.assertEqual(result["extension_directory"], str(directory))
                self.assertTrue(result["native_receipt_host_installed"])
                native = json.loads(setup.NATIVE_HOST_MANIFEST.read_text())
                self.assertEqual(native["type"], "stdio")
                self.assertEqual(native["path"], str(directory / "receipt_host.py"))
                self.assertEqual(len(native["allowed_origins"]), 1)
                self.assertRegex(native["allowed_origins"][0], r"^chrome-extension://[a-p]{32}/$")
                self.assertEqual((directory / "receipt_host.py").stat().st_mode & 0o777, 0o700)
                manifest = json.loads((directory / "manifest.json").read_text())
                self.assertEqual(manifest["permissions"], ["storage", "nativeMessaging"])
                receipt_path = key.parent / ".nabu-chatgpt-send-receipts.json"
                self.assertEqual(json.loads(receipt_path.read_text()), {})
                receipt_path.write_text('{"example":"existing"}')
                second = setup.install()
                self.assertEqual(json.loads(receipt_path.read_text()), {"example": "existing"})
                self.assertEqual(key.read_text().strip(), private)
                self.assertEqual(result["content_sha256"], second["content_sha256"])
                self.assertIn('"https://chatgpt.com/*"',
                              (directory / "manifest.json").read_text())

    def test_invalid_key_does_not_get_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "key"
            key.write_text("bad\n")
            directory = Path(folder) / "extension"
            with mock.patch.object(setup, "KEY_PATH", key), \
                 mock.patch.object(setup, "EXTENSION_DIR", directory), \
                 mock.patch.object(setup, "NATIVE_HOST_MANIFEST", Path(folder) / "native" / "host.json"):
                with self.assertRaises(RuntimeError):
                    setup.install()
                self.assertEqual(key.read_text(), "bad\n")


if __name__ == "__main__":
    unittest.main()
