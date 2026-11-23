"""Exercise the real Chrome content script with a fake composer, without ChatGPT access."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import shutil
import subprocess
import time
import unittest
from urllib.parse import quote


SOURCE = Path(__file__).resolve().parents[1] / "nabu" / "chatgpt_sender.content.js.in"
BACKGROUND = SOURCE.with_name("chatgpt_sender.background.js")
NODE = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const {webcrypto} = require("node:crypto");
const data = JSON.parse(fs.readFileSync(0, "utf8"));
const url = new URL(data.url);
const stored = {};
let backgroundListener;
const backgroundChrome = {
  runtime: { onMessage: { addListener(fn) { backgroundListener = fn; } } },
  storage: { local: {
    async get(key) { return {[key]: stored[key]}; },
    async set(values) {
      if (data.storageFailure) throw new Error("storage failed");
      Object.assign(stored, values);
    }
  } }
};
vm.runInNewContext(data.background, {chrome: backgroundChrome, Date, URL});
function openTab() {
  const draft = {
    value: data.composer,
    getClientRects() { return [{}]; }
  };
  let clicks = 0;
  let cleaned = "";
  const send = {
    disabled: false,
    getAttribute(name) { return name === "aria-label" ? "Nachricht senden" : null; },
    getClientRects() { return [{}]; },
    click() { clicks++; }
  };
  const context = {
    location: {origin: "https://chatgpt.com", search: url.search, href: url.href},
    URL, URLSearchParams, TextEncoder, crypto: webcrypto, Date,
    chrome: { runtime: {
      sendMessage(message) {
        return new Promise(resolve => {
          if (!backgroundListener(message, {url: url.href}, resolve)) {
            resolve({granted: false});
          }
        });
      }
    } },
    document: {
      documentElement: {},
      querySelectorAll(selector) {
        return selector === "button" ? [send] : [draft];
      }
    },
    history: {state: null, replaceState(_state, _title, path) { cleaned = path; }},
    MutationObserver: class { observe() {} disconnect() {} },
    setTimeout(_fn, _ms) {}
  };
  vm.runInNewContext(data.script, context);
  return {get clicks() {return clicks;}, get cleaned() {return cleaned;}};
}
// Distinct JS contexts, with no shared tab memory, claim the same signed URL.
const tabs = Array.from({length: data.tabs || 1}, () => openTab());
setTimeout(() => {
  console.log(JSON.stringify({
    clicks: tabs.reduce((n, tab) => n + tab.clicks, 0),
    perTabClicks: tabs.map(tab => tab.clicks),
    marked: Object.keys(stored.nabu_consumed_nonces_v1 || {}).length,
    cleaned: tabs.map(tab => tab.cleaned)
  }));
}, 250);
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required for Chrome-script simulation")
class NabuChromeSendContentTests(unittest.TestCase):
    def send_once(self, *, tamper=False, age=0, signed=True, tabs=1, storage_failure=False):
        key = bytes.fromhex("ab" * 32)
        prompt = "Nabu-Sendetest ohne Werkzeuge"
        ts = int(time.time()) - age
        nonce = "cd" * 12
        message = f"nabu-send-v1\n{ts}\n{nonce}\n{prompt}".encode()
        signature = hmac.new(key, message, hashlib.sha256).hexdigest()
        url = "https://chatgpt.com/?prompt=" + quote(
            "Nabu-anderer-Test" if tamper else prompt, safe=""
        )
        if signed:
            url += f"&nabu_ts={ts}&nabu_nonce={nonce}&nabu_sig={signature}"
        script = SOURCE.read_text().replace("__NABU_SEND_SECRET_HEX__", key.hex())
        proc = subprocess.run(
            ["node", "-e", NODE],
            input=json.dumps({"url": url, "composer": prompt if not tamper else "Nabu-anderer-Test",
                              "script": script, "background": BACKGROUND.read_text(),
                              "tabs": tabs, "storageFailure": storage_failure}),
            capture_output=True, text=True, timeout=10, check=True,
        )
        return json.loads(proc.stdout)

    def test_signed_fresh_text_gets_one_click(self):
        result = self.send_once()
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["marked"], 1)
        self.assertEqual(result["cleaned"], ["/"])

    def test_same_signed_request_in_two_tabs_claims_at_most_once(self):
        result = self.send_once(tabs=2)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["marked"], 1)
        self.assertEqual(sorted(result["perTabClicks"]), [0, 1])

    def test_storage_failure_fails_closed(self):
        result = self.send_once(storage_failure=True)
        self.assertEqual(result["clicks"], 0)
        self.assertEqual(result["marked"], 0)

    def test_tampered_expired_or_unsigned_link_cannot_click(self):
        for kwargs in ({"tamper": True}, {"age": 400}, {"signed": False}):
            with self.subTest(kwargs=kwargs):
                result = self.send_once(**kwargs)
                self.assertEqual(result["clicks"], 0)
                self.assertEqual(result["marked"], 0)


if __name__ == "__main__":
    unittest.main()