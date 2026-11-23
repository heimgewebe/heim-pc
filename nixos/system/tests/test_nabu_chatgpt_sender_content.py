"""Exercise the real extension scripts with a changing, simulated composer.

The fixture never accesses ChatGPT, a browser profile, credentials or model output.
"""
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
let installListener;
const backgroundChrome = {
  runtime: {
    onMessage: { addListener(fn) { backgroundListener = fn; } },
    onInstalled: { addListener(fn) { installListener = fn; } },
    getManifest() { return {version: "1.1.0"}; }
  },
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
  const loc = {origin: url.origin, search: url.search, href: url.href};
  let hydrated = !data.delayedHydration;
  let clicks = 0;
  const visible = {getClientRects() {return hydrated ? [{}] : [];}};
  const draft = {
    ...visible,
    value: data.composer
  };
  const send = {
    ...visible,
    disabled: false,
    getAttribute(name) { return name === "aria-label" ? "Nachricht senden" : null; },
    click() { clicks++; }
  };
  const context = {
    location: loc, URL, URLSearchParams, TextEncoder, crypto: webcrypto, Date,
    chrome: { runtime: {
      sendMessage(message) {
        return new Promise(resolve => {
          if (!backgroundListener(message, {url: loc.href, frameId: 0}, resolve)) {
            resolve({granted: false, recorded: false});
          }
        });
      }
    } },
    document: {
      querySelectorAll(selector) {
        if (selector === "button") return data.missingSend ? [] : [send];
        if (selector.includes('data-message-author-role="user"')) {
          return clicks && data.confirm !== false ? [{...visible, innerText: data.composer}] : [];
        }
        if (selector.includes('data-testid="login-button"')) return data.login ? [visible] : [];
        if (selector.includes('data-testid="profile-button"')) return data.account === false ? [] : [visible];
        if (selector.includes("#prompt-textarea")) return data.missingComposer ? [] : [draft];
        return [];
      }
    },
    // Compress bounded polling for the synthetic fixture, not production.
    setTimeout(fn, _ms) {return setTimeout(fn, 1);}
  };
  const finished = vm.runInNewContext(data.script, context);
  if (data.delayedHydration) {
    // The site may remove the query before the composer becomes available.
    loc.search = "";
    loc.href = "https://chatgpt.com/";
    setTimeout(() => {hydrated = true;}, 5);
  }
  return {finished, get clicks() {return clicks;}};
}
const tabs = Array.from({length: data.tabs || 1}, () => openTab());
Promise.all(tabs.map(tab => tab.finished)).then(() => {
  const receipts = Object.values(stored.nabu_send_receipts_v1 || {});
  console.log(JSON.stringify({
    clicks: tabs.reduce((n, tab) => n + tab.clicks, 0),
    perTabClicks: tabs.map(tab => tab.clicks),
    marked: Object.keys(stored.nabu_consumed_nonces_v1 || {}).length,
    stage: receipts[0]?.stage || null,
    noPromptInReceipts: !JSON.stringify(receipts).includes(data.composer)
  }));
}).catch(error => { console.error(error); process.exitCode = 1; });
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required for Chrome-script simulation")
class NabuChromeSendContentTests(unittest.TestCase):
    def send_once(self, *, tamper=False, age=0, signed=True, tabs=1, storage_failure=False,
                  prompt="Nabu-Sendetest ohne Werkzeuge", **fixture):
        key = bytes.fromhex("ab" * 32)
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
        data = {"url": url, "composer": prompt if not tamper else "Nabu-anderer-Test",
                "script": script, "background": BACKGROUND.read_text(),
                "tabs": tabs, "storageFailure": storage_failure}
        data.update(fixture)
        proc = subprocess.run(
            ["node", "-e", NODE], input=json.dumps(data),
            capture_output=True, text=True, timeout=10, check=True,
        )
        return json.loads(proc.stdout)

    def test_signed_fresh_text_gets_one_click_and_own_message_receipt(self):
        result = self.send_once()
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["marked"], 1)
        self.assertEqual(result["stage"], "message_sent")
        self.assertTrue(result["noPromptInReceipts"])

    def test_capture_survives_query_removal_before_composer_hydration(self):
        result = self.send_once(delayedHydration=True)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["stage"], "message_sent")

    def test_no_guest_send_or_unconfirmed_account(self):
        for fixture, expected in (
            ({"login": True}, "timeout_login_required"),
            ({"account": False}, "timeout_account_unconfirmed"),
        ):
            with self.subTest(fixture=fixture):
                result = self.send_once(**fixture)
                self.assertEqual(result["clicks"], 0)
                self.assertEqual(result["marked"], 0)
                self.assertEqual(result["stage"], expected)

    def test_click_without_own_message_is_not_reported_as_sent(self):
        result = self.send_once(confirm=False)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["stage"], "send_unconfirmed")

    def test_missing_or_different_composer_and_button_are_diagnosed(self):
        for fixture, expected in (
            ({"missingComposer": True}, "timeout_composer_missing"),
            ({"composer": "Another user's draft"}, "timeout_composer_mismatch"),
            ({"missingSend": True}, "timeout_send_button_missing"),
        ):
            with self.subTest(fixture=fixture):
                result = self.send_once(**fixture)
                self.assertEqual(result["clicks"], 0)
                self.assertEqual(result["marked"], 0)
                self.assertEqual(result["stage"], expected)

    def test_signed_prompt_length_matches_url_constructor(self):
        for size in (4500, 4800):
            with self.subTest(size=size):
                self.assertEqual(self.send_once(prompt="a" * size)["clicks"], 1)
        for prompt in ("a" * 4801, "ä" * 1601, "!" * 1601):
            with self.subTest(encoded_length=len(quote(prompt, safe=""))):
                self.assertEqual(self.send_once(prompt=prompt)["clicks"], 0)

    def test_same_signed_request_in_two_tabs_claims_at_most_once(self):
        result = self.send_once(tabs=2)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["marked"], 1)
        self.assertEqual(sorted(result["perTabClicks"]), [0, 1])
        self.assertEqual(result["stage"], "message_sent")

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
