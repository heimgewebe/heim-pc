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
const stored = data.verify && data.priorAttempt !== false ? {
  nabu_send_receipts_v1: {["cd".repeat(12)]: {stage: "send_unconfirmed", at: Math.floor(Date.now()/1000)}}
} : {};
let backgroundListener;
let installListener;
const nativeReceipts = [];
const sessionStored = {};
const backgroundChrome = {
  runtime: {
    onMessage: { addListener(fn) { backgroundListener = fn; } },
    onInstalled: { addListener(fn) { installListener = fn; } },
    getManifest() { return {version: "1.1.6"}; },
    async sendNativeMessage(host, body) {
      nativeReceipts.push({host, body});
      if (data.nativeFailure) throw new Error("native host unavailable");
      return {recorded: true};
    }
  },
  storage: { local: {
    async get(key) { return {[key]: stored[key]}; },
    async set(values) {
      if (data.storageFailure) throw new Error("storage failed");
      Object.assign(stored, values);
    }
  }, session: {
    async get(key) { return {[key]: sessionStored[key]}; },
    async set(values) {
      if (data.sessionFailure) throw new Error("session storage failed");
      Object.assign(sessionStored, values);
    }
  } }
};
vm.runInNewContext(data.background, {chrome: backgroundChrome, Date, URL});
function openTab(tabId, documentURL = url, recovery = false, recoveredText = null) {
  const loc = {origin: documentURL.origin, pathname: documentURL.pathname, search: documentURL.search, href: documentURL.href};
  let hydrated = !data.delayedHydration;
  let clicks = 0;
  const visible = {getClientRects() {return hydrated ? [{}] : [];}};
  const send = {
    ...visible,
    disabled: !!data.sendDisabled,
    getAttribute(name) {
      if (name === "aria-label") return data.sendLabel ?? "Nachricht senden";
      if (name === "data-testid") return data.sendTestId || null;
      if (name === "type") return data.formSubmit ? "submit" : "button";
      return null;
    },
    click() { clicks++; }
  };
  const form = {querySelectorAll(selector) {
    if (selector === 'button[type="submit"]') return data.formSubmit ? [send] : [];
    return data.missingSend ? [] : [send];
  }};
  const draft = {
    ...visible,
    value: data.composer,
    closest(selector) {return data.formSubmit && selector === "form" ? form : null;}
  };
  const context = {
    location: loc, URL, URLSearchParams, TextEncoder, crypto: webcrypto, Date,
    chrome: { runtime: {
      sendMessage(message) {
        return new Promise(resolve => {
          if (!backgroundListener(message, {url: loc.href, frameId: 0, tab: {id: tabId}}, resolve)) {
            resolve({granted: false, recorded: false});
          }
        });
      }
    } },
    document: {
      querySelectorAll(selector) {
        if (selector === "button") return data.missingSend ? [] : [send];
        if (selector.includes('data-message-author-role="user"')) {
          if (data.directUserTestId && !selector.includes('[data-testid="user-message"]')) return [];
          if (!(recovery || data.verify || clicks && data.confirm !== false && !data.navigate)) return [];
          const value = recoveredText ?? data.messageText ?? data.composer;
          return [{...visible, ...(data.hiddenWrapper ? {getClientRects() {return [];}} : {}),
            innerText: data.wrapped ? "You said:\n" + value : value,
            querySelectorAll() {return data.wrapped || data.hiddenWrapper ? [{...visible, innerText: value}] : [];}
          }];
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
const tabs = Array.from({length: data.tabs || 1}, (_, i) => openTab(i + 1));
Promise.all(tabs.map(tab => tab.finished)).then(async () => {
  let recoveryClicks = 0;
  if (data.navigate) {
    if (data.expirePending) {
      for (const p of Object.values(sessionStored.nabu_pending_proof_v1 || {})) p.at -= 61;
    }
    if (data.removeAttempt) stored.nabu_send_receipts_v1 = {};
    const first = openTab(data.otherTab ? 99 : 1, new URL("https://chatgpt.com/c/new-chat-12345678"), true, data.wrongRecoveredText ? "different message" : null);
    await first.finished;
    recoveryClicks += first.clicks;
    if (data.secondRoute) {
      const second = openTab(1, new URL("https://chatgpt.com/c/other-chat-12345678"), true);
      await second.finished;
      recoveryClicks += second.clicks;
    }
  }
  const receipts = Object.values(stored.nabu_send_receipts_v1 || {});
  console.log(JSON.stringify({
    clicks: tabs.reduce((n, tab) => n + tab.clicks, 0) + recoveryClicks,
    recoveryClicks,
    noPromptInSession: !JSON.stringify(sessionStored).includes(data.composer),
    perTabClicks: tabs.map(tab => tab.clicks),
    marked: Object.keys(stored.nabu_consumed_nonces_v1 || {}).length,
    stage: receipts[0]?.stage || null,
    noPromptInReceipts: !JSON.stringify(receipts).includes(data.composer),
    nativeReceipts
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
        if fixture.get("verify"):
            path = "/c/00000000-test"
            digest = hashlib.sha256(prompt.encode()).hexdigest()
            verification = f"nabu-verify-v1\n{ts}\n{nonce}\n{path}\n{digest}".encode()
            signature = hmac.new(key, verification, hashlib.sha256).hexdigest()
            url = (f"https://chatgpt.com{path}?nabu_verify={digest}&nabu_ts={ts}"
                   f"&nabu_nonce={nonce}&nabu_sig={signature if signed else '0'*64}")
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
        self.assertEqual(result["nativeReceipts"], [
            {"host": "net.heimgewebe.nabu_receipt", "body": {"nonce": "cd" * 12, "stage": stage}}
            for stage in ("click_attempted", "message_sent")
        ])

    def test_message_proof_survives_replaced_document_in_same_tab(self):
        result = self.send_once(navigate=True)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["recoveryClicks"], 0)
        self.assertEqual(result["stage"], "message_verified")
        self.assertTrue(result["noPromptInSession"])
        self.assertEqual(result["nativeReceipts"][-1]["body"]["stage"], "message_verified")

    def test_document_recovery_rejects_other_tab_stale_or_unattempted_claim(self):
        for fixture in ({"otherTab": True}, {"expirePending": True},
                        {"removeAttempt": True}, {"sessionFailure": True}):
            with self.subTest(fixture=fixture):
                result = self.send_once(navigate=True, **fixture)
                self.assertEqual(result["clicks"], 1)
                self.assertEqual(result["recoveryClicks"], 0)
                self.assertNotIn(result["stage"], ("message_sent", "message_verified"))

    def test_document_recovery_never_follows_second_conversation(self):
        result = self.send_once(navigate=True, wrongRecoveredText=True, secondRoute=True)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["stage"], "verification_text_mismatch")
        self.assertEqual(result["recoveryClicks"], 0)

    def test_semantic_wrapper_without_rectangle_has_visible_text_child(self):
        result = self.send_once(hiddenWrapper=True, wrapped=True)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["stage"], "message_sent")

    def test_native_transport_failure_does_not_repeat_send(self):
        result = self.send_once(nativeFailure=True)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["stage"], "message_sent")

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

    def test_localized_send_prompt_labels_and_unique_form_submit(self):
        for fixture in (
            {"sendLabel": "Send prompt"},
            {"sendLabel": "Prompt senden"},
            {"sendLabel": "Senden"},
            {"sendLabel": "Unlabeled", "formSubmit": True},
        ):
            with self.subTest(fixture=fixture):
                result = self.send_once(**fixture)
                self.assertEqual(result["clicks"], 1)
                self.assertEqual(result["stage"], "message_sent")

    def test_never_click_disabled_or_voice_or_stop_control(self):
        for fixture, expected in (
            ({"sendDisabled": True}, "timeout_send_button_unavailable"),
            ({"sendLabel": "Voice", "formSubmit": True}, "timeout_send_button_missing"),
            ({"sendLabel": "Stop generating", "formSubmit": True}, "timeout_send_button_missing"),
            ({"sendLabel": "Unrelated control"}, "timeout_send_button_missing"),
        ):
            with self.subTest(fixture=fixture):
                result = self.send_once(**fixture)
                self.assertEqual(result["clicks"], 0)
                self.assertEqual(result["marked"], 0)
                self.assertEqual(result["stage"], expected)

    def test_wrapped_own_message_confirms_exact_outgoing_text(self):
        result = self.send_once(wrapped=True)
        self.assertEqual(result["clicks"], 1)
        self.assertEqual(result["stage"], "message_sent")

    def test_read_only_recovery_recognizes_standalone_user_message_testid(self):
        result = self.send_once(verify=True, directUserTestId=True)
        self.assertEqual(result["clicks"], 0)
        self.assertEqual(result["stage"], "message_verified")
        self.assertEqual(result["nativeReceipts"][-1]["body"]["stage"], "message_verified")

    def test_read_only_recovery_requires_prior_attempt_and_never_clicks(self):
        for fixture, expected in (
            ({"verify": True, "wrapped": True}, "message_verified"),
            ({"verify": True, "messageText": "different text"}, "verification_text_mismatch"),
            ({"verify": True, "priorAttempt": False}, None),
            ({"verify": True, "signed": False}, "send_unconfirmed"),
            ({"verify": True, "account": False}, "message_verified"),
            ({"verify": True, "login": True}, "verification_login_required"),
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
                self.assertEqual(result["nativeReceipts"], [])


if __name__ == "__main__":
    unittest.main()
