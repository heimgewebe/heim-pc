"use strict";

// Chrome shares this MV3 worker across this profile's tabs. Persist claims before
// clicking, and keep bounded content-free diagnostic receipts for signed requests.
const CLAIMS = "nabu_consumed_nonces_v1";
const RECEIPTS = "nabu_send_receipts_v1";
const STAGES = new Set([
  "validated", "login_required", "account_unconfirmed", "composer_missing",
  "composer_mismatch", "send_button_missing", "send_button_unavailable", "already_present",
  "claim_unconfirmed", "claim_denied", "composer_changed", "click_attempted",
  "message_sent", "send_unconfirmed", "expired", "timeout_login_required",
  "timeout_account_unconfirmed", "timeout_composer_missing",
  "timeout_composer_mismatch", "timeout_send_button_missing", "timeout_send_button_unavailable"
]);
const nowSeconds = () => Math.floor(Date.now() / 1000);
const validNonce = value => typeof value === "string" && /^[a-f0-9]{24}$/.test(value);

function recentClaims(previous, now) {
  const seen = {};
  for (const [nonce, stamp] of Object.entries(previous || {})) {
    if (validNonce(nonce) && Number.isSafeInteger(stamp) &&
        stamp >= now - 600 && stamp <= now + 15) seen[nonce] = stamp;
  }
  return seen;
}

async function claim(nonce) {
  const now = nowSeconds();
  const seen = recentClaims((await chrome.storage.local.get(CLAIMS))[CLAIMS], now);
  if (Object.hasOwn(seen, nonce)) return {granted: false};
  seen[nonce] = now;
  await chrome.storage.local.set({[CLAIMS]: seen});
  return {granted: true};
}

async function record(nonce, stage) {
  if (!STAGES.has(stage)) return {recorded: false};
  const now = nowSeconds();
  const old = (await chrome.storage.local.get(RECEIPTS))[RECEIPTS] || {};
  const records = Object.fromEntries(Object.entries(old)
    .filter(([key, value]) => validNonce(key) && STAGES.has(value?.stage) &&
      Number.isSafeInteger(value?.at) && value.at >= now - 3600 && value.at <= now + 15)
    .sort((a, b) => b[1].at - a[1].at).slice(0, 63));
  const before = records[nonce]?.stage;
  // A duplicate tab must not overwrite a completed or attempted send.
  const final = ["message_sent", "send_unconfirmed", "click_attempted"];
  if (before === "message_sent" ||
      (final.includes(before) && !final.includes(stage))) return {recorded: true};
  records[nonce] = {stage, at: now};
  await chrome.storage.local.set({[RECEIPTS]: records});
  return {recorded: true};
}

let queue = Promise.resolve();
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (!["nabu-signed-send-claim-v1", "nabu-send-status-v1"].includes(message?.type) ||
      !validNonce(message.nonce)) return false;
  try {
    if (new URL(sender.url || "").origin !== "https://chatgpt.com" ||
        sender.frameId !== 0) return false;
  } catch { return false; }
  const work = () => message.type === "nabu-signed-send-claim-v1"
    ? claim(message.nonce) : record(message.nonce, message.stage);
  const result = queue.then(work, work);
  queue = result.then(() => undefined, () => undefined);
  result.then(reply, () => reply({granted: false, recorded: false}));
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({nabu_sender_loaded_version: chrome.runtime.getManifest().version});
});
