"use strict";

// Chrome shares this MV3 worker across this profile's tabs. Persist claims before
// clicking, and keep bounded content-free diagnostic receipts for signed requests.
const CLAIMS = "nabu_consumed_nonces_v1";
const RECEIPTS = "nabu_send_receipts_v1";
const PENDING = "nabu_pending_proof_v1";
const PROOF_SECONDS = 60;
const conversationPath = path => /^\/c\/[a-zA-Z0-9-]{8,100}\/?$/.test(path);
const STAGES = new Set([
  "validated", "login_required", "account_unconfirmed", "composer_missing",
  "composer_mismatch", "send_button_missing", "send_button_unavailable", "already_present",
  "claim_unconfirmed", "claim_denied", "composer_changed", "click_attempted",
  "message_sent", "message_verified", "verification_not_found", "verification_login_required",
  "verification_text_mismatch", "verification_no_user_messages", "send_unconfirmed", "expired", "timeout_login_required",
  "timeout_account_unconfirmed", "timeout_composer_missing",
  "timeout_composer_mismatch", "timeout_send_button_missing", "timeout_send_button_unavailable"
]);
// Forward only attempted or terminal outcomes, never the prompt, URL or account.
const nativeStages = new Set([...STAGES].filter(stage =>
  stage === "click_attempted" || stage === "message_sent" ||
  stage === "message_verified" || stage === "send_unconfirmed" ||
  stage === "already_present" || stage === "claim_denied" ||
  stage === "claim_unconfirmed" || stage === "composer_changed" ||
  stage === "expired" || stage.startsWith("verification_") || stage.startsWith("timeout_")
));
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

// Only a bounded opaque digest survives a document replacement in this tab.
// Session storage is extension-private and does not persist across Chrome restarts.
async function pendingMap(now) {
  const old = (await chrome.storage.session.get(PENDING))[PENDING] || {};
  return Object.fromEntries(Object.entries(old).filter(([tab, p]) =>
    /^\d+$/.test(tab) && validNonce(p?.nonce) &&
    /^[a-f0-9]{64}$/.test(p.digest || "") && Number.isSafeInteger(p.at) &&
    p.at >= now - PROOF_SECONDS && p.at <= now + 15 &&
    (p.path === null || conversationPath(p.path))
  ).sort((a, b) => b[1].at - a[1].at).slice(0, 63));
}

async function claim(nonce, message, sender) {
  const now = nowSeconds();
  const seen = recentClaims((await chrome.storage.local.get(CLAIMS))[CLAIMS], now);
  if (Object.hasOwn(seen, nonce)) return {granted: false};
  seen[nonce] = now;
  await chrome.storage.local.set({[CLAIMS]: seen});
  // Proof transport must not prevent an otherwise valid once-only send.
  // This pending entry never authorizes a click in a later document.
  if (Number.isInteger(sender.tab?.id) &&
      /^[a-f0-9]{64}$/.test(message.digest || "") &&
      Number.isSafeInteger(message.issuedAt) &&
      message.issuedAt <= now + 15 && now - message.issuedAt <= 180) {
    try {
      const pending = await pendingMap(now);
      pending[String(sender.tab.id)] = {
        nonce, digest: message.digest, at: now, path: null
      };
      await chrome.storage.session.set({[PENDING]: pending});
    } catch { /* The original document can still provide proof. */ }
  }
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
  const confirmed = ["message_sent", "message_verified"];
  const verification = ["verification_not_found", "verification_login_required",
    "verification_text_mismatch", "verification_no_user_messages"];
  const attempted = ["click_attempted", "send_unconfirmed", ...verification];
  if (["message_verified", ...verification].includes(stage) &&
      !attempted.includes(before) && !confirmed.includes(before)) return {recorded: false};
  if (confirmed.includes(before) ||
      (attempted.includes(before) &&
       ![...confirmed, ...attempted].includes(stage))) return {recorded: true};
  records[nonce] = {stage, at: now};
  await chrome.storage.local.set({[RECEIPTS]: records});
  if (nativeStages.has(stage)) {
    // A local receipt transport failure is never a reason to click again.
    try {
      await chrome.runtime.sendNativeMessage("net.heimgewebe.nabu_receipt", {nonce, stage});
    } catch { /* Chrome-local receipt remains authoritative. */ }
  }
  return {recorded: true};
}

async function continuation(sender, url, message) {
  if (!Number.isInteger(sender.tab?.id) || !conversationPath(url.pathname))
    return {available: false};
  const now = nowSeconds();
  const pending = await pendingMap(now);
  const tab = String(sender.tab.id);
  const entry = pending[tab];
  if (!entry || (entry.path !== null && entry.path !== url.pathname))
    return {available: false};
  const previous = (await chrome.storage.local.get(RECEIPTS))[RECEIPTS]?.[entry.nonce]?.stage;
  const attempted = ["click_attempted", "send_unconfirmed", "verification_not_found",
    "verification_no_user_messages", "verification_text_mismatch", "verification_login_required"];
  // Bind the first new conversation route observed for the claimed tab.
  if (message.type === "nabu-pending-proof-v1") {
    if (entry.path === null) {
      entry.path = url.pathname;
      await chrome.storage.session.set({[PENDING]: pending});
    }
    if (!attempted.includes(previous)) {
      // Claiming does not replace the most recent composer-wait status.
      // A new document can query before the actual click report arrives.
      const waiting = ["validated", "login_required", "account_unconfirmed",
        "composer_missing", "composer_mismatch", "send_button_missing",
        "send_button_unavailable"];
      return {available: false, pending: waiting.includes(previous)};
    }
    return {available: true, nonce: entry.nonce, digest: entry.digest,
      expiresAt: entry.at + PROOF_SECONDS};
  }
  if (entry.path !== url.pathname || entry.nonce !== message.nonce || !attempted.includes(previous))
    return {recorded: false};
  if (!["message_verified", "verification_no_user_messages", "verification_text_mismatch",
        "verification_login_required"].includes(message.stage)) return {recorded: false};
  const result = await record(entry.nonce, message.stage);
  if (result.recorded && message.stage === "message_verified") {
    delete pending[tab];
    await chrome.storage.session.set({[PENDING]: pending});
  }
  return result;
}

async function clearPending(sender, nonce) {
  if (!Number.isInteger(sender.tab?.id)) return;
  try {
    const pending = await pendingMap(nowSeconds());
    const tab = String(sender.tab.id);
    if (pending[tab]?.nonce === nonce) {
      delete pending[tab];
      await chrome.storage.session.set({[PENDING]: pending});
    }
  } catch { /* A bounded proof entry expires even if cleanup fails. */ }
}

let queue = Promise.resolve();
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  const type = message?.type;
  if (!["nabu-signed-send-claim-v1", "nabu-send-status-v1",
        "nabu-pending-proof-v1", "nabu-pending-proof-result-v1"].includes(type))
    return false;
  if (type !== "nabu-pending-proof-v1" && !validNonce(message.nonce)) return false;
  let url;
  try {
    url = new URL(sender.url || "");
    if (url.origin !== "https://chatgpt.com" || sender.frameId !== 0) return false;
  } catch { return false; }
  const work = async () => {
    if (type === "nabu-signed-send-claim-v1") {
      if (url.pathname !== "/") return {granted: false};
      return claim(message.nonce, message, sender);
    }
    if (type === "nabu-pending-proof-v1" || type === "nabu-pending-proof-result-v1")
      return continuation(sender, url, message);
    const result = await record(message.nonce, message.stage);
    if (result.recorded && ["message_sent", "message_verified", "composer_changed", "expired"].includes(message.stage))
      await clearPending(sender, message.nonce);
    return result;
  };
  const result = queue.then(work, work);
  queue = result.then(() => undefined, () => undefined);
  result.then(reply, () => reply({granted: false, recorded: false, available: false}));
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({nabu_sender_loaded_version: chrome.runtime.getManifest().version});
});
