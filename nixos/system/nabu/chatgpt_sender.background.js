"use strict";

// A Chrome MV3 service worker is shared across the extension's tab contexts.
// Keep the claim queue in this worker; persist BEFORE replying to the sender.
let queue = Promise.resolve();
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== "nabu-signed-send-claim-v1") return false;
  const claim = async () => {
    if (!/^[a-f0-9]{24}$/.test(message.nonce)) return false;
    if (new URL(sender.url || "").origin !== "https://chatgpt.com") return false;
    const key = "nabu_consumed_nonces_v1";
    const previous = (await chrome.storage.local.get(key))[key] || {};
    const now = Math.floor(Date.now() / 1000);
    const seen = {};
    // Signed requests expire after 180s. Keep claims longer than that, but
    // prevent unbounded growth without allowing a still-valid nonce to recur.
    for (const [nonce, stamp] of Object.entries(previous)) {
      if (/^[a-f0-9]{24}$/.test(nonce) &&
          Number.isSafeInteger(stamp) && stamp >= now - 600 &&
          stamp <= now + 15) seen[nonce] = stamp;
    }
    if (Object.hasOwn(seen, message.nonce)) return false;
    seen[message.nonce] = now;
    await chrome.storage.local.set({[key]: seen});
    return true;
  };
  const result = queue.then(claim, claim);
  queue = result.then(() => undefined, () => undefined);
  result.then(granted => reply({granted}), () => reply({granted: false}));
  return true; // Keep the message port open for the durable claim.
});
