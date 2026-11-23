"use strict";
const reload = () => {
  // This private extension page has no web_accessible_resources entry.
  // An explicit local navigation or button click requests a supported reload.
  if (location.hash) history.replaceState(history.state, "", location.pathname);
  chrome.runtime.reload();
};
if (location.hash === "#reload") {
  reload();
} else {
  document.getElementById("version").textContent = "Version " + chrome.runtime.getManifest().version;
  document.getElementById("reload").addEventListener("click", reload);
  chrome.storage?.local?.get("nabu_send_receipts_v1").then(result => {
    const latest = Object.values(result.nabu_send_receipts_v1 || {})
      .sort((a, b) => b.at - a.at)[0];
    document.getElementById("status").textContent = latest
      ? "Letzter Versandstatus: " + latest.stage
      : "Noch kein Versandstatus.";
  }).catch(() => {
    document.getElementById("status").textContent = "Versandstatus noch nicht verfügbar.";
  });
}
