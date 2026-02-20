/**
 * content.js — VerifyFirst content script safety net.
 *
 * Injected at document_start on all http/https pages.
 * Listens for messages from the service worker to show/hide
 * overlays and banners in case scripting.executeScript fails.
 */

(function () {
  "use strict";

  // Prevent double injection
  if (window.__vfContentLoaded) return;
  window.__vfContentLoaded = true;

  // Message bus from service worker
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || !msg.type) return;

    switch (msg.type) {
      case "VF_SHOW_OVERLAY":
        showOverlay();
        sendResponse({ ok: true });
        break;
      case "VF_HIDE_OVERLAY":
        hideOverlay();
        sendResponse({ ok: true });
        break;
      case "VF_SHOW_BANNER":
        showBanner(msg.data);
        sendResponse({ ok: true });
        break;
    }
  });

  function showOverlay() {
    if (document.getElementById("__vf_overlay__")) return;

    const el = document.createElement("div");
    el.id = "__vf_overlay__";
    el.style.cssText = `
      position: fixed; top:0; left:0; right:0; bottom:0;
      background: rgba(5,10,20,0.88); z-index:2147483647;
      display:flex; align-items:center; justify-content:center;
      font-family:'Courier New',monospace; backdrop-filter:blur(4px);
    `;
    el.innerHTML = `
      <div style="text-align:center; color:#4A9EFF;">
        <div style="
          width:48px;height:48px;border:3px solid #4A9EFF;
          border-top-color:transparent;border-radius:50%;
          margin:0 auto 16px;animation:__vf_spin__ 0.8s linear infinite;
        "></div>
        <div style="font-size:14px;letter-spacing:3px;text-transform:uppercase;">Scanning URL…</div>
        <style>@keyframes __vf_spin__ { to{transform:rotate(360deg)} }</style>
      </div>
    `;
    (document.documentElement || document.body || document).appendChild(el);
  }

  function hideOverlay() {
    document.getElementById("__vf_overlay__")?.remove();
  }

  function showBanner(data) {
    hideOverlay();
    document.getElementById("__vf_banner__")?.remove();

    const { type, score, reasons } = data || {};
    const c = type === "suspicious"
      ? { bg: "#1A0F00", border: "#F5A623", accent: "#F5A623", icon: "⚠" }
      : { bg: "#0A0A0A", border: "#555", accent: "#888", icon: "?" };

    const title = type === "suspicious"
      ? `Suspicious Page — Score ${score}/100`
      : "VerifyFirst Unavailable";

    const reasonHtml = (reasons || []).slice(0, 3)
      .map((r) => `<li style="margin:2px 0;opacity:0.85;">${r}</li>`)
      .join("");

    const banner = document.createElement("div");
    banner.id = "__vf_banner__";
    banner.style.cssText = `
      position:fixed;top:0;left:0;right:0;
      background:${c.bg};border-bottom:2px solid ${c.border};
      color:#e8e8e8;font-family:'Courier New',monospace;font-size:12px;
      padding:10px 16px;z-index:2147483646;
      display:flex;align-items:flex-start;gap:12px;
      box-shadow:0 4px 24px rgba(0,0,0,0.5);
      animation:__vf_slidein__ 0.25s ease;
    `;
    banner.innerHTML = `
      <style>@keyframes __vf_slidein__{from{transform:translateY(-100%);opacity:0}to{transform:translateY(0);opacity:1}}</style>
      <span style="font-size:20px;line-height:1;color:${c.accent};flex-shrink:0;">${c.icon}</span>
      <div style="flex:1;">
        <div style="font-weight:bold;color:${c.accent};margin-bottom:3px;letter-spacing:1px;">${title}</div>
        <ul style="margin:0;padding-left:16px;list-style:disc;">${reasonHtml}</ul>
      </div>
      <button id="__vf_close__" style="
        background:none;border:1px solid #444;color:#aaa;
        cursor:pointer;padding:3px 8px;font-family:inherit;border-radius:3px;flex-shrink:0;
      ">✕</button>
    `;
    (document.documentElement || document.body).appendChild(banner);
    document.getElementById("__vf_close__")?.addEventListener("click", () => banner.remove());
  }
})();
