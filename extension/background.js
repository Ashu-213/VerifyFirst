/**
 * background.js — VerifyFirst Service Worker (Manifest V3)
 *
 * Flow:
 *  1. chrome.tabs.onUpdated fires when a tab's URL changes
 *  2. Show overlay immediately via content script injection
 *  3. POST URL to backend /analyze
 *  4. Handle result: safe / suspicious / dangerous / unreachable
 *  5. Update badge
 */

const BACKEND_URL = "https://verifyfirst.onrender.com";
const ANALYZE_ENDPOINT = `${BACKEND_URL}/analyze`;
const TIMEOUT_MS = 4000;

// In-memory session cache (mirrors backend cache, avoids redundant calls)
const sessionCache = new Map();
const MAX_CACHE = 200;

// Badge counter for blocked phishing attempts
let blockedCount = 0;

// ── Ignore list: protocols and internal pages ─────────────────────────────────
function shouldIgnoreUrl(url) {
  if (!url) return true;
  const lower = url.toLowerCase();
  const ignoredPrefixes = [
    "chrome://", "chrome-extension://", "about:", "data:",
    "javascript:", "file://", "moz-extension://", "edge://",
    "devtools://", "view-source:",
  ];
  return ignoredPrefixes.some((p) => lower.startsWith(p));
}

function isHttpUrl(url) {
  return url.startsWith("http://") || url.startsWith("https://");
}

// ── Session cache helpers ─────────────────────────────────────────────────────
function cacheGet(url) {
  return sessionCache.get(url) || null;
}

function cacheSet(url, result) {
  if (sessionCache.size >= MAX_CACHE) {
    const firstKey = sessionCache.keys().next().value;
    sessionCache.delete(firstKey);
  }
  sessionCache.set(url, result);
}

// ── Tab state tracking ────────────────────────────────────────────────────────
// Tracks URLs we have already started analyzing for a given tab
const pendingTabs = new Map(); // tabId → url

// ── Main listener ─────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  const url = changeInfo.url || tab.url;

  if (!url) return;
  if (shouldIgnoreUrl(url)) return;
  if (!isHttpUrl(url)) return;

  // Only fire once per URL change (not on every status change)
  if (changeInfo.status !== "loading" && !changeInfo.url) return;

  // Deduplicate: skip if we already analyzed this URL for this tab
  if (pendingTabs.get(tabId) === url) return;
  pendingTabs.set(tabId, url);

  // Show overlay immediately
  await safeInjectOverlay(tabId, "checking");

  // Check session cache
  const cached = cacheGet(url);
  if (cached) {
    await handleResult(tabId, url, cached, true);
    return;
  }

  // Call backend with timeout
  const result = await fetchAnalysis(url);
  cacheSet(url, result);
  await handleResult(tabId, url, result, false);
});

// Clear pending state when tab navigates away or closes
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete") {
    pendingTabs.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pendingTabs.delete(tabId);
});

// ── Backend call ──────────────────────────────────────────────────────────────
async function fetchAnalysis(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(ANALYZE_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!response.ok) {
      return fallbackResult("Backend returned error status");
    }

    return await response.json();
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      return fallbackResult("Analysis timed out");
    }
    return fallbackResult("Backend unreachable");
  }
}

function fallbackResult(reason) {
  return {
    risk_score: 0,
    category: "unavailable",
    reasons: [reason],
  };
}

// ── Result handler ────────────────────────────────────────────────────────────
async function handleResult(tabId, url, result, fromCache) {
  const { category, risk_score, reasons } = result;

  if (category === "dangerous") {
    blockedCount++;
    setBadge(tabId, "dangerous");
    await redirectToDangerPage(tabId, url, result);
  } else if (category === "suspicious") {
    setBadge(tabId, "suspicious");
    await safeInjectBanner(tabId, {
      type: "suspicious",
      score: risk_score,
      reasons,
      url,
    });
  } else if (category === "unavailable") {
    setBadge(tabId, "unavailable");
    await safeInjectBanner(tabId, {
      type: "unavailable",
      score: null,
      reasons: ["VerifyFirst backend is unavailable — analysis skipped"],
      url,
    });
  } else {
    // safe
    setBadge(tabId, "safe");
    await safeInjectOverlay(tabId, "done");
  }

  // Store result for popup to read
  await chrome.storage.session.set({
    [`result_${tabId}`]: {
      url,
      ...result,
      timestamp: Date.now(),
    },
  });
}

// ── Redirect to warning page ──────────────────────────────────────────────────
async function redirectToDangerPage(tabId, originalUrl, result) {
  const params = new URLSearchParams({
    url: originalUrl,
    score: String(result.risk_score),
    reasons: JSON.stringify(result.reasons || []),
  });
  const warningUrl = chrome.runtime.getURL(`warning.html?${params.toString()}`);

  try {
    await chrome.tabs.update(tabId, { url: warningUrl });
  } catch (e) {
    console.warn("[VF] Could not redirect tab:", e);
  }
}

// ── Badge ─────────────────────────────────────────────────────────────────────
const BADGE_CONFIG = {
  safe: { text: "✓", color: "#00C896" },
  suspicious: { text: "!", color: "#F5A623" },
  dangerous: { text: String(blockedCount), color: "#E5144B" },
  unavailable: { text: "?", color: "#888888" },
  checking: { text: "…", color: "#4A9EFF" },
};

function setBadge(tabId, type) {
  if (type === "dangerous") {
    BADGE_CONFIG.dangerous.text = String(blockedCount);
  }
  const cfg = BADGE_CONFIG[type] || BADGE_CONFIG.checking;
  chrome.action.setBadgeText({ tabId, text: cfg.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
}

// ── Content script injection helpers ─────────────────────────────────────────
async function safeInjectOverlay(tabId, state) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: injectOverlay,
      args: [state],
    });
  } catch (_) {
    // Tab may have navigated away — ignore
  }
}

async function safeInjectBanner(tabId, data) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: injectBanner,
      args: [data],
    });
  } catch (_) {
    // Ignore
  }
}

// ── Functions injected into page context ──────────────────────────────────────
// NOTE: These are serialized and run in the page — no closure access.

function injectOverlay(state) {
  const existingId = "__vf_overlay__";
  let el = document.getElementById(existingId);

  if (state === "done") {
    if (el) el.remove();
    return;
  }

  if (!el) {
    el = document.createElement("div");
    el.id = existingId;
    el.style.cssText = `
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(5, 10, 20, 0.88);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Courier New', monospace;
      backdrop-filter: blur(4px);
      transition: opacity 0.3s ease;
    `;

    el.innerHTML = `
      <div style="text-align:center; color: #4A9EFF;">
        <div style="
          width: 48px; height: 48px; border: 3px solid #4A9EFF;
          border-top-color: transparent; border-radius: 50%;
          margin: 0 auto 16px;
          animation: __vf_spin__ 0.8s linear infinite;
        "></div>
        <div style="font-size:14px; letter-spacing:3px; text-transform:uppercase; opacity:0.9;">
          Scanning URL…
        </div>
        <style>
          @keyframes __vf_spin__ { to { transform: rotate(360deg); } }
        </style>
      </div>
    `;
    document.documentElement.appendChild(el);
  }
}

function injectBanner(data) {
  // Remove overlay first
  const overlay = document.getElementById("__vf_overlay__");
  if (overlay) overlay.remove();

  // Remove existing banner
  const existing = document.getElementById("__vf_banner__");
  if (existing) existing.remove();

  const { type, score, reasons } = data;

  const colors = {
    suspicious: { bg: "#1A0F00", border: "#F5A623", accent: "#F5A623", icon: "⚠" },
    unavailable: { bg: "#0A0A0A", border: "#555555", accent: "#888888", icon: "?" },
  };
  const c = colors[type] || colors.unavailable;
  const title = type === "suspicious"
    ? `Suspicious Page — Score ${score}/100`
    : "VerifyFirst Unavailable";

  const reasonHtml = (reasons || [])
    .slice(0, 3)
    .map((r) => `<li style="margin:2px 0; opacity:0.85;">${r}</li>`)
    .join("");

  const banner = document.createElement("div");
  banner.id = "__vf_banner__";
  banner.style.cssText = `
    position: fixed;
    top: 0; left: 0; right: 0;
    background: ${c.bg};
    border-bottom: 2px solid ${c.border};
    color: #e8e8e8;
    font-family: 'Courier New', monospace;
    font-size: 12px;
    padding: 10px 16px;
    z-index: 2147483646;
    display: flex;
    align-items: flex-start;
    gap: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.5);
    animation: __vf_slidein__ 0.25s ease;
  `;

  banner.innerHTML = `
    <style>
      @keyframes __vf_slidein__ { from { transform:translateY(-100%); opacity:0; } to { transform:translateY(0); opacity:1; } }
    </style>
    <span style="font-size:20px; line-height:1; color:${c.accent}; flex-shrink:0;">${c.icon}</span>
    <div style="flex:1;">
      <div style="font-weight:bold; color:${c.accent}; margin-bottom:3px; letter-spacing:1px;">${title}</div>
      <ul style="margin:0; padding-left:16px; list-style:disc;">${reasonHtml}</ul>
    </div>
    <button id="__vf_close__" style="
      background: none; border: 1px solid #444;
      color: #aaa; cursor: pointer; padding: 3px 8px;
      font-family: inherit; border-radius: 3px; flex-shrink:0;
    ">Dismiss</button>
  `;

  document.documentElement.appendChild(banner);
  document.getElementById("__vf_close__")?.addEventListener("click", () => banner.remove());
}

// ── Startup health check ───────────────────────────────────────────────────────
async function checkBackendHealth() {
  try {
    const res = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(1000) });
    if (res.ok) {
      console.log("[VF] Backend is online.");
    }
  } catch (_) {
    console.warn("[VF] Backend appears offline. Start with: python main.py");
  }
}

checkBackendHealth();
