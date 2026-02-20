/**
 * popup.js — Drives the VerifyFirst popup UI.
 * Reads from chrome.storage.session (written by background.js).
 */

const BACKEND = "http://127.0.0.1:8000";

const CATEGORY_CONFIG = {
  safe: {
    icon: "✓",
    label: "Safe",
    accent: "#00c896",
    dotClass: "dot-safe",
  },
  suspicious: {
    icon: "⚠",
    label: "Suspicious",
    accent: "#f5a623",
    dotClass: "dot-sus",
  },
  dangerous: {
    icon: "⛔",
    label: "Phishing Blocked",
    accent: "#e5144b",
    dotClass: "dot-danger",
  },
  unavailable: {
    icon: "?",
    label: "Unavailable",
    accent: "#888888",
    dotClass: "dot-unknown",
  },
};

// ── On load ─────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  await Promise.all([
    checkBackendStatus(),
    loadCurrentTabResult(),
    loadStats(),
    loadRecentScans(),
  ]);
});

// ── Backend health check ─────────────────────────────────────────────────────

async function checkBackendStatus() {
  const pill = document.getElementById("backendStatus");
  try {
    const res = await fetch(`${BACKEND}/health`, {
      signal: AbortSignal.timeout(1000),
    });
    if (res.ok) {
      const data = await res.json();
      pill.textContent = "ONLINE";
      pill.className = "status-pill pill-online";
      const cacheEl = document.getElementById("cacheSize");
      if (cacheEl && data.cache_size != null) {
        cacheEl.textContent = `cache: ${data.cache_size}`;
      }
    } else {
      throw new Error("not ok");
    }
  } catch (_) {
    pill.textContent = "OFFLINE";
    pill.className = "status-pill pill-offline";
  }
}

// ── Current tab result ───────────────────────────────────────────────────────

async function loadCurrentTabResult() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  const stored = await chrome.storage.session.get([`result_${tab.id}`]);
  const result = stored[`result_${tab.id}`];

  const container = document.getElementById("currentResult");
  const noResult = document.getElementById("noResult");

  if (!result) return;

  noResult?.remove();

  const cfg = CATEGORY_CONFIG[result.category] || CATEGORY_CONFIG.unavailable;

  const card = document.createElement("div");
  card.className = "result-card";
  card.style.setProperty("--card-accent", cfg.accent);

  const urlShort = shortenUrl(result.url || "—");

  card.innerHTML = `
    <div class="result-row">
      <span class="result-icon">${cfg.icon}</span>
      <span class="result-cat">${cfg.label}</span>
      <span class="result-score">${result.risk_score ?? "—"}<span>/100</span></span>
    </div>
    <div class="result-url">${escapeHtml(urlShort)}</div>
  `;

  container.appendChild(card);
}

// ── Stats from backend ────────────────────────────────────────────────────────

async function loadStats() {
  try {
    const res = await fetch(`${BACKEND}/stats`, {
      signal: AbortSignal.timeout(1000),
    });
    if (!res.ok) return;
    const data = await res.json();
    const safe = data.safe || 0;
    const sus  = data.suspicious || 0;
    const danger = data.dangerous || 0;

    document.getElementById("statSafe").textContent   = safe;
    document.getElementById("statSus").textContent    = sus;
    document.getElementById("statDanger").textContent = danger;
  } catch (_) {
    // Backend offline — leave dashes
  }
}

// ── Recent scans from session storage ────────────────────────────────────────

async function loadRecentScans() {
  const all = await chrome.storage.session.get(null);
  const results = Object.entries(all)
    .filter(([key]) => key.startsWith("result_"))
    .map(([, v]) => v)
    .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
    .slice(0, 8);

  const list = document.getElementById("recentList");
  if (!list) return;

  if (results.length === 0) return;

  list.innerHTML = results
    .map((r) => {
      const cfg = CATEGORY_CONFIG[r.category] || CATEGORY_CONFIG.unavailable;
      return `
        <li class="recent-item">
          <span class="recent-dot ${cfg.dotClass}"></span>
          <span class="recent-url">${escapeHtml(shortenUrl(r.url || ""))}</span>
          <span class="recent-score">${r.risk_score ?? "—"}</span>
        </li>
      `;
    })
    .join("");
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function shortenUrl(url) {
  try {
    const u = new URL(url);
    let display = u.hostname + u.pathname;
    if (display.length > 42) display = display.slice(0, 40) + "…";
    return display;
  } catch (_) {
    return url.slice(0, 42);
  }
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.appendChild(document.createTextNode(String(str)));
  return d.innerHTML;
}
