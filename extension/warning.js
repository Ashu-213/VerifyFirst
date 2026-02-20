/**
 * warning.js — Populates the warning page with threat data from URL params.
 * Also handles "Go Back" and "Proceed Anyway" actions.
 */

(function () {
  "use strict";

  const params = new URLSearchParams(window.location.search);
  const originalUrl = decodeURIComponent(params.get("url") || "");
  const score = parseInt(params.get("score") || "85", 10);
  let reasons = [];

  try {
    reasons = JSON.parse(decodeURIComponent(params.get("reasons") || "[]"));
  } catch (_) {
    reasons = ["Threat indicators detected"];
  }

  // ── Populate URL ────────────────────────────────────────────────────────────
  const urlDisplay = document.getElementById("urlDisplay");
  if (urlDisplay) {
    urlDisplay.textContent = originalUrl || "Unknown URL";
  }

  // ── Populate score with animated counter ────────────────────────────────────
  const scoreEl = document.getElementById("scoreDisplay");
  const gaugeEl = document.getElementById("gaugeFill");

  function animateScore(target) {
    let current = 0;
    const step = Math.ceil(target / 30);
    const interval = setInterval(() => {
      current = Math.min(current + step, target);
      if (scoreEl) scoreEl.innerHTML = `${current}<span>/100</span>`;
      if (current >= target) clearInterval(interval);
    }, 28);
  }

  // Trigger gauge animation after paint
  requestAnimationFrame(() => {
    setTimeout(() => {
      if (gaugeEl) gaugeEl.style.width = `${Math.min(score, 100)}%`;
      animateScore(score);
    }, 300);
  });

  // ── Populate timestamp ───────────────────────────────────────────────────────
  const ts = document.getElementById("timestamp");
  if (ts) {
    const now = new Date();
    ts.textContent = `THREAT SCORE: CRITICAL — ${now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
  }

  // ── Populate reasons ─────────────────────────────────────────────────────────
  const reasonsList = document.getElementById("reasonsList");
  if (reasonsList) {
    if (reasons.length === 0) {
      reasons = ["URL matches threat intelligence database"];
    }
    reasonsList.innerHTML = reasons
      .slice(0, 6)
      .map(
        (r) => `
        <div class="reason-item">
          <span class="reason-bullet">▸</span>
          <span>${escapeHtml(r)}</span>
        </div>`
      )
      .join("");
  }

  // ── Go Back button ───────────────────────────────────────────────────────────
  document.getElementById("btnBack")?.addEventListener("click", () => {
    if (window.history.length > 1) {
      // Go back two steps (skip the warning page itself)
      window.history.go(-2);
    } else {
      // Fall back to new tab page
      window.location.href = "chrome://newtab";
    }
  });

  // ── Proceed Anyway button ────────────────────────────────────────────────────
  document.getElementById("btnProceed")?.addEventListener("click", () => {
    if (!originalUrl) return;

    const confirmed = window.confirm(
      "⚠ WARNING: This page has been identified as a likely phishing site.\n\n" +
        "Proceeding may expose your credentials and personal data to attackers.\n\n" +
        "Are you sure you want to continue?"
    );

    if (confirmed) {
      // Navigate directly, bypassing extension analysis for this load
      window.location.href = originalUrl;
    }
  });

  // ── Utility ──────────────────────────────────────────────────────────────────
  function escapeHtml(str) {
    const d = document.createElement("div");
    d.appendChild(document.createTextNode(str));
    return d.innerHTML;
  }
})();
