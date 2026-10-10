(() => {
  let overlayShown = false;

  // Known-safe host patterns — regex for flexible matching.
  const SAFE_HOST_PATTERNS = [
    // Search engines
    /(^|\.)google\.(com|co\.in|co\.uk)$/,
    /(^|\.)bing\.com$/,
    /(^|\.)duckduckgo\.com$/,
    /(^|\.)yahoo\.com$/,
    /(^|\.)yandex\.com$/,
    /(^|\.)baidu\.com$/,
    // Encyclopedias / dev
    /(^|\.)wikipedia\.org$/,
    /(^|\.)youtube\.com$/,
    /(^|\.)youtu\.be$/,
    /(^|\.)github\.com$/,
    /(^|\.)gitlab\.com$/,
    /(^|\.)stackoverflow\.com$/,
    /(^|\.)reddit\.com$/,
    /(^|\.)quora\.com$/,
    // Social
    /(^|\.)twitter\.com$/,
    /(^|\.)x\.com$/,
    /(^|\.)linkedin\.com$/,
    /(^|\.)facebook\.com$/,
    /(^|\.)instagram\.com$/,
    // E-commerce
    /(^|\.)amazon\.(com|in)$/,
    /(^|\.)flipkart\.com$/,
    // Travel / gov
    /(^|\.)irctc\.co\.in$/,
    /(^|\.)rbi\.org\.in$/,
    /(^|\.)npci\.org\.in$/,
    // All Indian banks on .bank.in TLD (RBI-mandated)
    /\.bank\.in$/,
    // Known Indian bank domains — covers all subdomains
    /(^|\.)hdfcbank\.(com|co\.in)$/,
    /(^|\.)icicibank\.(com|co\.in)$/,
    /(^|\.)sbi\.co\.in$/,
    /(^|\.)onlinesbi\.(sbi|com)$/,
    /(^|\.)sbicard\.com$/,
    /(^|\.)axisbank\.(com|co\.in)$/,
    /(^|\.)kotak\.com$/,
    /(^|\.)kotakbank\.com$/,
    /(^|\.)yesbank\.in$/,
    /(^|\.)indusind\.com$/,
    /(^|\.)indusindbank\.com$/,
    /(^|\.)pnbindia\.in$/,
    /(^|\.)bankofbaroda\.(in|co\.in|com)$/,
    /(^|\.)canarabank\.(com|in)$/,
    /(^|\.)idfcfirstbank\.com$/,
    /(^|\.)idfcbank\.com$/,
    /(^|\.)unionbankofindia\.(co\.in|com)$/,
    /(^|\.)centralbankofindia\.co\.in$/,
    /(^|\.)iob\.in$/,
    /(^|\.)ucobank\.com$/,
    /(^|\.)federalbank\.co\.in$/,
    /(^|\.)southindianbank\.com$/,
    /(^|\.)karnatakabank\.com$/,
    /(^|\.)dcbbank\.com$/,
    /(^|\.)rblbank\.com$/,
    /(^|\.)bandhanbank\.com$/,
    /(^|\.)aubank\.in$/,
    /(^|\.)equitasbank\.com$/,
    /(^|\.)ujjivansfb\.in$/,
    /(^|\.)paytm\.com$/,
    /(^|\.)phonepe\.com$/,
    /(^|\.)mobikwik\.com$/,
    /(^|\.)zerodha\.com$/,
    /(^|\.)groww\.in$/,
    /(^|\.)upstox\.com$/,
    /(^|\.)angelone\.in$/,
    /(^|\.)hdfcsec\.com$/,
    /(^|\.)icicidirect\.com$/
  ];

  function isSafeHost() {
    try {
      const host = window.location.hostname.toLowerCase();
      if (!host) return false;
      for (const pattern of SAFE_HOST_PATTERNS) {
        if (pattern.test(host)) return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (ch) => {
      switch (ch) {
        case "&": return "&amp;";
        case "<": return "&lt;";
        case ">": return "&gt;";
        case '"': return "&quot;";
        default: return "&#39;";
      }
    });
  }

  function sendAnalyze(payload, cb) {
    try {
      chrome.runtime.sendMessage({ type: "analyze", ...payload }, (result) => {
        if (chrome.runtime.lastError) return;
        if (cb) cb(result);
      });
    } catch {
      /* extension context gone */
    }
  }

  function ensureBody(fn) {
    if (document.body) {
      fn();
      return;
    }
    const obs = new MutationObserver(() => {
      if (document.body) {
        obs.disconnect();
        fn();
      }
    });
    obs.observe(document.documentElement || document, { childList: true, subtree: true });
    document.addEventListener("DOMContentLoaded", () => fn(), { once: true });
  }

  function getAnalyzeUrl() {
    if (window.location.protocol === "file:") {
      return document.body?.dataset?.kavachUrl || window.location.href;
    }
    return window.location.href;
  }

  function getTrustHost() {
    const url = getAnalyzeUrl();
    try {
      const u = new URL(url);
      return u.hostname.toLowerCase();
    } catch {
      return String(url || "").toLowerCase();
    }
  }

  function isTrusted(cb) {
    const host = getTrustHost();
    if (!host) return cb(false);
    try {
      chrome.storage.local.get(["trustedDomains"], (res) => {
        if (chrome.runtime.lastError) return cb(false);
        const list = Array.isArray(res.trustedDomains) ? res.trustedDomains : [];
        cb(list.includes(host));
      });
    } catch {
      cb(false);
    }
  }

  function showOverlay(verdict) {
    if (overlayShown) return;
    if (!verdict || (verdict.level !== "suspicious" && verdict.level !== "dangerous")) return;
    overlayShown = true;

    ensureBody(() => {
      if (document.getElementById("kavach-overlay")) return;

      const dangerous = verdict.level === "dangerous";
      const score100 = Math.round((verdict.score || 0) * 100);
      const title = dangerous ? "Dangerous page blocked" : "Suspicious page";
      const icon = dangerous ? "⚠" : "!";
      const reasons = (verdict.explanation || []).slice(0, 4);
      const cat = verdict.categoryLabel
        ? `<div class="kavach-cat">Detected: ${escapeHtml(verdict.categoryLabel)}</div>`
        : "";
      const reasonHtml = reasons.length
        ? `<ul class="kavach-reasons">${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
        : "";

      const warningBox = dangerous
        ? `<div class="kavach-warning-box">
             <div class="kavach-warning-title">Do NOT enter your:</div>
             <div class="kavach-warning-items">OTP · PIN · CVV · Password · Card number</div>
           </div>`
        : "";

      const root = document.createElement("div");
      root.id = "kavach-overlay";
      root.className = dangerous ? "kavach-overlay kavach-dangerous" : "kavach-overlay kavach-suspicious";
      root.innerHTML = `
        <div class="kavach-card" role="dialog" aria-modal="true" aria-labelledby="kavach-title">
          <div class="kavach-icon">${icon}</div>
          <h1 id="kavach-title">${escapeHtml(title)}</h1>
          <p class="kavach-sub">Risk score: ${escapeHtml(String(score100))}/100 · Analyzed locally on your device</p>
          ${cat}
          ${reasonHtml}
          ${warningBox}
          <div class="kavach-actions">
            <button type="button" class="kavach-btn kavach-btn-primary" id="kavach-leave">Leave this page</button>
            <button type="button" class="kavach-btn kavach-btn-secondary" id="kavach-continue">Continue anyway</button>
          </div>
          <p class="kavach-foot">All analysis runs on your device. No data was sent anywhere.</p>
        </div>
      `;

      document.body.appendChild(root);

      const leave = root.querySelector("#kavach-leave");
      const cont = root.querySelector("#kavach-continue");
      leave.addEventListener("click", () => {
        if (window.history.length > 1) window.history.back();
        else window.location.href = "about:blank";
      });
      cont.addEventListener("click", () => {
        root.remove();
      });
    });
  }

  function runScan() {
    if (isSafeHost()) return;
    isTrusted((trusted) => {
      if (trusted) return;
      const url = getAnalyzeUrl();
      const text = (document.body?.innerText || "").slice(0, 3000);
      sendAnalyze({ url, text }, showOverlay);
    });
  }

  ensureBody(runScan);
})();