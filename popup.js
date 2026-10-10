import { getLang, setLang, t, nextLang, langLabel } from "./lib/i18n.js";

let currentLang = "en";
let lastState = null; // { verdict, pageUrl, currentHost, isTrusted }

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

function featureList(features, lang) {
  if (!features || !features.length) {
    return `<p class="none">${escapeHtml(t(lang, "noSignals"))}</p>`;
  }
  return features.map((f) => `
    <div class="feat">
      <div class="feat-top">
        <span>${escapeHtml(f.name)}</span>
        <span class="feat-w">+${escapeHtml(String(f.weight))}</span>
      </div>
      <p>${escapeHtml(f.detail || "")}</p>
    </div>
  `).join("");
}

function hostFromUrl(url, fallbackHost) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    if (h) return h;
  } catch {}
  return (fallbackHost || "").toLowerCase();
}

function renderHeader(lang) {
  document.getElementById("hdr-title").textContent = t(lang, "appName");
  document.getElementById("hdr-sub").textContent = t(lang, "tagline");
  document.getElementById("ftr-text").textContent = t(lang, "footerText");
  document.getElementById("lang-toggle").textContent = langLabel(lang);
}

function render(lang) {
  const state = lastState;
  const app = document.getElementById("app");

  if (!state) {
    app.innerHTML = `<p class="empty">${escapeHtml(t(lang, "loading"))}</p>`;
    return;
  }

  const { verdict, pageUrl, currentHost, isTrusted } = state;

  if (!verdict) {
    app.innerHTML = `<p class="empty">${escapeHtml(t(lang, "noVerdict"))}</p>`;
    return;
  }

  const level = verdict.level || "safe";
  const score100 = Math.round((verdict.score || 0) * 100);
  const labels = {
    safe: { title: t(lang, "verdictSafe"), icon: "✓" },
    suspicious: { title: t(lang, "verdictSuspicious"), icon: "!" },
    dangerous: { title: t(lang, "verdictDangerous"), icon: "⚠" }
  };
  const meta = labels[level] || labels.safe;

  let displayUrl = pageUrl || verdict.host || "";
  if (displayUrl.startsWith("file:") && verdict.host) {
    displayUrl = verdict.host;
  }

  const cat = verdict.categoryLabel
    ? `<div class="cat">${escapeHtml(verdict.categoryLabel)}</div>`
    : "";

  const showButtons = level !== "safe" && currentHost && !isTrusted;
  const actionsHtml = showButtons ? `
    <div class="actions">
      <button type="button" class="btn btn-primary" id="trust-btn">${escapeHtml(t(lang, "trustButton"))}</button>
      <button type="button" class="btn btn-secondary" id="report-btn">${escapeHtml(t(lang, "reportButton"))}</button>
    </div>
    <div class="status" id="status"></div>
  ` : "";

  app.innerHTML = `
    <div class="badge ${escapeHtml(level)}">
      <div class="badge-icon">${meta.icon}</div>
      <div>
        <h2>${escapeHtml(meta.title)}</h2>
        <p>${escapeHtml(t(lang, "riskScore", { score: score100 }))}</p>
      </div>
    </div>
    <div class="score-bar">
      <div class="score-fill ${escapeHtml(level)}" style="width: ${score100}%"></div>
    </div>
    ${cat}
    <div class="urlbox">${escapeHtml(displayUrl)}</div>
    <section class="section">
      <h3>${escapeHtml(t(lang, "linkAnalysis"))}</h3>
      ${featureList(verdict.url && verdict.url.features, lang)}
    </section>
    <section class="section">
      <h3>${escapeHtml(t(lang, "contentAnalysis"))}</h3>
      ${featureList(verdict.text && verdict.text.features, lang)}
    </section>
    ${actionsHtml}
  `;

  if (!showButtons) return;

  const trustBtn = document.getElementById("trust-btn");
  const reportBtn = document.getElementById("report-btn");
  const statusEl = document.getElementById("status");

  trustBtn.addEventListener("click", () => {
    chrome.storage.local.get(["trustedDomains"], (res) => {
      const list = Array.isArray(res.trustedDomains) ? res.trustedDomains : [];
      if (!list.includes(currentHost)) list.push(currentHost);
      chrome.storage.local.set({ trustedDomains: list }, () => {
        chrome.runtime.sendMessage({ type: "clear-verdict", tabId: null });
        statusEl.textContent = t(lang, "trustConfirmed");
        statusEl.classList.add("show");
        setTimeout(() => chrome.tabs.reload(), 800);
      });
    });
  });

  reportBtn.addEventListener("click", () => {
    chrome.storage.local.get(["reportedFalsePositives"], (res) => {
      const list = Array.isArray(res.reportedFalsePositives) ? res.reportedFalsePositives : [];
      list.push({
        host: currentHost,
        url: pageUrl,
        timestamp: Date.now()
      });
      chrome.storage.local.set({ reportedFalsePositives: list }, () => {
        statusEl.textContent = t(lang, "reportConfirmed");
        statusEl.classList.add("show");
      });
    });
  });
}

function analyzeTab(tab, lang) {
  chrome.runtime.sendMessage(
    { type: "analyze", tabId: tab.id, url: tab.url || "" },
    (result) => {
      if (chrome.runtime.lastError) {
        document.getElementById("app").innerHTML =
          `<p class="empty">${escapeHtml(t(lang, "couldNotAnalyze"))}</p>`;
        return;
      }
      const host = hostFromUrl(tab.url || "", result && result.host);
      chrome.storage.local.get(["trustedDomains"], (res) => {
        const list = Array.isArray(res.trustedDomains) ? res.trustedDomains : [];
        lastState = { verdict: result, pageUrl: tab.url, currentHost: host, isTrusted: list.includes(host) };
        render(lang);
      });
    }
  );
}

function init(lang) {
  currentLang = lang;
  renderHeader(lang);

  document.getElementById("lang-toggle").addEventListener("click", async () => {
    const next = nextLang(currentLang);
    await setLang(next);
    currentLang = next;
    renderHeader(next);
    render(next);
  });

  document.getElementById("loading").textContent = t(lang, "loading");

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab) {
      document.getElementById("app").innerHTML =
        `<p class="empty">${escapeHtml(t(lang, "noActiveTab"))}</p>`;
      return;
    }

    chrome.runtime.sendMessage({ type: "get-verdict", tabId: tab.id }, (cached) => {
      if (chrome.runtime.lastError) {
        analyzeTab(tab, lang);
        return;
      }
      if (cached) {
        const host = hostFromUrl(tab.url || "", cached.host);
        chrome.storage.local.get(["trustedDomains"], (res) => {
          const list = Array.isArray(res.trustedDomains) ? res.trustedDomains : [];
          lastState = { verdict: cached, pageUrl: tab.url, currentHost: host, isTrusted: list.includes(host) };
          render(lang);
        });
      } else {
        analyzeTab(tab, lang);
      }
    });
  });
}

getLang().then(init);