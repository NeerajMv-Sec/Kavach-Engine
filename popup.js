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

function featureList(features) {
  if (!features || !features.length) {
    return `<p class="none">No signals</p>`;
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

function render(verdict, pageUrl, currentHost, isTrusted) {
  const app = document.getElementById("app");
  if (!verdict) {
    app.innerHTML = `<p class="empty">No verdict yet.</p>`;
    return;
  }

  const level = verdict.level || "safe";
  const score100 = Math.round((verdict.score || 0) * 100);
  const labels = {
    safe: { title: "Looks Safe", icon: "✓" },
    suspicious: { title: "Suspicious", icon: "!" },
    dangerous: { title: "Dangerous", icon: "⚠" }
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
      <button type="button" class="btn btn-primary" id="trust-btn">Trust this site</button>
      <button type="button" class="btn btn-secondary" id="report-btn">Report false positive</button>
    </div>
    <div class="status" id="status"></div>
  ` : "";

  app.innerHTML = `
    <div class="badge ${escapeHtml(level)}">
      <div class="badge-icon">${meta.icon}</div>
      <div>
        <h2>${meta.title}</h2>
        <p>Risk score ${score100}/100</p>
      </div>
    </div>
    ${cat}
    <div class="urlbox">${escapeHtml(displayUrl)}</div>
    <section class="section">
      <h3>Link Analysis</h3>
      ${featureList(verdict.url && verdict.url.features)}
    </section>
    <section class="section">
      <h3>Content Analysis</h3>
      ${featureList(verdict.text && verdict.text.features)}
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
        statusEl.textContent = "✓ This site will be skipped in future checks";
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
        statusEl.textContent = "✓ Reported. Thank you.";
        statusEl.classList.add("show");
      });
    });
  });
}

function analyzeTab(tab) {
  chrome.runtime.sendMessage(
    { type: "analyze", tabId: tab.id, url: tab.url || "" },
    (result) => {
      if (chrome.runtime.lastError) {
        document.getElementById("app").innerHTML = `<p class="empty">Could not analyze this tab.</p>`;
        return;
      }
      const host = hostFromUrl(tab.url || "", result && result.host);
chrome.storage.local.get(["trustedDomains"], (res) => {
  const list = Array.isArray(res.trustedDomains) ? res.trustedDomains : [];
  render(result, tab.url, host, list.includes(host));
});
    }
  );
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab) {
    document.getElementById("app").innerHTML = `<p class="empty">No active tab.</p>`;
    return;
  }

  chrome.runtime.sendMessage({ type: "get-verdict", tabId: tab.id }, (cached) => {
    if (chrome.runtime.lastError) {
      analyzeTab(tab);
      return;
    }
    if (cached) {
  const host = hostFromUrl(tab.url || "", cached.host);
  chrome.storage.local.get(["trustedDomains"], (res) => {
    const list = Array.isArray(res.trustedDomains) ? res.trustedDomains : [];
    render(cached, tab.url, host, list.includes(host));
  });
} else {
      analyzeTab(tab);
    }
  });
});