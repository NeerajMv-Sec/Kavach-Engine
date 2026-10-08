import { analyze } from "./lib/fusion.js";

const verdicts = new Map();

function tabIdFrom(msg, sender) {
  if (typeof msg.tabId === "number") return msg.tabId;
  if (sender.tab && typeof sender.tab.id === "number") return sender.tab.id;
  return null;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.type !== "string") return;

  if (msg.type === "analyze") {
    const tabId = tabIdFrom(msg, sender);
    const prev = tabId != null ? verdicts.get(tabId) : null;
    const text = typeof msg.text === "string" ? msg.text : prev?.inputText;
    const url = typeof msg.url === "string" ? msg.url : prev?.inputUrl;
    const result = analyze({ text, url });
    if (tabId != null) {
      verdicts.set(tabId, {
        result,
        inputText: text,
        inputUrl: url
      });
    }
    sendResponse(result);
    return true;
  }

  if (msg.type === "get-verdict") {
    const tabId = tabIdFrom(msg, sender);
    const entry = tabId != null ? verdicts.get(tabId) : null;
    sendResponse(entry ? entry.result : null);
    return true;
  }

  if (msg.type === "clear-verdict") {
    const tabId = tabIdFrom(msg, sender);
    if (tabId != null) verdicts.delete(tabId);
    sendResponse({ ok: true });
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  verdicts.delete(tabId);
});
