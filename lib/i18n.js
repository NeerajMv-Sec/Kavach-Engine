// Kavach localization — English + Hindi
// Add new languages by extending STRINGS with a new locale key.

const STRINGS = {
  en: {
    appName: "Kavach",
    tagline: "On-device scam and phishing detection",

    loading: "Analyzing this page…",
    noVerdict: "No verdict yet.",
    noActiveTab: "No active tab.",
    couldNotAnalyze: "Could not analyze this tab.",

    verdictSafe: "Looks Safe",
    verdictSuspicious: "Suspicious",
    verdictDangerous: "Dangerous",
    riskScore: "Risk score {score}/100",

    linkAnalysis: "Link Analysis",
    contentAnalysis: "Content Analysis",
    noSignals: "No signals",

    trustButton: "Trust this site",
    reportButton: "Report false positive",
    trustConfirmed: "✓ This site will be skipped in future checks",
    reportConfirmed: "✓ Reported. Thank you.",

    footerText: "All analysis runs locally · no cloud"
  },

  hi: {
    appName: "कवच",
    tagline: "डिवाइस पर ही स्कैम और फ़िशिंग की पहचान",

    loading: "इस पेज की जाँच हो रही है…",
    noVerdict: "अभी कोई फ़ैसला नहीं।",
    noActiveTab: "कोई सक्रिय टैब नहीं।",
    couldNotAnalyze: "इस टैब की जाँच नहीं हो सकी।",

    verdictSafe: "सुरक्षित लगता है",
    verdictSuspicious: "संदिग्ध",
    verdictDangerous: "खतरनाक",
    riskScore: "जोखिम स्कोर {score}/100",

    linkAnalysis: "लिंक विश्लेषण",
    contentAnalysis: "सामग्री विश्लेषण",
    noSignals: "कोई संकेत नहीं",

    trustButton: "इस साइट पर भरोसा करें",
    reportButton: "गलत अलर्ट की रिपोर्ट करें",
    trustConfirmed: "✓ इस साइट को आगे नहीं जाँचा जाएगा",
    reportConfirmed: "✓ रिपोर्ट दर्ज हो गई। धन्यवाद।",

    footerText: "सारी जाँच आपके डिवाइस पर · क्लाउड पर कुछ नहीं"
  }
};

const DEFAULT_LANG = "en";
const STORAGE_KEY = "kavachLang";

export function getLang() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get([STORAGE_KEY], (res) => {
        if (chrome.runtime.lastError) return resolve(DEFAULT_LANG);
        const saved = res && res[STORAGE_KEY];
        resolve(STRINGS[saved] ? saved : DEFAULT_LANG);
      });
    } catch {
      resolve(DEFAULT_LANG);
    }
  });
}

export function setLang(lang) {
  return new Promise((resolve) => {
    if (!STRINGS[lang]) return resolve(false);
    try {
      chrome.storage.local.set({ [STORAGE_KEY]: lang }, () => {
        if (chrome.runtime.lastError) return resolve(false);
        resolve(true);
      });
    } catch {
      resolve(false);
    }
  });
}

export function t(lang, key, vars) {
  const table = STRINGS[lang] || STRINGS[DEFAULT_LANG];
  let str = table[key] ?? STRINGS[DEFAULT_LANG][key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      str = str.replace(new RegExp("\\{" + k + "\\}", "g"), String(v));
    }
  }
  return str;
}

export function nextLang(lang) {
  return lang === "en" ? "hi" : "en";
}

export function langLabel(lang) {
  return lang === "en" ? "EN" : "हिं";
}