const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "zip", "mov", "top", "work", "click", "link",
  "xyz", "country", "kim", "science", "party", "gdn", "loan", "download",
  "racing", "stream", "review", "win", "bid", "trade"
]);

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
]);

const SCAM_KEYWORDS = [
  "verify", "verification", "confirm", "update", "secure", "security",
  "account", "login", "signin", "password", "reset", "unlock", "suspend",
  "urgent", "alert", "warning", "kyc", "refund", "claim", "prize", "reward",
  "winner", "lottery", "gift", "bonus", "free", "offer", "cashback", "recover",
  "support", "helpdesk", "billing", "invoice", "payment"
];

const BRANDS = [
  "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
  "instagram", "whatsapp", "outlook", "office365", "icloud", "coinbase",
  "binance", "metamask", "wellsfargo", "chase", "bankofamerica", "citibank",
  "hdfc", "hdfcbank", "icici", "icicibank", "sbi", "axis", "axisbank",
  "kotak", "idfc", "yesbank", "indusind", "pnb", "bob", "canara",
  "zerodha", "paytm", "phonepe", "gpay", "flipkart", "myntra"
];

const LEGITIMATE_DOMAINS = new Set([
  // Indian banks
  "hdfcbank.com", "icicibank.com", "sbi.co.in", "onlinesbi.com",
  "axisbank.com", "kotak.com", "yesbank.in", "indusind.com",
  "pnbindia.in", "bankofbaroda.in", "canarabank.com", "idfcfirstbank.com",
  // Payment / UPI
  "paytm.com", "phonepe.com", "googlepay.com", "amazonpay.in", "mobikwik.com",
  // Financial / trading
  "zerodha.com", "kite.zerodha.com", "groww.in", "upstox.com",
  // International
  "paypal.com", "apple.com", "microsoft.com", "google.com",
  "amazon.com", "amazon.in", "netflix.com", "facebook.com",
  "instagram.com", "whatsapp.com", "outlook.com", "icloud.com",
  "coinbase.com", "binance.com",
  // E-commerce
  "flipkart.com", "myntra.com",
  // Courier
  "fedex.com", "dhl.com", "ups.com", "usps.com", "bluedart.com",
  "delhivery.com", "dtdc.in", "indiapost.gov.in",
  // Utilities
  "irctc.co.in"
]);

const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "ac.in", "gov.in", "net.in",
  "org.in", "res.in", "com.au", "net.au", "org.au", "co.nz", "co.za", "co.jp",
  "co.kr", "com.br", "com.mx", "com.sg", "com.hk", "com.tw", "co.id", "com.tr",
  "com.ar", "co.th", "bank.in", ".bank"
]);

function levelFromScore(score) {
  if (score > 0.6) return "dangerous";
  if (score >= 0.3) return "suspicious";
  return "safe";
}

function shannonEntropy(str) {
  if (!str) return 0;
  const freq = Object.create(null);
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const n of Object.values(freq)) {
    const p = n / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isIPv4(host) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function isIPv6(host) {
  const h = host.replace(/^\[|\]$/g, "");
  return h.includes(":") && /^[0-9a-fA-F:]+$/.test(h);
}

function registeredDomain(host) {
  if (isIPv4(host) || isIPv6(host)) return host;
  const parts = host.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 1) return host.toLowerCase();
  const last2 = parts.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(last2) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return last2;
}

function sldOf(regDomain, host) {
  if (isIPv4(host) || isIPv6(host)) return "";
  const parts = regDomain.split(".");
  const last2 = parts.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(last2) && parts.length >= 3) {
    return parts[0];
  }
  return parts[0] || "";
}

export function analyzeURL(rawUrl) {
  const features = [];
  let host = "";

  if (!rawUrl || typeof rawUrl !== "string") {
    return { score: 0, level: "safe", features, host };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    try {
      parsed = new URL("https://" + rawUrl);
    } catch {
      return { score: 0, level: "safe", features, host };
    }
  }

  host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const href = parsed.href;

  if (parsed.protocol === "http:") {
    features.push({
      name: "insecure-http",
      weight: 12,
      detail: "Page is served over HTTP instead of HTTPS"
    });
  }

  if (isIPv4(host) || isIPv6(host)) {
    features.push({
      name: "ip-host",
      weight: 25,
      detail: "Host is an IP address rather than a domain name"
    });
  }

  if (host.includes("xn--") || href.toLowerCase().includes("xn--")) {
    features.push({
      name: "punycode",
      weight: 15,
      detail: "Hostname uses punycode (xn--), which can hide lookalike domains"
    });
  }

  if (/[\u0370-\u03FF\u0400-\u04FF]/.test(parsed.hostname) || /[\u0370-\u03FF\u0400-\u04FF]/.test(href)) {
    features.push({
      name: "homoglyph",
      weight: 30,
      detail: "URL contains Cyrillic or Greek characters used for lookalike spoofing"
    });
  }

  if (rawUrl.includes("@") || href.includes("@")) {
    features.push({
      name: "at-sign",
      weight: 25,
      detail: "URL contains @, which can hide the real destination"
    });
  }

  const labels = host.split(".").filter(Boolean);
  const tld = labels[labels.length - 1] || "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    features.push({
      name: "suspicious-tld",
      weight: 20,
      detail: `Suspicious top-level domain .${tld}`
    });
  }

  const reg = registeredDomain(host);
  const sub = host.endsWith(reg) ? host.slice(0, Math.max(0, host.length - reg.length)).replace(/\.$/, "") : "";
  const subLabels = sub ? sub.split(".").filter(Boolean) : [];
  if (subLabels.length >= 4) {
    features.push({
      name: "many-subdomains",
      weight: 8,
      detail: `Host has ${subLabels.length} subdomain labels`
    });
  }

  const shortHost = host.replace(/^www\./, "");
  if (SHORTENERS.has(shortHost) || SHORTENERS.has(host)) {
    features.push({
      name: "url-shortener",
      weight: 18,
      detail: `URL shortener domain (${shortHost})`
    });
  }

  const entropy = shannonEntropy(host);
  if (entropy > 3.8) {
    features.push({
      name: "high-entropy",
      weight: 10,
      detail: `Hostname entropy is ${entropy.toFixed(2)} (high randomness)`
    });
  }

  const pathBlob = `${parsed.pathname} ${parsed.search}`.toLowerCase();
  const pathHits = SCAM_KEYWORDS.filter((kw) => pathBlob.includes(kw));
  if (pathHits.length >= 2) {
    features.push({
      name: "path-scam-keywords",
      weight: 15,
      detail: `Path contains multiple scam keywords: ${pathHits.slice(0, 6).join(", ")}`
    });
  } else if (pathHits.length === 1) {
    features.push({
      name: "path-scam-keyword",
      weight: 6,
      detail: `Path contains scam keyword: ${pathHits[0]}`
    });
  }

  const sld = sldOf(reg, host);
  const subLower = sub.toLowerCase();

  const isLegitimateDomain = LEGITIMATE_DOMAINS.has(reg);

  if (!isIPv4(host) && !isIPv6(host) && !isLegitimateDomain) {
    for (const brand of BRANDS) {
      const inSub = subLower.includes(brand);
      const inReg = reg.includes(brand) || sld.includes(brand);
      const whole = sld === brand;

      if (inSub) {
        features.push({
          name: "brand-subdomain",
          weight: 35,
          detail: `Brand “${brand}” appears in the subdomain of ${host}`
        });
      } else if (inReg && !whole) {
        features.push({
          name: "brand-domain",
          weight: 30,
          detail: `Brand “${brand}” appears in the domain ${reg} but is not the real site`
        });
      }
    }
  }

  const raw = features.reduce((sum, f) => sum + f.weight, 0);
  const score = 1 - Math.exp(-raw / 50);
  return { score, level: levelFromScore(score), features, host };
}
