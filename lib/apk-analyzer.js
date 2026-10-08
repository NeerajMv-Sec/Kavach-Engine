const SUSPICIOUS_PERMISSIONS = {
  READ_SMS: {
    weight: 20,
    detail: "Reads incoming SMS, enables OTP interception"
  },
  RECEIVE_SMS: {
    weight: 20,
    detail: "Intercepts incoming SMS in real time"
  },
  SEND_SMS: {
    weight: 18,
    detail: "Can send SMS, used for premium-rate fraud"
  },
  READ_CONTACTS: {
    weight: 12,
    detail: "Reads the contact list"
  },
  RECORD_AUDIO: {
    weight: 18,
    detail: "Can record audio in the background"
  },
  ACCESS_FINE_LOCATION: {
    weight: 10,
    detail: "Tracks precise location"
  },
  ACCESS_BACKGROUND_LOCATION: {
    weight: 15,
    detail: "Tracks location even when closed"
  },
  READ_CALL_LOG: {
    weight: 15,
    detail: "Reads call history"
  },
  SYSTEM_ALERT_WINDOW: {
    weight: 22,
    detail: "Draws overlays over other apps, common in banking trojans"
  },
  REQUEST_INSTALL_PACKAGES: {
    weight: 25,
    detail: "Can install other apps, used by dropper malware"
  },
  BIND_ACCESSIBILITY_SERVICE: {
    weight: 30,
    detail: "Accessibility access, full screen reading and tapping"
  },
  CAMERA: {
    weight: 8,
    detail: "Camera access"
  },
  READ_EXTERNAL_STORAGE: {
    weight: 8,
    detail: "Reads files on external storage"
  },
  WRITE_EXTERNAL_STORAGE: {
    weight: 8,
    detail: "Writes files on external storage"
  }
};

const EXPECTED_PERMISSIONS = {
  flashlight: ["CAMERA"],
  calculator: [],
  notes: [],
  weather: ["ACCESS_FINE_LOCATION"],
  camera: ["CAMERA", "WRITE_EXTERNAL_STORAGE"],
  banking: ["INTERNET", "CAMERA", "ACCESS_FINE_LOCATION"],
  social: ["INTERNET", "CAMERA", "READ_CONTACTS"],
  unknown: []
};

const CATEGORY_LABELS = {
  flashlight: "Flashlight",
  calculator: "Calculator",
  notes: "Notes",
  weather: "Weather",
  camera: "Camera",
  banking: "Banking",
  social: "Social",
  unknown: "Unknown"
};

const CATEGORY_HINTS = [
  { key: "flashlight", re: /flash\s*light|torch/i },
  { key: "calculator", re: /calc(ulator)?/i },
  { key: "notes", re: /\bnotes?\b|notepad|memo/i },
  { key: "weather", re: /weather|forecast/i },
  { key: "camera", re: /camera|selfie|photo/i },
  { key: "banking", re: /bank|upi|wallet|finance|payment/i },
  { key: "social", re: /social|chat|messenger|whatsapp|instagram|facebook/i }
];

const SUSPICIOUS_TOKEN_RE = /(fake|mod|crack|hack|free|pro|premium|unlock)/i;

function levelFromScore(score) {
  if (score > 0.6) return "dangerous";
  if (score >= 0.3) return "suspicious";
  return "safe";
}

function normalizePerm(name) {
  if (!name || typeof name !== "string") return "";
  const trimmed = name.trim();
  const m = trimmed.match(/^(?:android\.permission\.)?([A-Z_]+)$/i);
  return m ? m[1].toUpperCase() : trimmed.replace(/^android\.permission\./i, "").toUpperCase();
}

function inferCategory(packageName, label) {
  const blob = `${packageName || ""} ${label || ""}`;
  for (const hint of CATEGORY_HINTS) {
    if (hint.re.test(blob)) return hint.key;
  }
  return "unknown";
}

function parseManifestXml(xml) {
  const permissions = [];
  const permRe = /android:name\s*=\s*"android\.permission\.([A-Z_]+)"/g;
  let m;
  while ((m = permRe.exec(xml)) !== null) {
    permissions.push(m[1]);
  }

  const pkgMatch = xml.match(/package\s*=\s*"([^"]+)"/);
  const packageName = pkgMatch ? pkgMatch[1] : "";

  const labelRe = /android:label\s*=\s*"([^"]+)"/g;
  let label = "";
  let lm;
  while ((lm = labelRe.exec(xml)) !== null) {
    label = lm[1];
  }

  return { packageName, permissions, label };
}

function isObfuscatedPackage(packageName) {
  if (!packageName) return false;
  const parts = packageName.split(".").filter(Boolean);
  return parts.some((p) => p.length === 1);
}

function uniquePerms(list) {
  const seen = new Set();
  const out = [];
  for (const raw of list || []) {
    const p = normalizePerm(raw);
    if (!p || seen.has(p)) continue;
    seen.add(p);
    out.push(p);
  }
  return out;
}

function emptyResult() {
  return {
    score: 0,
    level: "safe",
    host: "",
    category: "unknown",
    categoryLabel: CATEGORY_LABELS.unknown,
    features: [],
    explanation: []
  };
}

export function analyzeAPK(input) {
  if (input == null || input === "") return emptyResult();

  let packageName = "";
  let permissions = [];
  let category = "";
  let label = "";
  let obfuscated = null;

  if (typeof input === "string") {
    const parsed = parseManifestXml(input);
    packageName = parsed.packageName;
    permissions = parsed.permissions;
    label = parsed.label;
  } else if (typeof input === "object") {
    packageName = typeof input.packageName === "string" ? input.packageName : "";
    permissions = Array.isArray(input.permissions) ? input.permissions : [];
    category = typeof input.category === "string" ? input.category : "";
    label = typeof input.label === "string" ? input.label : "";
    if (typeof input.obfuscated === "boolean") obfuscated = input.obfuscated;
  } else {
    return emptyResult();
  }

  permissions = uniquePerms(permissions);
  const inferred = inferCategory(packageName, label);
  const catKey = EXPECTED_PERMISSIONS[category] ? category : inferred;
  const categoryLabel = CATEGORY_LABELS[catKey] || CATEGORY_LABELS.unknown;
  const expected = new Set(EXPECTED_PERMISSIONS[catKey] || []);
  const features = [];

  for (const perm of permissions) {
    const meta = SUSPICIOUS_PERMISSIONS[perm];
    if (!meta) continue;
    if (expected.has(perm)) continue;
    const prefix = catKey === "unknown" ? "App" : `${categoryLabel} app`;
    features.push({
      name: `permission-${perm}`,
      weight: meta.weight,
      detail: `${prefix} requests ${perm} — ${meta.detail}`
    });
  }

  if (packageName && SUSPICIOUS_TOKEN_RE.test(packageName)) {
    features.push({
      name: "suspicious-package-token",
      weight: 12,
      detail: "Package name contains suspicious token"
    });
  }

  const obfuscatedFlag = obfuscated === true || isObfuscatedPackage(packageName);
  if (obfuscatedFlag) {
    features.push({
      name: "obfuscated-package",
      weight: 10,
      detail: "Package name looks obfuscated (single-character segments)"
    });
  }

  const raw = features.reduce((sum, f) => sum + f.weight, 0);
  const score = 1 - Math.exp(-raw / 50);
  const ranked = [...features].sort((a, b) => b.weight - a.weight);
  const explanation = ranked.slice(0, 6).map((f) => f.detail);

  return {
    score,
    level: levelFromScore(score),
    host: packageName,
    category: catKey,
    categoryLabel,
    features,
    explanation
  };
}
