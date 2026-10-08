const CATEGORY_META = {
  bank: { label: "Bank / KYC / Account Scam" },
  delivery: { label: "Delivery / Package Scam" },
  job: { label: "Job Scam" },
  lottery: { label: "Lottery Scam" },
  investment: { label: "Investment Scam" },
  otp: { label: "OTP Theft" }
};

const CATEGORY_PATTERNS = {
  bank: [
    { re: /\bkyc\b/i, weight: 14, detail: "Mentions KYC verification" },
    { re: /account\s+(has\s+been\s+)?(suspended|blocked|frozen)/i, weight: 14, detail: "Claims an account is suspended, blocked, or frozen" },
    { re: /\b(update|verify)\s+(your\s+)?account\b/i, weight: 12, detail: "Asks to update or verify an account" },
    { re: /unauthorized\s+transaction/i, weight: 14, detail: "Warns of an unauthorized transaction" },
    { re: /\bcard\s+(has\s+been\s+)?blocked\b/i, weight: 12, detail: "Claims a card is blocked" },
    { re: /\bnet[\s-]?banking\b/i, weight: 12, detail: "Mentions net banking" }
  ],
  delivery: [
    { re: /\b(package|parcel|shipment)\b/i, weight: 10, detail: "Mentions a package, parcel, or shipment" },
    { re: /\bcustoms\s+(duty|fee|charges?)\b/i, weight: 14, detail: "Asks for a customs duty or fee" },
    { re: /\b(re-?delivery|redeliver)\b/i, weight: 12, detail: "Mentions redelivery" },
    { re: /\btracking\s+(number|#|id)\b/i, weight: 10, detail: "Mentions a tracking number" },
    { re: /\bunpaid\s+(fee|charge|duty|amount)\b/i, weight: 14, detail: "Claims an unpaid fee" },
    { re: /\b(dhl|fedex|ups|usps|bluedart|delhivery|dtdc|india\s*post)\b/i, weight: 10, detail: "Uses a courier brand name" }
  ],
  job: [
    { re: /\bwork\s+from\s+home\b/i, weight: 12, detail: "Offers work from home" },
    { re: /\bpart[\s-]?time\s+job\b/i, weight: 12, detail: "Offers a part-time job" },
    { re: /\bdata\s+entry\b/i, weight: 12, detail: "Mentions data entry work" },
    { re: /\bearn\s+.{0,20}\s*per\s+day\b/i, weight: 14, detail: "Promises earnings per day" },
    { re: /\bno\s+experience\s+required\b/i, weight: 10, detail: "Says no experience is required" },
    { re: /\bregistration\s+fee\b/i, weight: 14, detail: "Asks for a registration fee" },
    { re: /\bjoining\s+bonus\b/i, weight: 12, detail: "Promises a joining bonus" }
  ],
  lottery: [
    { re: /\bcongratulations\b.{0,40}\b(you\s+)?won\b/i, weight: 16, detail: "Says congratulations, you won" },
    { re: /\b(lottery|lucky\s+draw|prize)\b/i, weight: 12, detail: "Mentions a lottery, lucky draw, or prize" },
    { re: /\bclaim\s+(your\s+)?prize\b/i, weight: 14, detail: "Asks to claim a prize" },
    { re: /\bwinner\b/i, weight: 10, detail: "Calls the reader a winner" },
    { re: /\bcashback\b/i, weight: 10, detail: "Mentions cashback" },
    { re: /\bclick\s+to\s+claim\b/i, weight: 14, detail: "Asks to click to claim" }
  ],
  investment: [
    { re: /\b(invest(?:ing|ment)?|trading|forex|crypto|bitcoin)\b/i, weight: 12, detail: "Pushes investing, trading, forex, or crypto" },
    { re: /\bguaranteed\s+returns?\b/i, weight: 16, detail: "Promises guaranteed returns" },
    { re: /\brisk[\s-]?free\b/i, weight: 14, detail: "Claims the offer is risk-free" },
    { re: /\bdouble\s+your\s+money\b/i, weight: 16, detail: "Promises to double your money" },
    { re: /\bprofit\s*\d+\s*%/i, weight: 12, detail: "Advertises a profit percentage" },
    { re: /\btrading\s+signals?\b/i, weight: 12, detail: "Offers trading signals" }
  ],
  otp: [
    { re: /\b(otp|one[\s-]?time\s+password|verification\s+code)\b/i, weight: 14, detail: "Mentions an OTP or verification code" },
    { re: /\b(share|send|provide)\s+(your\s+)?(otp|one[\s-]?time\s+password|code)\b/i, weight: 18, detail: "Asks to share, send, or provide an OTP" },
    { re: /\b(read|forward)\s+(the\s+)?otp\b/i, weight: 16, detail: "Asks to read or forward an OTP" },
    { re: /\b(cvv|card\s+number|atm\s+pin)\b/i, weight: 16, detail: "Asks for CVV, card number, or ATM PIN" }
  ]
};

const URGENCY = [
  { re: /\bimmediate(?:ly)?\b/i, label: "immediate" },
  { re: /\burgent\b/i, label: "urgent" },
  { re: /\basap\b/i, label: "asap" },
  { re: /\bfinal\s+notice\b/i, label: "final notice" },
  { re: /\baction\s+required\b/i, label: "action required" },
  { re: /\bexpires?\s+today\b/i, label: "expires today" },
  { re: /\bwithin\s+24\s+hours\b/i, label: "within 24 hours" },
  { re: /\blast\s+chance\b/i, label: "last chance" },
  { re: /\bact\s+now\b/i, label: "act now" }
];

const SENSITIVE = [
  { re: /\bpassword\b/i, label: "password" },
  { re: /\botp\b/i, label: "otp" },
  { re: /\bpin\b/i, label: "pin" },
  { re: /\bcvv\b/i, label: "cvv" },
  { re: /\bcard\s+number\b/i, label: "card number" },
  { re: /\baadhaar\b/i, label: "aadhaar" },
  { re: /\bpan\b/i, label: "pan" },
  { re: /\bssn\b/i, label: "ssn" },
  { re: /\baccount\s+number\b/i, label: "account number" },
  { re: /\bnet[\s-]?banking\b/i, label: "net banking" },
  { re: /\bupi\b/i, label: "upi" }
];

const URL_RE = /https?:\/\/[^\s<>"'`]+|www\.[^\s<>"'`]+/gi;

// Safety warnings that legit senders include. Strip them so the detector
// doesn't treat "Never share your OTP" as a request to share it.
const SAFETY_WARNING_RE = /\b(never|do\s+not|don'?t|avoid)\s+(share|send|provide|give|tell|reveal|disclose|disclose|hand\s+over)[^.!?\n]{0,120}/gi;

// Secondary guard: strip common advisory clauses starting with these
const ADVISORY_CLAUSE_RE = /\b(please\s+note|remember|for\s+your\s+safety|security\s+reminder|beware\s+of)\b[^.!?\n]{0,160}/gi;

function levelFromScore(score) {
  if (score > 0.6) return "dangerous";
  if (score >= 0.3) return "suspicious";
  return "safe";
}

function sanitize(text) {
  return text
    .replace(SAFETY_WARNING_RE, " ")
    .replace(ADVISORY_CLAUSE_RE, " ");
}

export function analyzeText(text) {
  const features = [];
  const urls = [];
  const categoryScores = {
    bank: 0,
    delivery: 0,
    job: 0,
    lottery: 0,
    investment: 0,
    otp: 0
  };

  if (!text || typeof text !== "string") {
    return { score: 0, level: "safe", category: null, categoryLabel: null, features, urls };
  }

  // URL extraction runs on the ORIGINAL text so URLs embedded in
  // warnings still get picked up.
  const seenUrls = new Set();
  const matches = text.match(URL_RE) || [];
  for (const raw of matches) {
    const cleaned = raw.replace(/[),.;:!?]+$/, "");
    if (!seenUrls.has(cleaned)) {
      seenUrls.add(cleaned);
      urls.push(cleaned);
    }
  }

  // All pattern matching runs against sanitized text.
  const s = sanitize(text);

  for (const [key, patterns] of Object.entries(CATEGORY_PATTERNS)) {
    for (const p of patterns) {
      if (p.re.test(s)) {
        categoryScores[key] += p.weight;
        features.push({
          name: `category-${key}`,
          weight: p.weight,
          detail: p.detail
        });
      }
    }
  }

  for (const u of URGENCY) {
    if (u.re.test(s)) {
      features.push({
        name: "urgency",
        weight: 8,
        detail: `Urgency language: “${u.label}”`
      });
    }
  }

  for (const sens of SENSITIVE) {
    if (sens.re.test(s)) {
      features.push({
        name: "sensitive-info",
        weight: 12,
        detail: `Asks for sensitive information: ${sens.label}`
      });
    }
  }

  const capsWords = s.match(/\b[A-Z]{2,}\b/g) || [];
  if (capsWords.length >= 2) {
    features.push({
      name: "all-caps",
      weight: 6,
      detail: `Uses ${capsWords.length} ALL CAPS words`
    });
  }

  const bangQ = (s.match(/[!?]/g) || []).length;
  if (bangQ >= 2) {
    features.push({
      name: "punctuation",
      weight: 4,
      detail: "Uses multiple exclamation or question marks"
    });
  }

  let topCat = null;
  let topScore = 0;
  for (const [key, sc] of Object.entries(categoryScores)) {
    if (sc > topScore) {
      topScore = sc;
      topCat = key;
    }
  }

  const category = topScore >= 10 ? topCat : null;
  const categoryLabel = category ? CATEGORY_META[category].label : null;

  const raw = features.reduce((sum, f) => sum + f.weight, 0);
  const score = 1 - Math.exp(-raw / 50);

  return {
    score,
    level: levelFromScore(score),
    category,
    categoryLabel,
    features,
    urls
  };
}