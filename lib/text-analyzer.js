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
    // English
    { re: /\bkyc\b/i, weight: 14, detail: "Mentions KYC verification" },
    { re: /account\s+(has\s+been\s+)?(suspended|blocked|frozen)/i, weight: 14, detail: "Claims an account is suspended, blocked, or frozen" },
    { re: /\b(update|verify)\s+(your\s+)?account\b/i, weight: 12, detail: "Asks to update or verify an account" },
    { re: /unauthorized\s+transaction/i, weight: 14, detail: "Warns of an unauthorized transaction" },
    { re: /\bcard\s+(has\s+been\s+)?blocked\b/i, weight: 12, detail: "Claims a card is blocked" },
    { re: /\bnet[\s-]?banking\b/i, weight: 12, detail: "Mentions net banking" },
    // NEW — Hinglish
    { re: /\b(khaata|khata|account)\b.{0,30}\b(band|block|suspend|freeze)\b/i, weight: 14, detail: "[Hinglish] Warns of account suspension or blocking" },
    { re: /\bkyc\s+(update|verify|complete)\s+(karein|karo|kijiye)\b/i, weight: 14, detail: "[Hinglish] Asks to update or verify KYC" },
    { re: /\bturant\b.{0,20}\b(verify|update|karein|karo)\b/i, weight: 12, detail: "[Hinglish] Urgent verification demand" },
    { re: /\b(bank|account)\b.{0,20}\b(band|suspend|block)\s+ho\s+jayega\b/i, weight: 14, detail: "[Hinglish] Account closure threat" },
    // NEW — Hindi (Devanagari)
    { re: /खाता.{0,20}(निलंबित|बंद|अवरुद्ध|ब्लॉक)/, weight: 14, detail: "[Hindi] Account suspension warning" },
    { re: /केवाईसी|KYC\s*(अपडेट|सत्यापन|पूरा)/, weight: 14, detail: "[Hindi] KYC update or verification" },
    { re: /तुरंत.{0,20}(सत्यापित|अपडेट|करें)/, weight: 12, detail: "[Hindi] Urgent verification demand" },
    { re: /बैंक.{0,20}(बंद|निलंबित|सस्पेंड)/, weight: 14, detail: "[Hindi] Bank account closure warning" }
  ],
  delivery: [
    // English
    { re: /\b(package|parcel|shipment)\b/i, weight: 10, detail: "Mentions a package, parcel, or shipment" },
    { re: /\bcustoms\s+(duty|fee|charges?)\b/i, weight: 14, detail: "Asks for a customs duty or fee" },
    { re: /\b(re-?delivery|redeliver)\b/i, weight: 12, detail: "Mentions redelivery" },
    { re: /\btracking\s+(number|#|id)\b/i, weight: 10, detail: "Mentions a tracking number" },
    { re: /\bunpaid\s+(fee|charge|duty|amount)\b/i, weight: 14, detail: "Claims an unpaid fee" },
    { re: /\b(dhl|fedex|ups|usps|bluedart|delhivery|dtdc|india\s*post)\b/i, weight: 10, detail: "Uses a courier brand name" },
    // NEW — Hinglish
    { re: /\b(parcel|package)\b.{0,30}\b(ruk|roka|held|hold)\b/i, weight: 12, detail: "[Hinglish] Package held or stuck" },
    { re: /\bcustoms\b.{0,20}\b(fees|duty|charge|bharni|bharna)\b/i, weight: 14, detail: "[Hinglish] Customs fee demand" },
    { re: /\bdelivery\b.{0,20}\b(ke liye|ke paid|karne ke liye).{0,20}\b(pay|payment|paisa|fees)\b/i, weight: 14, detail: "[Hinglish] Payment required for delivery" },
    // NEW — Hindi
    { re: /पार्सल.{0,20}(रुक|फंस|रोक)/, weight: 12, detail: "[Hindi] Package held or stuck" },
    { re: /कस्टम.{0,20}(शुल्क|फीस|चार्ज)/, weight: 14, detail: "[Hindi] Customs fee demand" },
    { re: /डिलीवरी.{0,20}(शुल्क|भुगतान|पैसे)/, weight: 14, detail: "[Hindi] Delivery payment required" }
  ],
  job: [
    // English
    { re: /\bwork\s+from\s+home\b/i, weight: 12, detail: "Offers work from home" },
    { re: /\bpart[\s-]?time\s+job\b/i, weight: 12, detail: "Offers a part-time job" },
    { re: /\bdata\s+entry\b/i, weight: 12, detail: "Mentions data entry work" },
    { re: /\bearn\s+.{0,20}\s*per\s+day\b/i, weight: 14, detail: "Promises earnings per day" },
    { re: /\bno\s+experience\s+required\b/i, weight: 10, detail: "Says no experience is required" },
    { re: /\bregistration\s+fee\b/i, weight: 14, detail: "Asks for a registration fee" },
    { re: /\bjoining\s+bonus\b/i, weight: 12, detail: "Promises a joining bonus" },
    // NEW — Hinglish
    { re: /\bghar\s+baithe\b.{0,30}\b(paise|kamayein|income|earn)\b/i, weight: 12, detail: "[Hinglish] Work-from-home earning offer" },
    { re: /\bdaily\s+(income|earning)\b.{0,20}\b(\d+|rupees|rs)/i, weight: 14, detail: "[Hinglish] Daily income promise" },
    { re: /\bregistration\s+(fees|fee|charge)\b.{0,20}\b(bharein|dena|pay)\b/i, weight: 14, detail: "[Hinglish] Registration fee demand" },
    { re: /\b(koi|no)\s+experience\s+(zaroori|required)\s+(nahi|nahin)\b/i, weight: 10, detail: "[Hinglish] No experience required" },
    // NEW — Hindi
    { re: /घर बैठे.{0,30}(पैसे|कमाई|कमाएं|आय)/, weight: 12, detail: "[Hindi] Work-from-home earning offer" },
    { re: /रोज.{0,20}(कमाई|आय|पैसे)/, weight: 14, detail: "[Hindi] Daily income promise" },
    { re: /रजिस्ट्रेशन.{0,20}(शुल्क|फीस|पैसे)/, weight: 14, detail: "[Hindi] Registration fee demand" }
  ],
  lottery: [
    // English
    { re: /\bcongratulations\b.{0,40}\b(you\s+)?won\b/i, weight: 16, detail: "Says congratulations, you won" },
    { re: /\b(lottery|lucky\s+draw|prize)\b/i, weight: 12, detail: "Mentions a lottery, lucky draw, or prize" },
    { re: /\bclaim\s+(your\s+)?prize\b/i, weight: 14, detail: "Asks to claim a prize" },
    { re: /\bwinner\b/i, weight: 10, detail: "Calls the reader a winner" },
    { re: /\bcashback\b/i, weight: 10, detail: "Mentions cashback" },
    { re: /\bclick\s+to\s+claim\b/i, weight: 14, detail: "Asks to click to claim" },
    // NEW — Hinglish
    { re: /\b(aapne|aap)\s+jeet\s+(liya|gaye|liye|lia)\b/i, weight: 16, detail: "[Hinglish] Says you have won" },
    { re: /\b(inam|prize|reward)\s+(claim|lena|le)\s+(karein|karo)\b/i, weight: 14, detail: "[Hinglish] Asks to claim prize" },
    { re: /\blucky\s+draw\b.{0,30}\b(jeeta|winner|jeet)\b/i, weight: 12, detail: "[Hinglish] Lucky draw winner claim" },
    { re: /\bcashback\s+(milega|paayein|payein|milega)\b/i, weight: 10, detail: "[Hinglish] Cashback offer" },
    // NEW — Hindi
    { re: /बधाई.{0,30}(जीत|जीते|इनाम|पुरस्कार)/, weight: 16, detail: "[Hindi] Congratulations, you won" },
    { re: /(इनाम|पुरस्कार|लॉटरी).{0,20}(दावा|ले|प्राप्त)/, weight: 14, detail: "[Hindi] Prize claim offer" },
    { re: /लकी ड्रॉ.{0,30}(विजेता|जीत)/, weight: 12, detail: "[Hindi] Lucky draw winner" }
  ],
  investment: [
    // English
    { re: /\b(invest(?:ing|ment)?|trading|forex|crypto|bitcoin)\b/i, weight: 12, detail: "Pushes investing, trading, forex, or crypto" },
    { re: /\bguaranteed\s+returns?\b/i, weight: 16, detail: "Promises guaranteed returns" },
    { re: /\brisk[\s-]?free\b/i, weight: 14, detail: "Claims the offer is risk-free" },
    { re: /\bdouble\s+your\s+money\b/i, weight: 16, detail: "Promises to double your money" },
    { re: /\bprofit\s*\d+\s*%/i, weight: 12, detail: "Advertises a profit percentage" },
    { re: /\btrading\s+signals?\b/i, weight: 12, detail: "Offers trading signals" },
    // NEW — Hinglish
    { re: /\b(paise|paisa|investment)\s+(double|doguna|do\s+guna)\b/i, weight: 16, detail: "[Hinglish] Promises to double money" },
    { re: /\bguaranteed\s+(return|profit|munafa)\b/i, weight: 16, detail: "[Hinglish] Guaranteed returns promise" },
    { re: /\b(risk[\s-]?free|bina\s+risk)\b.{0,20}\b(invest|profit|trading)\b/i, weight: 14, detail: "[Hinglish] Risk-free investment claim" },
    { re: /\bcrypto\s+(mein|me)\s+(invest|trading|paise)\b/i, weight: 12, detail: "[Hinglish] Crypto investment push" },
    { re: /\btrading\s+(signals|tips)\s+(group|channel|vip)\b/i, weight: 12, detail: "[Hinglish] Trading signals group offer" },
    // NEW — Hindi
    { re: /(पैसे|निवेश).{0,20}(डबल|दोगुना)/, weight: 16, detail: "[Hindi] Money doubling promise" },
    { re: /गारंटीड.{0,20}(रिटर्न|मुनाफा|लाभ)/, weight: 16, detail: "[Hindi] Guaranteed returns promise" },
    { re: /बिना.{0,10}(जोखिम|रिस्क).{0,20}(निवेश|मुनाफा|ट्रेडिंग)/, weight: 14, detail: "[Hindi] Risk-free investment claim" },
    { re: /क्रिप्टो.{0,20}(निवेश|ट्रेडिंग|पैसे)/, weight: 12, detail: "[Hindi] Crypto investment push" }
  ],
  otp: [
    // English
    { re: /\b(otp|one[\s-]?time\s+password|verification\s+code)\b/i, weight: 14, detail: "Mentions an OTP or verification code" },
    { re: /\b(share|send|provide)\s+(your\s+)?(otp|one[\s-]?time\s+password|code)\b/i, weight: 18, detail: "Asks to share, send, or provide an OTP" },
    { re: /\b(read|forward)\s+(the\s+)?otp\b/i, weight: 16, detail: "Asks to read or forward an OTP" },
    { re: /\b(cvv|card\s+number|atm\s+pin)\b/i, weight: 16, detail: "Asks for CVV, card number, or ATM PIN" },
    // NEW — Hinglish
    { re: /\botp\s+(share|bhejein|bhejo|batayein|bataye|batao)\b/i, weight: 18, detail: "[Hinglish] Asks to share OTP" },
    { re: /\b(verification|security)\s+code\s+(share|bhejein|batayein)\b/i, weight: 16, detail: "[Hinglish] Asks to share verification code" },
    { re: /\b(cvv|atm\s+pin|card\s+number)\s+(batayein|share|bhejein|daalein)\b/i, weight: 16, detail: "[Hinglish] Asks for card details or PIN" },
    { re: /\botp\s+(kisi\s+ko|kisiko)\s+(na|mat)\s+(batayein|share)\b/i, weight: 0, detail: "" }, // negated safety line — ignored
    // NEW — Hindi
    { re: /(ओटीपी|OTP).{0,20}(शेयर|भेजें|बताएं|बताइए)/, weight: 18, detail: "[Hindi] Asks to share OTP" },
    { re: /(सत्यापन|सुरक्षा)\s*(कोड|कॉड).{0,20}(भेजें|शेयर|बताएं)/, weight: 16, detail: "[Hindi] Asks to share verification code" },
    { re: /(सीवीवी|सीवीवी|पिन|कार्ड नंबर).{0,20}(बताएं|शेयर|भेजें)/, weight: 16, detail: "[Hindi] Asks for card details or PIN" }
  ]
};

const URGENCY = [
  // English
  { re: /\bimmediate(?:ly)?\b/i, label: "immediate" },
  { re: /\burgent\b/i, label: "urgent" },
  { re: /\basap\b/i, label: "asap" },
  { re: /\bfinal\s+notice\b/i, label: "final notice" },
  { re: /\baction\s+required\b/i, label: "action required" },
  { re: /\bexpires?\s+today\b/i, label: "expires today" },
  { re: /\bwithin\s+24\s+hours\b/i, label: "within 24 hours" },
  { re: /\blast\s+chance\b/i, label: "last chance" },
  { re: /\bact\s+now\b/i, label: "act now" },
  // NEW — Hinglish
  { re: /\bturant\b/i, label: "turant (immediately)" },
  { re: /\bjaldi\b/i, label: "jaldi (quickly)" },
  { re: /\bforan\b/i, label: "foran (immediately)" },
  { re: /\babhi\b.{0,10}\b(karein|karo|bhejein)\b/i, label: "abhi (right now)" },
  { re: /\b24\s+ghante\s+(mein|me)\b/i, label: "24 ghante mein (within 24 hours)" },
  { re: /\bakhir\s+mauka\b/i, label: "akhir mauka (last chance)" },
  // NEW — Hindi
  { re: /तुरंत/, label: "तुरंत (immediately)" },
  { re: /जल्दी/, label: "जल्दी (quickly)" },
  { re: /अभी.{0,10}(करें|करो|भेजें)/, label: "अभी (right now)" },
  { re: /24\s*घंटे.{0,10}(में|भीतर)/, label: "24 घंटे में (within 24 hours)" },
  { re: /आखिरी\s*(मौका|अवसर)/, label: "आखिरी मौका (last chance)" }
];

const SENSITIVE = [
  // English
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
  { re: /\bupi\b/i, label: "upi" },
  // NEW — Hinglish
  { re: /\b(pin|password|pasword)\s+(batayein|share|bhejein|daalein)\b/i, label: "[Hinglish] password/PIN request" },
  { re: /\baadhaar\s+(number|no|details)\s+(share|bhejein|daalein)\b/i, label: "[Hinglish] Aadhaar request" },
  { re: /\baccount\s+(number|no)\s+(share|bhejein|batayein)\b/i, label: "[Hinglish] Account number request" },
  // NEW — Hindi
  { re: /(पासवर्ड|पिन|सीवीवी).{0,20}(बताएं|शेयर|भेजें|डालें)/, label: "[Hindi] Password or PIN request" },
  { re: /आधार.{0,20}(नंबर|संख्या|विवरण).{0,20}(शेयर|भेजें|बताएं)/, label: "[Hindi] Aadhaar request" },
  { re: /खाता\s*(संख्या|नंबर).{0,20}(शेयर|भेजें|बताएं)/, label: "[Hindi] Account number request" }
];

const URL_RE = /https?:\/\/[^\s<>"'`]+|www\.[^\s<>"'`]+/gi;

// Safety warnings that legit senders include. Strip them so the detector
// doesn't treat "Never share your OTP" as a request to share it.
// Includes Hinglish and Hindi variants.
const SAFETY_WARNING_RE = /\b(never|do\s+not|don'?t|avoid)\s+(share|send|provide|give|tell|reveal|disclose|hand\s+over)[^.!?\n]{0,120}/gi;
const SAFETY_WARNING_HINGLISH_RE = /\b(kisi\s+ko\s+na|kisiko\s+na|kabhi\s+na|na\s+share|mat\s+share|na\s+batayein)\b[^.!?\n]{0,120}/gi;
const SAFETY_WARNING_HINDI_RE = /(किसी\s+को\s+न|कभी\s+न|न\s+शेयर|शेयर\s+न\s+करें|न\s+बताएं)[^।.!?\n]{0,120}/g;

// Advisory clauses — "please note", "for your safety" — strip as well
const ADVISORY_CLAUSE_RE = /\b(please\s+note|remember|for\s+your\s+safety|security\s+reminder|beware\s+of)\b[^.!?\n]{0,160}/gi;
const ADVISORY_CLAUSE_HINGLISH_RE = /\b(dhyan\s+dein|yaad\s+rakhein|savdhani|suchna)\b[^.!?\n]{0,160}/gi;

function levelFromScore(score) {
  if (score > 0.6) return "dangerous";
  if (score >= 0.3) return "suspicious";
  return "safe";
}

function sanitize(text) {
  return text
    .replace(SAFETY_WARNING_RE, " ")
    .replace(SAFETY_WARNING_HINGLISH_RE, " ")
    .replace(SAFETY_WARNING_HINDI_RE, " ")
    .replace(ADVISORY_CLAUSE_RE, " ")
    .replace(ADVISORY_CLAUSE_HINGLISH_RE, " ");
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

  // URL extraction runs on ORIGINAL text
  const seenUrls = new Set();
  const matches = text.match(URL_RE) || [];
  for (const raw of matches) {
    const cleaned = raw.replace(/[),.;:!?]+$/, "");
    if (!seenUrls.has(cleaned)) {
      seenUrls.add(cleaned);
      urls.push(cleaned);
    }
  }

  // Pattern matching runs on sanitized text
  const s = sanitize(text);

  for (const [key, patterns] of Object.entries(CATEGORY_PATTERNS)) {
    for (const p of patterns) {
      // Skip the "negated safety" placeholder pattern (weight 0)
      if (p.weight === 0) continue;
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
        detail: `Urgency language: "${u.label}"`
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