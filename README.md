# Kavach

> On-device phishing and scam detection engine. One engine, every surface where scams live.

**Kavach** (Hindi: *armour*) is a security engine that scores URLs, message text, and Android app manifests for scam signals — and returns an explainable verdict. Every flag shows the feature, the weight, and a plain-language reason. Nothing leaves the device.

## What it catches

| Input              | Analyzer                               | Catches                                                                               |
| ------------------ | -------------------------------------- | ------------------------------------------------------------------------------------- |
| URL + page content | `url-analyzer.js` + `text-analyzer.js` | Phishing pages, KYC fraud, delivery scams, lottery scams, investment fraud, OTP theft |
| Android APK        | `apk-analyzer.js`                      | Malicious apps requesting permissions they don't need                                 |

## How it works

```text
URL / Message / APK
        ↓
    Analyzer
        ↓
  Fusion Layer
        ↓
Verdict + Reasons
```

1. **URL Analyzer** — 11 signals across domain reputation, URL structure, and semantic patterns
2. **Text Analyzer** — 6 scam categories + cross-cutting signals (urgency, sensitive-info requests)
3. **APK Analyzer** — reads Android manifest permissions and flags category-inconsistent requests
4. **Fusion Layer** — combines scores with weighted averaging and asymptotic cap
5. **Explainability** — every flag returns a human-readable reason with its weight

## Surfaces

* **Browser extension** (Chrome Manifest V3) — runs on every page, warns before user interaction
* **APK manifest analyzer** — standalone HTML demo, parses real `.apk` files entirely in-browser
* **Roadmap** — Android NotificationListenerService, iOS SMS Filter, federated rule updates

## Tech stack

* Plain JavaScript (ES modules), no build step, no bundler
* Chrome Manifest V3
* JSZip for in-browser APK parsing
* `chrome.storage.local` for trust list and report log
* Total extension size: under 20 KB

## Setup

### 1. Clone this repository

```bash
git clone https://github.com/yourusername/kavach.git
cd kavach
```

### 2. Load the extension

Open:

```text
brave://extensions
```

or:

```text
chrome://extensions
```

Then:

1. Enable **Developer mode**
2. Click **Load unpacked**
3. Select the `kavach` folder

### 3. Test with demo pages

Open any file in the `demos/` folder in the browser.

The overlay fires on scam pages and stays silent on the safe page.

### 4. Test with a real APK

Open:

```text
apk-demo.html
```

Drag any `.apk` file onto the drop zone.

Kavach parses the manifest in-browser and scores the permissions.

## Trust and false-positive reporting

* **Trust this site** — click in the popup after a verdict; the hostname is stored locally and skipped on future visits
* **Report false positive** — stored locally in `chrome.storage.local`
* Clear both lists from the extension's service worker console:

```js
chrome.storage.local.set({
  trustedDomains: [],
  reportedFalsePositives: []
});
```

## Privacy

* All analysis runs on the user's device
* No network calls during detection
* No telemetry, no tracking, no analytics
* Trust list and reports stay in `chrome.storage.local`

## Project structure

```text
kavach/
├── manifest.json                 # MV3 extension manifest
├── background.js                 # Service worker — analysis orchestrator
├── content.js                    # Page scanner + overlay renderer
├── content.css                   # Overlay styles
├── popup.html                    # Extension popup UI
├── popup.css                     # Popup styles
├── popup.js                      # Popup logic — verdict breakdown
├── test.html                     # Basic overlay test page
├── apk-demo.html                 # Standalone APK analyzer
│
├── lib/
│   ├── url-analyzer.js           # 11 URL signals (weighted)
│   ├── text-analyzer.js          # 6 scam categories + urgency detection
│   ├── apk-analyzer.js           # Android manifest permission scoring
│   ├── fusion.js                 # Weighted combination → verdict
│   └── jszip.min.js              # APK unzipping (bundled locally)
│
├── demos/
│   ├── safe-bank.html            # Legitimate bank page — no overlay
│   ├── scam-bank-kyc.html        # Bank / KYC scam
│   ├── scam-lottery.html          # Lottery / prize scam
│   ├── scam-delivery.html         # Delivery / customs fee scam
│   └── scam-investment.html       # Investment / crypto scam
│
├── icons/
│   └── icon128.png               # Extension icon
│
└── Screenshots/
    ├── demo-01-dangerous-overlay.png
    ├── demo-02-dangerous-overlay-alt.png
    ├── demo-03-suspicious-overlay.png
    ├── demo-04-archive-old-version.png
    └── demo-05-popup-dangerous.png
```

## Why Kavach?

Traditional security tools say:

> Warning.

Kavach answers the question that matters:

**"Why is this dangerous?"**

```text
DANGEROUS — Risk score 91/100

• Suspicious domain structure
• Bank impersonation detected
• Urgent KYC language detected
• Request for sensitive information
```

## Roadmap

### Phase 1 — During hackathon

* UI polish: explainability score bar, risk history log

### Phase 2 — Right after

* Hinglish + Hindi scam patterns
* WhatsApp/SMS link scanner
* APK network-permission scanning
* QR code decoding
* Fake CAPTCHA detection

### Phase 3 — Long-term vision

* Native Android app — PackageManager auto-scan
* iOS SMS Filter extension
* Opt-in cloud threat-intel, signed rule updates
* Federated learning + local API for third-party tools

## Team

**DEADSEC** — Code Carnival 3.0 · Atmiya University

* Neeraj Mv
* Subham Palai
* Srikar Vaila
* Mani Sharma

## License

MIT
