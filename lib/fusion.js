import { analyzeURL } from "./url-analyzer.js";
import { analyzeText } from "./text-analyzer.js";

function levelFromScore(score) {
  if (score > 0.6) return "dangerous";
  if (score >= 0.3) return "suspicious";
  return "safe";
}

function hasData(value) {
  return typeof value === "string" && value.trim().length > 0;
}

export function analyze({ text, url } = {}) {
  const textOk = hasData(text);
  const urlOk = hasData(url);

  const textResult = textOk ? analyzeText(text) : null;
  let urlToUse = urlOk ? url.trim() : null;

  if (!urlToUse && textResult && textResult.urls.length > 0) {
    urlToUse = textResult.urls[0];
  }

  const urlResult = urlToUse ? analyzeURL(urlToUse) : null;

  let finalScore = 0;
  if (textResult && urlResult) {
    finalScore = textResult.score * 0.55 + urlResult.score * 0.45;
  } else if (textResult) {
    finalScore = textResult.score;
  } else if (urlResult) {
    finalScore = urlResult.score;
  }
  finalScore = Math.min(1, finalScore);

  const merged = [
    ...(textResult?.features || []),
    ...(urlResult?.features || [])
  ].sort((a, b) => b.weight - a.weight);

  const explanation = [];
  const seen = new Set();
  for (const f of merged) {
    if (!f.detail || seen.has(f.detail)) continue;
    seen.add(f.detail);
    explanation.push(f.detail);
    if (explanation.length >= 8) break;
  }

  return {
    score: finalScore,
    level: levelFromScore(finalScore),
    category: textResult?.category ?? null,
    categoryLabel: textResult?.categoryLabel ?? null,
    explanation,
    text: textResult,
    url: urlResult,
    host: urlResult?.host ?? null
  };
}
