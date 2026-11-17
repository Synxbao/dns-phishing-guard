// Warning history and aggregate scan statistics.

import { sanitizeUrlForHistory } from "./url-privacy.js";

const HISTORY_KEY = "scan_history";
const STATS_KEY = "scan_stats";
const HISTORY_MAX_ITEMS = 500;

const DEFAULT_STATS = {
  totalScans: 0,
  safe: 0,
  suspicious: 0,
  medium: 0,
  high: 0,
  dynamicRescans: 0,
  rdapAvailable: 0,
  rdapUnavailable: 0,
  rdapCacheHits: 0,
  resultCacheHits: 0,
  resultCacheMisses: 0,
  contentWarnings: 0,
  scamCommerceWarnings: 0,
  gameCommerceWarnings: 0,
  gamblingWarnings: 0,
  adultWarnings: 0,
  personalDataWarnings: 0,
  malwareWarnings: 0,
  identityAbuseWarnings: 0,
  deepfakeWarnings: 0,
  financialSchemeWarnings: 0,
  warningsShown: 0,
  blocks: 0,
  bypasses: 0,
  falsePositiveReports: 0,
  scanDurationSamples: [],
  scanAverageMs: 0,
  scanP95Ms: 0,
  lastScanAt: null
};

const STAT_EVENT_KEYS = new Set(["blocks", "bypasses", "falsePositiveReports"]);

function updateDurationStats(stats, durationMs) {
  if (durationMs === null || typeof durationMs === "undefined" || durationMs === "") return;
  const duration = Math.max(0, Math.min(60000, Number(durationMs)));
  if (!Number.isFinite(duration)) return;
  const samples = [...(Array.isArray(stats.scanDurationSamples) ? stats.scanDurationSamples : []), duration]
    .slice(-120)
    .sort((a, b) => a - b);
  stats.scanDurationSamples = samples;
  stats.scanAverageMs = Math.round(samples.reduce((sum, value) => sum + value, 0) / samples.length);
  stats.scanP95Ms = Math.round(samples[Math.max(0, Math.ceil(samples.length * 0.95) - 1)] || 0);
}

async function getSettings() {
  const data = await chrome.storage.local.get(["saveHistory"]);
  return { saveHistory: data.saveHistory !== false };
}

async function addHistoryEntry(entry) {
  const { saveHistory } = await getSettings();
  if (!saveHistory || (entry.risk.level === "SAFE" && !entry.contentSafety?.detected)) return;

  const data = await chrome.storage.local.get(HISTORY_KEY);
  let history = data[HISTORY_KEY] || [];
  const now = Date.now();

  const duplicate = history.find(item =>
    item.domain === entry.domain &&
    item.score === entry.risk.score &&
    now - new Date(item.checkedAt).getTime() < 60000
  );
  if (duplicate) return;

  history.unshift({
    domain: entry.domain,
    registrableDomain: entry.registrableDomain || entry.domain,
    url: sanitizeUrlForHistory(entry.url),
    score: entry.risk.score,
    confidenceScore: entry.risk.confidenceScore,
    confidenceLevel: entry.risk.confidenceLevel,
    level: entry.risk.level,
    reasons: entry.risk.reasons,
    recommendations: entry.risk.recommendations,
    breakdown: entry.risk.breakdown,
    siteContext: entry.siteContext?.type || entry.risk.siteContext?.type || "PUBLIC_WEB",
    identityStatus: entry.risk.identityStatus?.label || "",
    ageDays: entry.ageInfo?.ageDays ?? null,
    isPunycode: Boolean(entry.homoglyphInfo?.isPunycode),
    hasHomoglyph: Boolean(entry.homoglyphInfo?.hasHomoglyph),
    redirectCount: Math.max(0, (entry.redirectInfo?.hopCount || 1) - 1),
    threatSource: entry.threatInfo?.source || "",
    threatUnsafe: Boolean(entry.threatInfo?.isUnsafe),
    contentSafetyScore: entry.contentSafety?.score || 0,
    contentSafetyLevel: entry.contentSafety?.level || "NONE",
    contentCategories: (entry.contentSafety?.categories || []).map(item => item.id),
    contentReasons: entry.contentSafety?.reasons || [],
    evidenceStatus: entry.evidenceAssessment?.status || "",
    riskState: entry.evidenceAssessment?.riskState || "",
    checkedAt: entry.checkedAt
  });

  history = history.slice(0, HISTORY_MAX_ITEMS);
  await chrome.storage.local.set({ [HISTORY_KEY]: history });
}

async function getHistory() {
  const data = await chrome.storage.local.get(HISTORY_KEY);
  return data[HISTORY_KEY] || [];
}

async function clearHistory() {
  await chrome.storage.local.set({ [HISTORY_KEY]: [] });
}

async function updateStats({
  level,
  dynamic = false,
  rdapAvailable,
  rdapCacheHit = false,
  resultCacheHit = false,
  contentSafety = null,
  warningShown = false,
  scanDurationMs = null
}) {
  const data = await chrome.storage.local.get(STATS_KEY);
  const stats = { ...DEFAULT_STATS, ...(data[STATS_KEY] || {}) };
  updateDurationStats(stats, scanDurationMs);

  if (dynamic) {
    stats.dynamicRescans += 1;
  } else {
    stats.totalScans += 1;
    if (level === "HIGH") stats.high += 1;
    else if (level === "MEDIUM") stats.medium += 1;
    else if (level === "SUSPICIOUS") stats.suspicious += 1;
    else stats.safe += 1;
    if (warningShown) stats.warningsShown += 1;

    if (rdapAvailable === true) stats.rdapAvailable += 1;
    if (rdapAvailable === false) stats.rdapUnavailable += 1;
    if (rdapCacheHit) stats.rdapCacheHits += 1;
    if (resultCacheHit) stats.resultCacheHits += 1;
    else stats.resultCacheMisses += 1;

    if (contentSafety?.detected) {
      stats.contentWarnings += 1;
      const ids = new Set((contentSafety.categories || []).map(item => item.id));
      if (ids.has("SCAM_COMMERCE")) stats.scamCommerceWarnings += 1;
      if (ids.has("GAME_COMMERCE")) stats.gameCommerceWarnings += 1;
      if (ids.has("GAMBLING")) stats.gamblingWarnings += 1;
      if (ids.has("ADULT")) stats.adultWarnings += 1;
      if (ids.has("PERSONAL_DATA")) stats.personalDataWarnings += 1;
      if (ids.has("MALWARE")) stats.malwareWarnings += 1;
      if (ids.has("IDENTITY_ABUSE")) stats.identityAbuseWarnings += 1;
      if (ids.has("DEEPFAKE")) stats.deepfakeWarnings += 1;
      if (ids.has("FINANCIAL_SCHEME")) stats.financialSchemeWarnings += 1;
    }
  }
  stats.lastScanAt = new Date().toISOString();

  await chrome.storage.local.set({ [STATS_KEY]: stats });
  return stats;
}

async function recordSecurityEvent(eventName) {
  if (!STAT_EVENT_KEYS.has(eventName)) return null;
  const data = await chrome.storage.local.get(STATS_KEY);
  const stats = { ...DEFAULT_STATS, ...(data[STATS_KEY] || {}) };
  stats[eventName] = (Number(stats[eventName]) || 0) + 1;
  stats.lastScanAt = stats.lastScanAt || new Date().toISOString();
  await chrome.storage.local.set({ [STATS_KEY]: stats });
  return stats;
}

async function getStats() {
  const data = await chrome.storage.local.get(STATS_KEY);
  return { ...DEFAULT_STATS, ...(data[STATS_KEY] || {}) };
}

async function clearStats() {
  await chrome.storage.local.set({ [STATS_KEY]: { ...DEFAULT_STATS } });
}

function csvCell(value) {
  const text = value == null ? "" : String(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function historyToCSV(history) {
  const headers = [
    "Thời gian",
    "Hostname",
    "Domain đăng ký",
    "URL",
    "Điểm rủi ro",
    "Mức độ",
    "Chất lượng bằng chứng",
    "Ngữ cảnh site",
    "Nhận diện domain",
    "Tuổi domain (ngày)",
    "Punycode",
    "Homoglyph",
    "Số redirect",
    "Threat Intel",
    "Điểm an toàn nội dung",
    "Danh mục nội dung",
    "Lý do"
  ];

  const rows = history.map(item => [
    item.checkedAt,
    item.domain,
    item.registrableDomain || item.domain,
    item.url,
    item.score,
    item.level,
    `${item.confidenceScore ?? ""} ${item.confidenceLevel ?? ""}`.trim(),
    item.siteContext || "PUBLIC_WEB",
    item.identityStatus || "",
    item.ageDays ?? "N/A",
    item.isPunycode ? "Có" : "Không",
    item.hasHomoglyph ? "Có" : "Không",
    item.redirectCount || 0,
    item.threatUnsafe ? `Nguy hiểm (${item.threatSource || "nguồn ngoài"})` : (item.threatSource || "Không kiểm tra"),
    item.contentSafetyScore || 0,
    (item.contentCategories || []).join(" | "),
    [...(item.reasons || []), ...(item.contentReasons || [])].join(" | ")
  ]);

  return [headers, ...rows]
    .map(row => row.map(csvCell).join(","))
    .join("\n");
}

export {
  HISTORY_KEY,
  STATS_KEY,
  addHistoryEntry,
  getHistory,
  clearHistory,
  updateStats,
  getStats,
  clearStats,
  recordSecurityEvent,
  historyToCSV
};
