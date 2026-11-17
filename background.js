import { analyzeHomoglyph } from "./modules/homoglyph.js";
import { calculateRisk } from "./modules/risk-engine.js";
import { checkDomainAge } from "./modules/rdap.js";
import { findSimilarDomain } from "./modules/typosquat.js";
import { addHistoryEntry, updateStats, recordSecurityEvent } from "./modules/history.js";
import { checkThreatIntel } from "./modules/threat-intel.js";
import { predictUrlRisk } from "./modules/url-model.js";
import { analyzeContentSafety, CATEGORY_META } from "./modules/content-safety.js";
import { buildEvidenceAssessment } from "./modules/evidence-coverage.js";
import { analyzeFederatedAuthRedirect } from "./modules/auth-flow.js";
import { classifySiteContext } from "./modules/site-context.js";
import {
  MAX_REDIRECTS,
  MAX_RESPONSE_BYTES,
  PROBE_TIMEOUT_MS,
  buildPreflightVerdict,
  normalizeLinkLabUrl,
  probeUrlNetwork,
  redactUrl
} from "./modules/link-lab.js";
import {
  loadPublicSuffixList,
  getDomainParts
} from "./modules/public-suffix.js";
import {
  syncBlockedDomains,
  allowDomainOnce,
  enableStrictMode,
  disableStrictMode,
  isStrictModeEnabled,
  enableSafePreviewMode,
  cleanupTabRules,
  consumeAllowDomainOnce
} from "./modules/blocking.js";
import {
  setParentPin,
  unlockParent,
  isParentUnlocked,
  getParentState,
  lockParent,
  clearParentPin
} from "./modules/parent-control.js";
import {
  normalizeDomain,
  loadAllLists,
  ensureListsLoaded,
  getKnownDomains,
  getProtectedTyposquatDomains,
  getTyposquatReferenceDomains,
  getBlacklist,
  isBlacklisted,
  isWhitelisted,
  addToWhitelist,
  addToBlacklist
} from "./modules/lists.js";
import { classifySearchEnginePage } from "./modules/search-engines.js";

const STATIC_CACHE_TTL = 10 * 60 * 1000;
const TEMP_IGNORE_MS = 10 * 60 * 1000;
const NAVIGATION_WINDOW_MS = 15 * 1000;
const LINK_LAB_SESSION_TTL_MS = 15 * 60 * 1000;
const LINK_LAB_MIN_INTERVAL_MS = 750;

const pageSignalsByTab = new Map();
const currentUrlByTab = new Map();
const pendingNavigationByTab = new Map();
const redirectInfoByTab = new Map();
const lastCommittedUrlByTab = new Map();
const lastAttemptedUrlByTab = new Map();
let lastLinkLabProbeAt = 0;

const DEFAULT_SETTINGS = {
  enabled: true,
  analyzePage: true,
  saveHistory: true,
  showSafeBanner: false,
  showSearchEnginePageUi: false,
  childMode: false,
  childSafeBanner: true,
  childProtectionLevel: "strict",
  childRequireContentScan: true,
  childAutoSpeak: false,
  redirectAnalysis: true,
  autoBlockConfirmed: true,
  urlModelEnabled: true,
  contentSafetyEnabled: true,
  showContentSafetyWarnings: true,
  threatIntelEnabled: false,
  threatIntelEndpoint: "",
  uiProfile: "simple",
  simpleWarningsOnly: true
};

const listsReady = loadAllLists();
const pslReady = loadPublicSuffixList();

function hashText(text) {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function staticCacheKey(url) {
  return `static_cache_v274_${hashText(url)}`;
}

function isWebUrl(url) {
  try {
    return ["http:", "https:"].includes(new URL(url).protocol);
  } catch {
    return false;
  }
}

async function getSettings() {
  const settings = await chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS));
  return { ...DEFAULT_SETTINGS, ...settings };
}

async function initializeDefaults() {
  const existing = await chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS));
  const missing = {};
  for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
    if (typeof existing[key] === "undefined") missing[key] = value;
  }
  if (Object.keys(missing).length > 0) await chrome.storage.local.set(missing);
}

async function clearKeysByPrefix(prefix) {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter(key => key.startsWith(prefix));
  if (keys.length > 0) await chrome.storage.local.remove(keys);
  return keys.length;
}

async function getCachedStatic(url) {
  const key = staticCacheKey(url);
  const data = await chrome.storage.local.get(key);
  const cached = data[key];
  if (!cached) return null;

  if (Date.now() - cached.cachedAt > STATIC_CACHE_TTL) {
    await chrome.storage.local.remove(key);
    return null;
  }
  return cached.value;
}

async function saveCachedStatic(url, value) {
  await chrome.storage.local.set({
    [staticCacheKey(url)]: { value, cachedAt: Date.now() }
  });
}

async function getTemporaryIgnore(domain) {
  const key = `ignore_${domain}`;
  const data = await chrome.storage.session.get(key);
  const expiresAt = data[key] || 0;
  if (expiresAt <= Date.now()) {
    if (expiresAt) await chrome.storage.session.remove(key);
    return null;
  }
  return expiresAt;
}

async function setTemporaryIgnore(domain, durationMs = TEMP_IGNORE_MS) {
  const expiresAt = Date.now() + durationMs;
  await chrome.storage.session.set({ [`ignore_${domain}`]: expiresAt });
  return expiresAt;
}

function tabResultKey(tabId) {
  return String(tabId);
}

async function getTabResult(tabId) {
  if (!tabId) return null;
  const key = tabResultKey(tabId);
  const data = await chrome.storage.session.get(key);
  return data[key] || null;
}

async function saveTabResult(tabId, result) {
  await chrome.storage.session.set({ [tabResultKey(tabId)]: result });
}

async function updateBadge(tabId, risk, contentSafety = null, evidenceAssessment = null) {
  try {
    await chrome.tabs.get(tabId);
    if (risk.level === "HIGH") {
      await chrome.action.setBadgeText({ tabId, text: "!!" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#E53935" });
      if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#FFFFFF" });
      return;
    }
    if (risk.level === "MEDIUM") {
      await chrome.action.setBadgeText({ tabId, text: "!" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#FFD600" });
      if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#111111" });
      return;
    }
    if (risk.level === "SUSPICIOUS") {
      const pageWarning = risk.presentation?.shouldWarnOnPage !== false;
      await chrome.action.setBadgeText({ tabId, text: pageWarning ? "?" : "i" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: pageWarning ? "#F59E0B" : "#0EA5E9" });
      if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#111111" });
      return;
    }
    if (contentSafety?.detected) {
      const categories = contentSafety.categories || [];
      const onlyGameCommerce = categories.length > 0 && categories.every(item => item.id === "GAME_COMMERCE");
      if (onlyGameCommerce) {
        await chrome.action.setBadgeText({ tabId, text: "G?" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
        if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#111111" });
        return;
      }
      const highContent = contentSafety.level === "HIGH" || contentSafety.level === "WARNING";
      await chrome.action.setBadgeText({ tabId, text: highContent ? "C!" : "C" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: highContent ? "#7C3AED" : "#F97316" });
      if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#FFFFFF" });
      return;
    }
    const recognizedContext = [
      "KNOWN_DOMAIN", "OFFICIAL_SUFFIX", "ESTABLISHED_DOMAIN", "MODERATELY_ESTABLISHED", "USER_TRUSTED",
      "LOCAL_DEVELOPMENT", "PRIVATE_NETWORK"
    ].includes(risk.identityStatus?.code || "UNVERIFIED");
    const incompleteSafeEvidence = evidenceAssessment
      ? evidenceAssessment.riskState === "UNDETERMINED" || evidenceAssessment.safeDisplayState === "CAUTION"
      : contentSafety?.available !== true || !recognizedContext;
    if (incompleteSafeEvidence) {
      await chrome.action.setBadgeText({ tabId, text: "?" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
      if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#111111" });
      return;
    }
    await chrome.action.setBadgeText({ tabId, text: "✓" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#2ECC71" });
    if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#FFFFFF" });
  } catch {
    // Tab may have closed while checks were running.
  }
}

async function clearBadge(tabId) {
  try {
    await chrome.action.setBadgeText({ tabId, text: "" });
  } catch {
    // Ignore stale tab.
  }
}

async function sendMessageToPage(tabId, message) {
  try {
    await chrome.tabs.get(tabId);
    await chrome.tabs.sendMessage(tabId, message);
  } catch {
    // No content script on internal/closed tabs.
  }
}

async function requestPageSignals(tabId, expectedUrl) {
  try {
    const response = await Promise.race([
      chrome.tabs.sendMessage(tabId, { type: "REQUEST_PAGE_SIGNALS" }),
      new Promise(resolve => setTimeout(() => resolve(null), 1400))
    ]);
    if (!response?.ok || !response.signals) return null;
    if (expectedUrl && response.url && response.url !== expectedUrl) return null;
    pageSignalsByTab.set(tabId, response.signals);
    return response.signals;
  } catch {
    return null;
  }
}

async function syncBlockingRules() {
  const settings = await getSettings();
  if (!settings.autoBlockConfirmed) {
    await syncBlockedDomains([]);
    return 0;
  }
  await ensureListsLoaded();
  return syncBlockedDomains(getBlacklist());
}

function createRedirectInfo(initialUrl, finalUrl, qualifiers = []) {
  const urls = [...new Set([initialUrl, finalUrl].filter(Boolean))];
  const domainParts = urls.map(value => {
    try {
      return getDomainParts(new URL(value).hostname);
    } catch {
      return null;
    }
  }).filter(Boolean);
  const uniqueDomains = [...new Set(domainParts.map(item => item.registrableDomain).filter(Boolean))];
  const firstProtocol = (() => { try { return new URL(initialUrl).protocol; } catch { return ""; } })();
  const lastProtocol = (() => { try { return new URL(finalUrl).protocol; } catch { return ""; } })();

  const authContext = analyzeFederatedAuthRedirect(initialUrl, finalUrl, getDomainParts);

  return {
    initialUrl: initialUrl || finalUrl,
    finalUrl,
    urls,
    hopCount: urls.length,
    uniqueDomains,
    uniqueDomainCount: uniqueDomains.length,
    crossDomainCount: Math.max(0, uniqueDomains.length - 1),
    hasServerRedirect: qualifiers.includes("server_redirect"),
    hasClientRedirect: qualifiers.includes("client_redirect"),
    httpsDowngrade: firstProtocol === "https:" && lastProtocol === "http:",
    ...authContext,
    observedAt: new Date().toISOString()
  };
}

function getRedirectInfo(tabId, currentUrl) {
  const info = redirectInfoByTab.get(tabId);
  if (!info) return createRedirectInfo(currentUrl, currentUrl, []);
  if (Date.now() - new Date(info.observedAt).getTime() > NAVIGATION_WINDOW_MS) {
    return createRedirectInfo(currentUrl, currentUrl, []);
  }
  return { ...info, finalUrl: currentUrl || info.finalUrl };
}

async function buildStaticAnalysis(url, hostname) {
  await Promise.all([ensureListsLoaded(), pslReady]);
  const siteContext = classifySiteContext(url);
  const domainInfo = getDomainParts(hostname);
  const identityDomain = domainInfo.registrableDomain || hostname;
  const homoglyphInfo = analyzeHomoglyph(identityDomain);
  const knownDomains = getKnownDomains();
  const protectedTyposquatDomains = getProtectedTyposquatDomains();
  const typoReferenceDomains = getTyposquatReferenceDomains();
  const rdapResponse = siteContext.isPublic
    ? await checkDomainAge(identityDomain)
    : { value: null, available: false, cacheHit: false, skipped: true };
  const typoMatch = siteContext.isPublic
    ? findSimilarDomain(homoglyphInfo.skeleton, typoReferenceDomains, {
        exactBrandLabels: protectedTyposquatDomains
      })
    : null;
  const isKnownDomain = siteContext.isPublic && knownDomains.includes(identityDomain);
  const searchEnginePage = classifySearchEnginePage(url);

  return {
    domain: hostname,
    domainInfo,
    identityDomain,
    siteContext,
    url,
    ageInfo: rdapResponse.value,
    rdapMeta: {
      available: rdapResponse.available,
      cacheHit: rdapResponse.cacheHit,
      skipped: Boolean(rdapResponse.skipped),
      skipReason: rdapResponse.skipped ? "non-public-site-context" : ""
    },
    typoMatch,
    homoglyphInfo,
    isBlacklisted: isBlacklisted(hostname) || isBlacklisted(identityDomain),
    isWhitelisted: isWhitelisted(hostname) || isWhitelisted(identityDomain),
    isKnownDomain,
    isSearchEngineHome: searchEnginePage.isSearchEngineHome,
    searchEngineId: searchEnginePage.searchEngineId,
    staticCheckedAt: new Date().toISOString()
  };
}

function createProbeRedirectInfo(network, originalUrl, finalUrl) {
  const urls = [...new Set([
    ...(network?.redirects || []).map(item => item.url),
    finalUrl
  ].filter(Boolean))];
  const base = createRedirectInfo(originalUrl, finalUrl, urls.length > 1 ? ["server_redirect"] : []);
  const uniqueDomains = [...new Set(urls.map(value => {
    try {
      return getDomainParts(new URL(value).hostname).registrableDomain;
    } catch {
      return null;
    }
  }).filter(Boolean))];

  return {
    ...base,
    urls,
    hopCount: urls.length,
    uniqueDomains,
    uniqueDomainCount: uniqueDomains.length,
    crossDomainCount: Math.max(0, uniqueDomains.length - 1),
    hasServerRedirect: urls.length > 1,
    observedAt: new Date().toISOString()
  };
}

async function cleanupLinkLabSessions() {
  const all = await chrome.storage.session.get(null);
  const entries = Object.entries(all)
    .filter(([key]) => key.startsWith("link_lab_session_"))
    .sort((a, b) => Number(b[1]?.createdAt || 0) - Number(a[1]?.createdAt || 0));
  const now = Date.now();
  const removeKeys = entries
    .filter(([, value], index) => Number(value?.expiresAt || 0) <= now || index >= 20)
    .map(([key]) => key);
  if (removeKeys.length > 0) await chrome.storage.session.remove(removeKeys);
}

function createLinkLabSessionId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
}

async function analyzeUrlPreflight(rawUrl) {
  const original = normalizeLinkLabUrl(rawUrl);
  const now = Date.now();
  if (now - lastLinkLabProbeAt < LINK_LAB_MIN_INTERVAL_MS) {
    throw new Error("Hãy chờ một chút trước khi kiểm tra link tiếp theo.");
  }
  lastLinkLabProbeAt = now;
  const settings = await getSettings();
  const network = await probeUrlNetwork(original.href);
  const finalUrl = normalizeLinkLabUrl(network.finalUrl || original.href).href;
  const parsedFinal = new URL(finalUrl);
  const hostname = normalizeDomain(parsedFinal.hostname);

  let staticAnalysis = await getCachedStatic(finalUrl);
  if (!staticAnalysis) {
    staticAnalysis = await buildStaticAnalysis(finalUrl, hostname);
    await saveCachedStatic(finalUrl, staticAnalysis);
  }

  const redirectInfo = createProbeRedirectInfo(network, original.href, finalUrl);
  const threatInfo = staticAnalysis.siteContext.isPublic
    ? await checkThreatIntel(finalUrl, settings)
    : { checked: false, skipped: true, isUnsafe: false, threats: [], reason: "non-public-site-context" };
  const mlInfo = settings.urlModelEnabled && staticAnalysis.siteContext.isPublic
    ? await predictUrlRisk(finalUrl, staticAnalysis.domainInfo)
    : {
        available: false,
        disabled: !settings.urlModelEnabled,
        skipped: !staticAnalysis.siteContext.isPublic,
        reason: staticAnalysis.siteContext.isPublic ? "disabled" : "non-public-site-context",
        probability: 0,
        prediction: "NOT_APPLICABLE"
      };
  const risk = calculateRisk({
    url: finalUrl,
    domain: hostname,
    domainInfo: staticAnalysis.domainInfo,
    ageInfo: staticAnalysis.ageInfo,
    typoMatch: staticAnalysis.typoMatch,
    homoglyphInfo: staticAnalysis.homoglyphInfo,
    isBlacklisted: staticAnalysis.isBlacklisted,
    isWhitelisted: staticAnalysis.isWhitelisted,
    isKnownDomain: Boolean(staticAnalysis.isKnownDomain),
    pageSignals: null,
    redirectInfo,
    threatInfo,
    mlInfo,
    siteContext: staticAnalysis.siteContext
  });
  const verdict = buildPreflightVerdict(risk, network);
  const staticContent = network.htmlSignals?.staticContent || null;
  const preflightContentSafety = {
    available: network.probeSkipped !== true && network.reachable === true && network.ok === true,
    disabled: false,
    detected: Boolean(staticContent?.findings?.length),
    score: Number(staticContent?.score) || 0,
    level: staticContent?.level || "NONE",
    categories: (staticContent?.findings || []).map(item => ({
      ...item,
      label: CATEGORY_META[item.id]?.label || item.id,
      icon: CATEGORY_META[item.id]?.icon || "⚑",
      reasons: [item.reason].filter(Boolean),
      evidence: staticContent?.samples || []
    })),
    reasons: staticContent?.reasons || [],
    recommendations: [],
    legalIndicators: [],
    disclaimer: "Link Lab chỉ đọc HTML giới hạn, không chạy mã trang và không đưa ra kết luận pháp lý."
  };
  const evidenceAssessment = buildEvidenceAssessment({
    mode: "preflight",
    domain: hostname,
    registrableDomain: staticAnalysis.domainInfo.registrableDomain,
    risk: { ...verdict, identityStatus: risk.identityStatus },
    contentSafety: preflightContentSafety,
    rdapMeta: staticAnalysis.rdapMeta,
    ageInfo: staticAnalysis.ageInfo,
    mlInfo,
    redirectInfo,
    threatInfo,
    siteContext: staticAnalysis.siteContext,
    isSearchEngineHome: Boolean(staticAnalysis.isSearchEngineHome),
    searchEngineId: staticAnalysis.searchEngineId || null,
    listStatus: {
      blacklisted: staticAnalysis.isBlacklisted,
      whitelisted: staticAnalysis.isWhitelisted,
      knownDomain: Boolean(staticAnalysis.isKnownDomain)
    },
    settings,
    network
  });
  const previewAllowed = (
    network.probeSkipped !== true &&
    !network.redirectAnomaly &&
    network.reachable === true &&
    network.ok === true
  );

  const result = {
    mode: "preflight",
    originalUrl: original.href,
    displayOriginalUrl: redactUrl(original.href),
    finalUrl,
    displayFinalUrl: redactUrl(finalUrl),
    domain: hostname,
    registrableDomain: staticAnalysis.domainInfo.registrableDomain,
    domainInfo: staticAnalysis.domainInfo,
    siteContext: staticAnalysis.siteContext,
    isSearchEngineHome: Boolean(staticAnalysis.isSearchEngineHome),
    searchEngineId: staticAnalysis.searchEngineId || null,
    ageInfo: staticAnalysis.ageInfo,
    rdapMeta: staticAnalysis.rdapMeta,
    typoMatch: staticAnalysis.typoMatch,
    homoglyphInfo: staticAnalysis.homoglyphInfo,
    threatInfo,
    mlInfo,
    redirectInfo,
    network,
    sensitiveAction: network.sensitiveAction || null,
    previewAllowed,
    listStatus: {
      blacklisted: staticAnalysis.isBlacklisted,
      whitelisted: staticAnalysis.isWhitelisted,
      knownDomain: Boolean(staticAnalysis.isKnownDomain)
    },
    risk,
    verdict,
    contentSafety: preflightContentSafety,
    evidenceAssessment,
    coverage: {
      executedPageCode: false,
      credentialsSent: false,
      maxRedirects: MAX_REDIRECTS,
      maxResponseBytes: MAX_RESPONSE_BYTES,
      timeoutMs: PROBE_TIMEOUT_MS,
      limitations: [
        "Không chạy JavaScript, không gửi cookie và không gửi thông tin đăng nhập.",
        "Chỉ đọc tối đa 64 KiB đầu của phản hồi; hành vi sau tương tác có thể chưa được quan sát.",
        "Safe Preview là iframe bị khóa script/form/download, không phải máy ảo hay sandbox hệ điều hành.",
        "Tên miền được kiểm tra ở mức URL/literal host; DNS rebinding và địa chỉ IP sau phân giải vẫn là giới hạn còn lại.",
        ...(network.probeSkipped ? ["Không probe link có token/hành động nhạy cảm để tránh tiêu thụ token, lộ IP hoặc kích hoạt tác động phía máy chủ."] : []),
        ...(network.redirectAnomaly ? ["Safe Preview bị khóa vì chuỗi chuyển hướng có vòng lặp hoặc vượt giới hạn an toàn."] : []),
        ...(network.reachable === true && network.ok === false ? ["Safe Preview bị khóa vì máy chủ trả phản hồi HTTP không thành công và nội dung thực tế chưa được xác minh."] : [])
      ]
    },
    checkedAt: new Date().toISOString()
  };

  await cleanupLinkLabSessions();
  const sessionId = createLinkLabSessionId();
  const createdAt = Date.now();
  await chrome.storage.session.set({
    [`link_lab_session_${sessionId}`]: {
      result,
      createdAt,
      expiresAt: createdAt + LINK_LAB_SESSION_TTL_MS
    }
  });

  return { result, sessionId };
}

async function openSafePreview(sessionId) {
  const key = `link_lab_session_${String(sessionId || "")}`;
  const data = await chrome.storage.session.get(key);
  const session = data[key];
  if (!session || Number(session.expiresAt || 0) <= Date.now()) {
    if (session) await chrome.storage.session.remove(key);
    throw new Error("Phiên Link Lab đã hết hạn. Hãy quét lại URL.");
  }
  if (session.result?.previewAllowed === false || session.result?.network?.probeSkipped) {
    throw new Error("Safe Preview bị khóa vì link nhạy cảm, phản hồi chưa xác minh hoặc chuyển hướng bất thường.");
  }

  const pageUrl = `${chrome.runtime.getURL("link-lab.html")}?session=${encodeURIComponent(sessionId)}`;
  const tab = await chrome.tabs.create({ url: pageUrl, active: true });
  if (!tab?.id) throw new Error("Không thể mở Safe Preview.");
  try {
    await enableSafePreviewMode(tab.id);
  } catch {
    await chrome.tabs.remove(tab.id).catch(() => {});
    throw new Error("Không thể kích hoạt luật cô lập cho Safe Preview.");
  }
  await chrome.storage.session.set({ [key]: { ...session, previewTabId: tab.id } });
  return tab.id;
}

async function analyzeTab(tabId, url, options = {}) {
  const { dynamic = false, forceStatic = false } = options;
  const settings = await getSettings();

  if (!settings.enabled) {
    await clearBadge(tabId);
    await sendMessageToPage(tabId, { type: "PHISHING_DISABLED" });
    return null;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    await clearBadge(tabId);
    return null;
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    await clearBadge(tabId);
    return null;
  }

  const hostname = normalizeDomain(parsedUrl.hostname);
  currentUrlByTab.set(tabId, url);

  let staticAnalysis = forceStatic ? null : await getCachedStatic(url);
  const resultCacheHit = Boolean(staticAnalysis);
  if (!staticAnalysis) {
    staticAnalysis = await buildStaticAnalysis(url, hostname);
    await saveCachedStatic(url, staticAnalysis);
  }

  let pageSignals = settings.analyzePage ? pageSignalsByTab.get(tabId) || null : null;
  if (settings.analyzePage && !pageSignals) {
    pageSignals = await requestPageSignals(tabId, url);
  }
  const redirectInfo = settings.redirectAnalysis ? getRedirectInfo(tabId, url) : null;
  const threatInfo = staticAnalysis.siteContext.isPublic
    ? await checkThreatIntel(url, settings)
    : { checked: false, skipped: true, isUnsafe: false, threats: [], reason: "non-public-site-context" };
  const mlInfo = settings.urlModelEnabled && staticAnalysis.siteContext.isPublic
    ? await predictUrlRisk(url, staticAnalysis.domainInfo)
    : {
        available: false,
        disabled: !settings.urlModelEnabled,
        skipped: !staticAnalysis.siteContext.isPublic,
        reason: staticAnalysis.siteContext.isPublic ? "disabled" : "non-public-site-context",
        probability: 0,
        prediction: "NOT_APPLICABLE"
      };

  const contentSafety = analyzeContentSafety(pageSignals, {
    enabled: settings.contentSafetyEnabled
  });

  const risk = calculateRisk({
    url,
    domain: hostname,
    domainInfo: staticAnalysis.domainInfo,
    ageInfo: staticAnalysis.ageInfo,
    typoMatch: staticAnalysis.typoMatch,
    homoglyphInfo: staticAnalysis.homoglyphInfo,
    isBlacklisted: staticAnalysis.isBlacklisted,
    isWhitelisted: staticAnalysis.isWhitelisted,
    isKnownDomain: Boolean(staticAnalysis.isKnownDomain),
    pageSignals,
    redirectInfo,
    threatInfo,
    mlInfo,
    siteContext: staticAnalysis.siteContext
  });

  const ignoredUntil = await getTemporaryIgnore(hostname);
  const strictMode = await isStrictModeEnabled(tabId);
  const listStatus = {
    blacklisted: staticAnalysis.isBlacklisted,
    whitelisted: staticAnalysis.isWhitelisted,
    knownDomain: Boolean(staticAnalysis.isKnownDomain)
  };
  const evidenceAssessment = buildEvidenceAssessment({
    domain: hostname,
    registrableDomain: staticAnalysis.domainInfo.registrableDomain,
    risk,
    contentSafety,
    pageSignals,
    rdapMeta: staticAnalysis.rdapMeta,
    ageInfo: staticAnalysis.ageInfo,
    mlInfo,
    redirectInfo,
    threatInfo,
    siteContext: staticAnalysis.siteContext,
    listStatus,
    settings
  });
  const result = {
    domain: hostname,
    registrableDomain: staticAnalysis.domainInfo.registrableDomain,
    domainInfo: staticAnalysis.domainInfo,
    siteContext: staticAnalysis.siteContext,
    isSearchEngineHome: Boolean(staticAnalysis.isSearchEngineHome),
    searchEngineId: staticAnalysis.searchEngineId || null,
    url,
    ageInfo: staticAnalysis.ageInfo,
    rdapMeta: staticAnalysis.rdapMeta,
    typoMatch: staticAnalysis.typoMatch,
    homoglyphInfo: staticAnalysis.homoglyphInfo,
    pageSignals,
    redirectInfo,
    threatInfo,
    mlInfo,
    contentSafety,
    evidenceAssessment,
    strictMode,
    listStatus,
    risk,
    ignoredUntil,
    settings: {
      showSafeBanner: settings.showSafeBanner,
      showSearchEnginePageUi: settings.showSearchEnginePageUi,
      analyzePage: settings.analyzePage,
      childMode: settings.childMode,
      childSafeBanner: settings.childSafeBanner,
      childProtectionLevel: settings.childProtectionLevel,
      childRequireContentScan: settings.childRequireContentScan,
      childAutoSpeak: settings.childAutoSpeak,
      redirectAnalysis: settings.redirectAnalysis,
      urlModelEnabled: settings.urlModelEnabled,
      contentSafetyEnabled: settings.contentSafetyEnabled,
      showContentSafetyWarnings: settings.showContentSafetyWarnings,
      uiProfile: settings.uiProfile,
      simpleWarningsOnly: settings.simpleWarningsOnly
    },
    checkedAt: new Date().toISOString()
  };

  await saveTabResult(tabId, result);
  await updateBadge(tabId, risk, contentSafety, evidenceAssessment);
  await sendMessageToPage(tabId, { type: "PHISHING_RESULT", result });
  await addHistoryEntry(result);
  await updateStats({
    level: risk.level,
    dynamic,
    rdapAvailable: staticAnalysis.rdapMeta.skipped ? null : staticAnalysis.rdapMeta.available,
    rdapCacheHit: staticAnalysis.rdapMeta.cacheHit,
    resultCacheHit,
    contentSafety,
    warningShown: (
      (risk.level !== "SAFE" && risk.presentation?.shouldWarnOnPage !== false) ||
      Boolean(contentSafety?.detected && settings.showContentSafetyWarnings)
    ),
    scanDurationMs: pageSignals?.scanDurationMs
  });
  return result;
}

async function analyzeActiveTab(options = {}) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id && tab.url) return analyzeTab(tab.id, tab.url, options);
  } catch {
    // Ignore browser-internal pages.
  }
  return null;
}

async function invalidateDomainCaches(domain) {
  const all = await chrome.storage.local.get(null);
  const keys = Object.entries(all)
    .filter(([key, value]) => key.startsWith("static_cache_") && (
      value?.value?.domain === domain || value?.value?.identityDomain === domain
    ))
    .map(([key]) => key);
  if (keys.length > 0) await chrome.storage.local.remove(keys);
}

async function clearStoredTabResults() {
  const [localData, sessionData] = await Promise.all([
    chrome.storage.local.get(null),
    chrome.storage.session.get(null)
  ]);
  const localKeys = Object.keys(localData).filter(key => /^\d+$/.test(key));
  const sessionKeys = Object.keys(sessionData).filter(key => /^\d+$/.test(key));
  await Promise.all([
    localKeys.length ? chrome.storage.local.remove(localKeys) : Promise.resolve(),
    sessionKeys.length ? chrome.storage.session.remove(sessionKeys) : Promise.resolve()
  ]);
  return localKeys.length + sessionKeys.length;
}

async function parentActionAllowed() {
  const settings = await getSettings();
  if (!settings.childMode) return true;
  return isParentUnlocked();
}

function sameHostOrSubdomain(hostname, domain) {
  const host = normalizeDomain(hostname);
  const target = normalizeDomain(domain);
  return Boolean(host && target && (host === target || host.endsWith(`.${target}`)));
}

async function bypassRequiresTypedDomain(tabId, domain) {
  await ensureListsLoaded();
  const result = await getTabResult(tabId);
  return Boolean(
    isBlacklisted(domain) ||
    result?.risk?.level === "HIGH" ||
    result?.listStatus?.blacklisted ||
    result?.threatInfo?.isUnsafe ||
    result?.contentSafety?.level === "HIGH"
  );
}

async function recordFalsePositiveFeedback(tabId, domain, note = "") {
  const result = await getTabResult(tabId);
  const data = await chrome.storage.local.get("false_positive_feedback");
  const feedback = Array.isArray(data.false_positive_feedback) ? data.false_positive_feedback : [];
  feedback.unshift({
    domain,
    registrableDomain: result?.registrableDomain || domain,
    level: result?.risk?.level || "UNKNOWN",
    score: Number(result?.risk?.score) || 0,
    reasons: (result?.risk?.reasons || []).slice(0, 4),
    note: String(note || "").slice(0, 240),
    createdAt: new Date().toISOString()
  });
  await chrome.storage.local.set({ false_positive_feedback: feedback.slice(0, 100) });
  await recordSecurityEvent("falsePositiveReports");
}

chrome.runtime.onInstalled.addListener(details => {
  (async () => {
    await initializeDefaults();
    if (details.reason === "install" || details.reason === "update") {
      await chrome.storage.local.set({ uiProfile: "simple", simpleWarningsOnly: true });
    }
    await clearKeysByPrefix("static_cache_");
    await clearStoredTabResults();
    await Promise.all([listsReady, pslReady]);
    await syncBlockingRules();
    await analyzeActiveTab({ forceStatic: true });
  })().catch(error => {
    console.error("Không thể khởi tạo DNR khi cài đặt:", error);
  });
});

chrome.runtime.onStartup.addListener(() => {
  (async () => {
    await initializeDefaults();
    await Promise.all([loadAllLists(), loadPublicSuffixList()]);
    await syncBlockingRules();
  })().catch(error => {
    console.error("Không thể khởi tạo DNR khi mở trình duyệt:", error);
  });
});

chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0 || !isWebUrl(details.url)) return;
  const existing = pendingNavigationByTab.get(details.tabId);
  const now = Date.now();
  if (!existing || now - existing.startedAt > NAVIGATION_WINDOW_MS) {
    pendingNavigationByTab.set(details.tabId, { initialUrl: details.url, startedAt: now });
  }
  lastAttemptedUrlByTab.set(details.tabId, details.url);
});

chrome.webNavigation.onCommitted.addListener(details => {
  if (details.frameId !== 0) return;
  consumeAllowDomainOnce(details.tabId).catch(() => {});
  if (!isWebUrl(details.url)) return;

  const qualifiers = details.transitionQualifiers || [];
  const pending = pendingNavigationByTab.get(details.tabId);
  const previousCommitted = lastCommittedUrlByTab.get(details.tabId);
  let initialUrl = details.url;

  if (qualifiers.includes("server_redirect")) {
    initialUrl = pending?.initialUrl || previousCommitted || details.url;
  } else if (qualifiers.includes("client_redirect")) {
    initialUrl = previousCommitted || pending?.initialUrl || details.url;
  }

  redirectInfoByTab.set(details.tabId, createRedirectInfo(initialUrl, details.url, qualifiers));
  lastCommittedUrlByTab.set(details.tabId, details.url);
  pendingNavigationByTab.delete(details.tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;
  if (!isWebUrl(tab.url)) return;
  pageSignalsByTab.delete(tabId);
  analyzeTab(tabId, tab.url).catch(error => console.error("Không thể phân tích tab:", error));
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url && isWebUrl(tab.url)) await analyzeTab(tabId, tab.url);
  } catch {
    // Ignore stale tab.
  }
});

chrome.tabs.onRemoved.addListener(tabId => {
  pageSignalsByTab.delete(tabId);
  currentUrlByTab.delete(tabId);
  pendingNavigationByTab.delete(tabId);
  redirectInfoByTab.delete(tabId);
  lastCommittedUrlByTab.delete(tabId);
  lastAttemptedUrlByTab.delete(tabId);
  cleanupTabRules(tabId).catch(() => {});
  chrome.storage.session.remove(String(tabId)).catch(() => {});
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  if (changes.customWhitelist || changes.customBlacklist) {
    loadAllLists()
      .then(() => clearKeysByPrefix("static_cache_"))
      .then(() => syncBlockingRules())
      .then(() => analyzeActiveTab({ forceStatic: true }))
      .catch(() => {});
  }

  if (changes.autoBlockConfirmed) syncBlockingRules().catch(() => {});

  if (changes.threatIntelEndpoint || changes.threatIntelEnabled) {
    clearKeysByPrefix("threat_cache_").then(() => analyzeActiveTab({ forceStatic: true })).catch(() => {});
  }

  if (
    changes.enabled || changes.analyzePage || changes.showSafeBanner || changes.showSearchEnginePageUi ||
    changes.saveHistory || changes.childMode || changes.childSafeBanner ||
    changes.childProtectionLevel || changes.childRequireContentScan || changes.childAutoSpeak ||
    changes.redirectAnalysis || changes.urlModelEnabled ||
    changes.contentSafetyEnabled || changes.showContentSafetyWarnings ||
    changes.uiProfile || changes.simpleWarningsOnly
  ) {
    analyzeActiveTab().catch(() => {});
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PAGE_SIGNALS_UPDATED" && sender.tab?.id) {
    (async () => {
      const tabId = sender.tab.id;
      const currentUrl = sender.tab.url || message.url;
      if (!currentUrl) return;
      pageSignalsByTab.set(tabId, message.signals || null);
      const result = await analyzeTab(tabId, currentUrl, { dynamic: true });
      sendResponse({ done: true, score: result?.risk?.score ?? null });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "PAGE_URL_CHANGED" && sender.tab?.id && message.url) {
    (async () => {
      pageSignalsByTab.delete(sender.tab.id);
      await analyzeTab(sender.tab.id, message.url);
      sendResponse({ done: true });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "RECHECK_TAB" && message.tabId && message.url) {
    (async () => {
      await chrome.storage.local.remove(staticCacheKey(message.url));
      const result = await analyzeTab(message.tabId, message.url, { forceStatic: true });
      sendResponse({ done: true, result });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "ANALYZE_URL_PREFLIGHT" && message.url) {
    analyzeUrlPreflight(message.url)
      .then(({ result, sessionId }) => sendResponse({ done: true, result, sessionId }))
      .catch(error => sendResponse({ done: false, error: error.message || "Không thể kiểm tra URL." }));
    return true;
  }

  if (message.type === "OPEN_SAFE_PREVIEW" && message.sessionId) {
    openSafePreview(message.sessionId)
      .then(tabId => sendResponse({ done: true, tabId }))
      .catch(error => sendResponse({ done: false, error: error.message || "Không thể mở Safe Preview." }));
    return true;
  }

  if (message.type === "ENSURE_SAFE_PREVIEW_MODE" && sender.tab?.id) {
    const expectedPrefix = chrome.runtime.getURL("link-lab.html");
    if (!String(sender.url || "").startsWith(expectedPrefix)) {
      sendResponse({ done: false, error: "Nguồn yêu cầu không hợp lệ." });
      return false;
    }
    enableSafePreviewMode(sender.tab.id)
      .then(() => sendResponse({ done: true }))
      .catch(() => sendResponse({ done: false, error: "Không thể kích hoạt luật cô lập." }));
    return true;
  }

  if (message.type === "ADD_WHITELIST" && message.domain) {
    (async () => {
      if (!(await parentActionAllowed())) {
        sendResponse({ done: false, requiresParent: true });
        return;
      }
      const domain = normalizeDomain(message.domain);
      await addToWhitelist(domain);
      await invalidateDomainCaches(domain);
      const tabId = sender.tab?.id || message.tabId;
      if (tabId) {
        const tab = await chrome.tabs.get(tabId).catch(() => null);
        if (tab?.url && isWebUrl(tab.url)) await analyzeTab(tabId, tab.url, { forceStatic: true });
      }
      sendResponse({ done: true });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "ADD_BLACKLIST" && message.domain) {
    (async () => {
      const domain = normalizeDomain(message.domain);
      await addToBlacklist(domain);
      await invalidateDomainCaches(domain);
      await syncBlockingRules();
      const tabId = sender.tab?.id || message.tabId;
      if (tabId) {
        const tab = await chrome.tabs.get(tabId).catch(() => null);
        if (tab?.url && isWebUrl(tab.url)) await analyzeTab(tabId, tab.url, { forceStatic: true });
      }
      sendResponse({ done: true });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "IGNORE_DOMAIN_TEMP" && message.domain) {
    (async () => {
      if (!(await parentActionAllowed())) {
        sendResponse({ done: false, requiresParent: true });
        return;
      }
      const domain = normalizeDomain(message.domain);
      const tabId = sender.tab?.id || message.tabId;
      if (!tabId) throw new Error("Thiếu tabId");
      const storedResult = await getTabResult(tabId);
      if (storedResult?.domain && storedResult.domain !== domain) {
        throw new Error("Domain xác nhận không khớp tab hiện tại.");
      }
      if (await bypassRequiresTypedDomain(tabId, domain)) {
        const confirmationDomain = normalizeDomain(message.confirmationDomain);
        if (confirmationDomain !== domain) {
          sendResponse({ done: false, requiresConfirmation: true, confirmationDomain: domain });
          return;
        }
      }
      const expiresAt = await setTemporaryIgnore(domain);
      if (tabId) await sendMessageToPage(tabId, { type: "PHISHING_IGNORED", domain, expiresAt });
      await recordSecurityEvent("bypasses");
      sendResponse({ done: true, expiresAt });
    })().catch(error => sendResponse({ done: false, error: error.message || "Không thể cho phép tạm thời." }));
    return true;
  }

  if (message.type === "ENABLE_STRICT_MODE") {
    (async () => {
      if (!(await parentActionAllowed())) {
        sendResponse({ done: false, requiresParent: true });
        return;
      }
      const tabId = sender.tab?.id || message.tabId;
      if (!tabId) throw new Error("Thiếu tabId");
      await enableStrictMode(tabId);
      await chrome.tabs.reload(tabId);
      sendResponse({ done: true });
    })().catch(error => sendResponse({ done: false, error: error.message }));
    return true;
  }

  if (message.type === "DISABLE_STRICT_MODE") {
    (async () => {
      const tabId = sender.tab?.id || message.tabId;
      if (!tabId) throw new Error("Thiếu tabId");
      await disableStrictMode(tabId);
      await chrome.tabs.reload(tabId);
      sendResponse({ done: true });
    })().catch(error => sendResponse({ done: false, error: error.message }));
    return true;
  }

  if (message.type === "GET_BLOCK_CONTEXT") {
    (async () => {
      const tabId = sender.tab?.id || message.tabId;
      let attemptedUrl = tabId ? lastAttemptedUrlByTab.get(tabId) : null;
      let domain = message.domain || "";
      if (!domain && attemptedUrl) domain = normalizeDomain(new URL(attemptedUrl).hostname);
      if (!attemptedUrl && domain) attemptedUrl = `https://${domain}/`;
      if (tabId && domain) {
        const seenKey = `block_seen_${tabId}`;
        const seen = await chrome.storage.session.get(seenKey);
        if (!seen[seenKey]) {
          await chrome.storage.session.set({ [seenKey]: Date.now() });
          await recordSecurityEvent("blocks");
        }
      }
      sendResponse({ done: true, tabId, attemptedUrl, domain });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "ALLOW_BLOCKED_ONCE") {
    (async () => {
      if (!(await parentActionAllowed())) {
        sendResponse({ done: false, requiresParent: true });
        return;
      }
      const tabId = sender.tab?.id || message.tabId;
      const domain = normalizeDomain(message.domain);
      const url = message.url;
      if (!tabId || !domain || !url || !isWebUrl(url)) throw new Error("Dữ liệu không hợp lệ");
      const attemptedUrl = lastAttemptedUrlByTab.get(tabId) || url;
      const attemptedHost = normalizeDomain(new URL(attemptedUrl).hostname);
      if (!sameHostOrSubdomain(attemptedHost, domain)) throw new Error("Domain không khớp URL đã bị chặn.");
      if (normalizeDomain(message.confirmationDomain) !== domain) {
        sendResponse({ done: false, requiresConfirmation: true, confirmationDomain: domain });
        return;
      }
      await allowDomainOnce(tabId, domain);
      await recordSecurityEvent("bypasses");
      await chrome.tabs.update(tabId, { url });
      sendResponse({ done: true });
    })().catch(error => sendResponse({ done: false, error: error.message }));
    return true;
  }

  if (message.type === "REPORT_FALSE_POSITIVE" && message.domain) {
    (async () => {
      const tabId = sender.tab?.id || message.tabId;
      const domain = normalizeDomain(message.domain);
      if (!tabId || !domain) throw new Error("Thiếu dữ liệu phản hồi.");
      const result = await getTabResult(tabId);
      if (result?.domain && result.domain !== domain) throw new Error("Domain không khớp tab hiện tại.");
      await recordFalsePositiveFeedback(tabId, domain, message.note);
      sendResponse({ done: true, localOnly: true });
    })().catch(error => sendResponse({ done: false, error: error.message || "Không thể lưu phản hồi." }));
    return true;
  }

  if (message.type === "GET_PARENT_STATE") {
    getParentState().then(state => sendResponse({ done: true, ...state })).catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "SET_PARENT_PIN") {
    (async () => {
      const state = await getParentState();
      if (state.configured && !state.unlocked) {
        sendResponse({ done: false, requiresParent: true });
        return;
      }
      const result = await setParentPin(message.pin);
      if (result.ok && message.enableChildMode === true) await chrome.storage.local.set({ childMode: true });
      sendResponse({ done: result.ok, error: result.error || null });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "VERIFY_PARENT_PIN") {
    unlockParent(message.pin, message.minutes)
      .then(result => sendResponse({ done: result.ok, error: result.error || null, unlockedUntil: result.unlockedUntil || 0 }))
      .catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "LOCK_PARENT") {
    lockParent().then(() => sendResponse({ done: true })).catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "CLEAR_PARENT_PIN") {
    (async () => {
      if (!(await isParentUnlocked())) {
        sendResponse({ done: false, requiresParent: true });
        return;
      }
      await clearParentPin();
      await chrome.storage.local.set({ childMode: false });
      sendResponse({ done: true });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "SET_CHILD_MODE") {
    (async () => {
      const nextValue = Boolean(message.enabled);
      const state = await getParentState();
      if (nextValue && !state.configured) {
        sendResponse({ done: false, needsPinSetup: true });
        return;
      }
      if (!nextValue && state.configured && !state.unlocked) {
        sendResponse({ done: false, requiresParent: true });
        return;
      }
      await chrome.storage.local.set({ childMode: nextValue });
      await analyzeActiveTab();
      sendResponse({ done: true, enabled: nextValue });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  if (message.type === "CLEAR_ANALYSIS_CACHE") {
    (async () => {
      const counts = await Promise.all([
        clearKeysByPrefix("static_cache_"),
        clearKeysByPrefix("rdap_cache_"),
        clearKeysByPrefix("threat_cache_")
      ]);
      await analyzeActiveTab({ forceStatic: true });
      sendResponse({ done: true, removed: counts.reduce((a, b) => a + b, 0) });
    })().catch(() => sendResponse({ done: false }));
    return true;
  }

  return false;
});
