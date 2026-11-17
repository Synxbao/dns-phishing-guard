import { analyzeHomoglyph } from "./homoglyph.js";

const URL_SHORTENERS = new Set([
  "bit.ly", "t.co", "tinyurl.com", "cutt.ly", "is.gd", "rebrand.ly",
  "shorturl.at", "tiny.cc", "ow.ly", "buff.ly", "rb.gy", "soo.gd"
]);

const RISKY_TLDS = new Set([
  "xyz", "top", "click", "shop", "loan", "monster", "live", "site",
  "buzz", "work", "gq", "tk", "ml", "cf", "icu", "support", "cam",
  "cyou", "club", "online", "info", "vip", "store", "rest", "surf"
]);

const PHISHING_KEYWORDS = [
  "login", "log-in", "signin", "sign-in", "verify", "verification",
  "secure", "security", "account", "update", "confirm", "password",
  "wallet", "banking", "invoice", "payment", "unlock", "suspended",
  "support", "gift", "bonus", "otp", "auth", "authenticate", "recover",
  "recovery", "validate", "validation", "customer", "service", "webmail",
  "delivery", "tracking", "refund", "appeal", "billing", "alert"
];

// Only executable/archive/download extensions are treated as suspicious. Dynamic
// server page extensions such as .php, .aspx and .jsp are intentionally neutral.
const SUSPICIOUS_EXTENSIONS = new Set([
  "exe", "scr", "msi", "bat", "cmd", "com", "jar", "js", "vbs", "ps1",
  "apk", "iso", "img", "dmg", "pkg", "zip", "rar", "7z", "xll", "lnk"
]);

const SERVER_PAGE_EXTENSIONS = new Set([
  "html", "htm", "php", "aspx", "asp", "jsp", "jspx", "cfm", "cgi"
]);

const TRACKING_PARAMETER_NAMES = new Set([
  "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "cvid",
  "gs_lcrp", "ghsh", "ghacc", "ghpl", "ved", "ei", "oq", "sourceid",
  "sclient", "campaign", "campaignid", "adgroupid", "creative", "keyword",
  "ref", "ref_", "referrer", "source", "medium", "sp", "sc", "qs", "sk",
  "form", "feature", "si", "pp", "ab_channel", "igshid", "yclid"
]);

const TRACKING_PARAMETER_PREFIXES = [
  "utm_", "_ga", "pk_", "mtm_", "vero_", "hsa_", "oly_"
];

const KNOWN_BRAND_TOKENS = new Set([
  "google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram",
  "linkedin", "netflix", "whatsapp", "telegram", "discord", "github", "adobe",
  "dropbox", "binance", "coinbase", "chase", "wellsfargo", "bankofamerica",
  "citibank", "vietcombank", "techcombank", "vietinbank", "bidv", "shopee",
  "lazada", "tiki", "steam", "spotify", "yahoo", "outlook", "tiktok", "dhl", "usps"
]);

const KNOWN_BRAND_DOMAINS = Object.freeze({
  google: ["google.com", "googleapis.com", "googleusercontent.com", "google-analytics.com", "gmail.com"],
  microsoft: ["microsoft.com", "microsoftonline.com", "microsoft365.com", "office.com", "live.com", "outlook.com", "azure.com", "windows.com", "xbox.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp", "amazon.com.au", "amazon.ca", "amazon.in"],
  paypal: ["paypal.com", "paypalobjects.com"],
  facebook: ["facebook.com", "fb.com", "messenger.com", "meta.com"],
  instagram: ["instagram.com"],
  linkedin: ["linkedin.com"],
  netflix: ["netflix.com"],
  whatsapp: ["whatsapp.com"],
  telegram: ["telegram.org", "t.me"],
  discord: ["discord.com", "discord.gg"],
  github: ["github.com", "githubusercontent.com"],
  adobe: ["adobe.com", "adobelogin.com"],
  dropbox: ["dropbox.com", "dropboxusercontent.com"],
  binance: ["binance.com"],
  coinbase: ["coinbase.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  bankofamerica: ["bankofamerica.com"],
  citibank: ["citibank.com", "citi.com"],
  vietcombank: ["vietcombank.com.vn"],
  techcombank: ["techcombank.com.vn"],
  vietinbank: ["vietinbank.vn"],
  bidv: ["bidv.com.vn"],
  shopee: ["shopee.vn", "shopee.com"],
  lazada: ["lazada.vn", "lazada.com"],
  tiki: ["tiki.vn"],
  steam: ["steamcommunity.com", "steampowered.com"],
  spotify: ["spotify.com"],
  yahoo: ["yahoo.com"],
  outlook: ["outlook.com", "office.com", "live.com"],
  tiktok: ["tiktok.com"],
  dhl: ["dhl.com"],
  usps: ["usps.com"]
});

const EDUCATION_SUFFIX_PATTERNS = [
  /(^|\.)edu$/, /(^|\.)edu\.[a-z]{2}$/, /(^|\.)ac\.[a-z]{2}$/,
  /(^|\.)school$/, /(^|\.)college$/, /(^|\.)university$/
];

const GOVERNMENT_SUFFIX_PATTERNS = [
  /(^|\.)gov$/, /(^|\.)gov\.[a-z]{2}$/, /(^|\.)go\.[a-z]{2}$/,
  /(^|\.)gob\.[a-z]{2}$/
];

const LOGIN_TOKENS = new Set(["login", "signin", "sign-in", "auth", "sso", "logon"]);
const SEARCH_TOKENS = new Set(["search", "find", "query", "results"]);
const ACCOUNT_TOKENS = new Set(["account", "profile", "settings", "dashboard", "portal"]);

const FEATURE_NAMES = Object.freeze([
  "urlLength",
  "rawUrlLength",
  "hostnameLength",
  "registrableDomainLength",
  "pathLength",
  "queryLength",
  "rawQueryLength",
  "fragmentLength",
  "subdomainDepth",
  "pathDepth",
  "dotCount",
  "hyphenCount",
  "digitCountHostname",
  "digitCountUrl",
  "specialCharCount",
  "percentEncodedCount",
  "queryParameterCount",
  "rawQueryParameterCount",
  "removedTrackingParameterCount",
  "phishingKeywordCount",
  "hostnameEntropy",
  "urlEntropy",
  "longestHostnameLabelLength",
  "longestPathTokenLength",
  "usesHttps",
  "hasCredentials",
  "isIpAddress",
  "isUrlShortener",
  "isPunycode",
  "hasHomoglyph",
  "isRiskyTld",
  "hasNonStandardPort",
  "hasDoubleSlashInPath",
  "hasSuspiciousExtension",
  "hostnameKeywordCount",
  "pathKeywordCount",
  "queryKeywordCount",
  "hostLabelCount",
  "pathTokenCount",
  "maxQueryValueLength",
  "meanQueryValueLength",
  "digitRatioHostname",
  "hyphenRatioHostname",
  "hasServerPageExtension",
  "isEducationDomain",
  "isGovernmentDomain",
  "brandTokenMismatch",
  "officialBrandDomain",
  "hasLoginPath",
  "hasSearchPath",
  "hasAccountPath",
  "containsUnicode",
  "longRandomHostnameLabel",
  "normalizedLengthRatio"
]);

function countMatches(text, regex) {
  return (String(text).match(regex) || []).length;
}

function shannonEntropy(text) {
  const value = String(text || "");
  if (!value.length) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function isIpAddress(hostname) {
  const host = String(hostname || "").replace(/^\[|\]$/g, "");
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) &&
    host.split(".").every(part => Number(part) >= 0 && Number(part) <= 255);
  const ipv6 = host.includes(":") && /^[0-9a-f:]+$/i.test(host);
  return ipv4 || ipv6;
}

function lastPathExtension(pathname) {
  const last = String(pathname || "").split("/").filter(Boolean).at(-1) || "";
  const clean = last.split(/[?#]/)[0];
  const index = clean.lastIndexOf(".");
  if (index <= 0 || index === clean.length - 1) return "";
  return clean.slice(index + 1).toLowerCase();
}

function longestLength(parts) {
  return parts.reduce((max, item) => Math.max(max, String(item).length), 0);
}

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function countKeywords(text) {
  const lower = decodeURIComponentSafe(String(text || "").toLowerCase());
  let count = 0;
  for (const keyword of PHISHING_KEYWORDS) {
    if (lower.includes(keyword)) count += 1;
  }
  return count;
}

function isTrackingParameter(name) {
  const normalized = String(name || "").toLowerCase();
  return TRACKING_PARAMETER_NAMES.has(normalized) ||
    TRACKING_PARAMETER_PREFIXES.some(prefix => normalized.startsWith(prefix));
}

function normalizeUrlForMl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return null;

  const rawHref = parsed.href;
  const rawQueryLength = parsed.search.length;
  const rawQueryParameterCount = [...parsed.searchParams.keys()].length;
  let removedTrackingParameterCount = 0;

  for (const key of [...parsed.searchParams.keys()]) {
    if (isTrackingParameter(key)) {
      parsed.searchParams.delete(key);
      removedTrackingParameterCount += 1;
    }
  }

  parsed.hash = "";

  return {
    parsed,
    rawHref,
    normalizedHref: parsed.href,
    rawQueryLength,
    rawQueryParameterCount,
    removedTrackingParameterCount
  };
}

function hasAnyToken(tokens, dictionary) {
  return tokens.some(token => dictionary.has(token));
}

function suffixMatches(publicSuffix, patterns) {
  return patterns.some(pattern => pattern.test(publicSuffix));
}

function getBrandSignals(hostname, registrableDomain) {
  const lowerHost = hostname.toLowerCase();
  const lowerRegistrableDomain = registrableDomain.toLowerCase().replace(/^www\./, "");
  let officialBrandDomain = 0;
  let brandTokenMismatch = 0;

  for (const brand of KNOWN_BRAND_TOKENS) {
    const officialDomains = KNOWN_BRAND_DOMAINS[brand] || [];
    const isOfficial = officialDomains.includes(lowerRegistrableDomain);
    if (isOfficial) officialBrandDomain = 1;
    if (lowerHost.includes(brand) && !isOfficial) brandTokenMismatch = 1;
  }
  return { officialBrandDomain, brandTokenMismatch };
}

function extractUrlMlFeatures(url, domainInfo = {}) {
  const normalized = normalizeUrlForMl(url);
  if (!normalized) return null;

  const {
    parsed, rawHref, normalizedHref, rawQueryLength,
    rawQueryParameterCount, removedTrackingParameterCount
  } = normalized;
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const registrableDomain = String(domainInfo.registrableDomain || hostname).toLowerCase();
  const publicSuffix = String(domainInfo.publicSuffix || hostname.split(".").at(-1) || "").toLowerCase();
  const subdomainDepth = Number.isInteger(domainInfo.subdomainDepth)
    ? domainInfo.subdomainDepth
    : Math.max(0, hostname.split(".").filter(Boolean).length - 2);
  const homoglyph = analyzeHomoglyph(registrableDomain);
  const pathname = parsed.pathname || "/";
  const pathTokens = pathname.toLowerCase().split(/[\/._-]+/).filter(Boolean);
  const hostLabels = hostname.split(".").filter(Boolean);
  const defaultPort = parsed.protocol === "https:" ? "443" : "80";
  const tld = publicSuffix.split(".").at(-1) || "";
  const extension = lastPathExtension(pathname);
  const queryText = parsed.searchParams.toString();
  const queryValues = [...parsed.searchParams.values()].map(value => String(value));
  const maxQueryValueLength = longestLength(queryValues);
  const meanQueryValueLength = queryValues.length
    ? queryValues.reduce((sum, value) => sum + value.length, 0) / queryValues.length
    : 0;
  const hostnameKeywordCount = countKeywords(hostname);
  const pathKeywordCount = countKeywords(pathname);
  const queryKeywordCount = countKeywords(queryText);
  const phishingKeywordCount = hostnameKeywordCount + pathKeywordCount + queryKeywordCount;
  const { officialBrandDomain, brandTokenMismatch } = getBrandSignals(hostname, registrableDomain);
  const longestHostnameLabel = hostLabels.reduce((current, item) =>
    item.length > current.length ? item : current, "");
  const longRandomHostnameLabel = (
    longestHostnameLabel.length >= 14 &&
    shannonEntropy(longestHostnameLabel) >= 3.3 &&
    /\d/.test(longestHostnameLabel)
  ) ? 1 : 0;
  const hostnameLength = Math.max(hostname.length, 1);

  const values = {
    urlLength: normalizedHref.length,
    rawUrlLength: rawHref.length,
    hostnameLength: hostname.length,
    registrableDomainLength: registrableDomain.length,
    pathLength: pathname.length,
    queryLength: parsed.search.length,
    rawQueryLength,
    fragmentLength: 0,
    subdomainDepth,
    pathDepth: pathname.split("/").filter(Boolean).length,
    dotCount: countMatches(hostname, /\./g),
    hyphenCount: countMatches(hostname, /-/g),
    digitCountHostname: countMatches(hostname, /\d/g),
    digitCountUrl: countMatches(normalizedHref, /\d/g),
    specialCharCount: countMatches(normalizedHref, /[^a-z0-9]/gi),
    percentEncodedCount: countMatches(normalizedHref, /%[0-9a-f]{2}/gi),
    queryParameterCount: [...parsed.searchParams.keys()].length,
    rawQueryParameterCount,
    removedTrackingParameterCount,
    phishingKeywordCount,
    hostnameEntropy: shannonEntropy(hostname),
    urlEntropy: shannonEntropy(normalizedHref),
    longestHostnameLabelLength: longestLength(hostLabels),
    longestPathTokenLength: longestLength(pathTokens),
    usesHttps: parsed.protocol === "https:" ? 1 : 0,
    hasCredentials: parsed.username || parsed.password ? 1 : 0,
    isIpAddress: Boolean(domainInfo.isIpAddress) || isIpAddress(hostname) ? 1 : 0,
    isUrlShortener: URL_SHORTENERS.has(registrableDomain) ? 1 : 0,
    isPunycode: homoglyph.isPunycode ? 1 : 0,
    hasHomoglyph: homoglyph.hasHomoglyph ? 1 : 0,
    isRiskyTld: RISKY_TLDS.has(tld) ? 1 : 0,
    hasNonStandardPort: parsed.port && parsed.port !== defaultPort ? 1 : 0,
    hasDoubleSlashInPath: /\/\//.test(pathname.slice(1)) ? 1 : 0,
    hasSuspiciousExtension: SUSPICIOUS_EXTENSIONS.has(extension) ? 1 : 0,
    hostnameKeywordCount,
    pathKeywordCount,
    queryKeywordCount,
    hostLabelCount: hostLabels.length,
    pathTokenCount: pathTokens.length,
    maxQueryValueLength,
    meanQueryValueLength,
    digitRatioHostname: countMatches(hostname, /\d/g) / hostnameLength,
    hyphenRatioHostname: countMatches(hostname, /-/g) / hostnameLength,
    hasServerPageExtension: SERVER_PAGE_EXTENSIONS.has(extension) ? 1 : 0,
    isEducationDomain: suffixMatches(publicSuffix, EDUCATION_SUFFIX_PATTERNS) ? 1 : 0,
    isGovernmentDomain: suffixMatches(publicSuffix, GOVERNMENT_SUFFIX_PATTERNS) ? 1 : 0,
    brandTokenMismatch,
    officialBrandDomain,
    hasLoginPath: hasAnyToken(pathTokens, LOGIN_TOKENS) ? 1 : 0,
    hasSearchPath: hasAnyToken(pathTokens, SEARCH_TOKENS) ? 1 : 0,
    hasAccountPath: hasAnyToken(pathTokens, ACCOUNT_TOKENS) ? 1 : 0,
    containsUnicode: /[^\x00-\x7F]/.test(rawHref) ? 1 : 0,
    longRandomHostnameLabel,
    normalizedLengthRatio: rawHref.length ? normalizedHref.length / rawHref.length : 1
  };

  return {
    featureNames: FEATURE_NAMES,
    featureVector: FEATURE_NAMES.map(name => Number(values[name]) || 0),
    values,
    metadata: {
      hostname,
      registrableDomain,
      publicSuffix,
      tld,
      pathExtension: extension,
      normalizedUrl: normalizedHref,
      removedTrackingParameterCount
    }
  };
}

export {
  FEATURE_NAMES,
  URL_SHORTENERS,
  RISKY_TLDS,
  PHISHING_KEYWORDS,
  SUSPICIOUS_EXTENSIONS,
  SERVER_PAGE_EXTENSIONS,
  TRACKING_PARAMETER_NAMES,
  TRACKING_PARAMETER_PREFIXES,
  KNOWN_BRAND_TOKENS,
  KNOWN_BRAND_DOMAINS,
  normalizeUrlForMl,
  extractUrlMlFeatures,
  shannonEntropy
};
