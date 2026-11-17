// Blacklist / whitelist / known-domain management.

let BLACKLIST = [];
let WHITELIST = [];
let KNOWN_DOMAINS = [];
let PROTECTED_PAYMENT_DOMAINS = [];
let PROTECTED_GAME_DOMAINS = [];
let loadPromise = null;

function normalizeDomain(domain) {
  return String(domain || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/$/, "");
}

async function loadJsonValue(path, fallback) {
  try {
    const response = await fetch(chrome.runtime.getURL(path));
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.warn(`Không load được ${path}:`, error);
    return fallback;
  }
}

async function loadJson(path) {
  const value = await loadJsonValue(path, []);
  return Array.isArray(value) ? value.map(normalizeDomain).filter(Boolean) : [];
}

async function loadProtectedDomains(path) {
  const value = await loadJsonValue(path, {});
  const entries = Array.isArray(value) ? value : value?.entries;
  if (!Array.isArray(entries)) return [];
  return entries
    .map(item => normalizeDomain(typeof item === "string" ? item : item?.domain))
    .filter(Boolean);
}

function unique(items) {
  return [...new Set(items.map(normalizeDomain).filter(Boolean))];
}

function matchesEntry(domain, entry) {
  const normalized = normalizeDomain(domain);
  const target = normalizeDomain(entry);
  return normalized === target || normalized.endsWith(`.${target}`);
}

async function loadAllLists() {
  loadPromise = (async () => {
    const [knownBase, protectedPaymentBase, protectedGameBase, blacklistBase, whitelistBase, stored] = await Promise.all([
      loadJson("data/known-domains.json"),
      loadProtectedDomains("data/protected-payment-domains.json"),
      loadProtectedDomains("data/protected-game-domains.json"),
      loadJson("data/blacklist.json"),
      loadJson("data/whitelist.json"),
      chrome.storage.local.get(["customBlacklist", "customWhitelist"])
    ]);

    KNOWN_DOMAINS = unique(knownBase);
    PROTECTED_PAYMENT_DOMAINS = unique(protectedPaymentBase);
    PROTECTED_GAME_DOMAINS = unique(protectedGameBase);
    BLACKLIST = unique([...blacklistBase, ...(stored.customBlacklist || [])]);
    WHITELIST = unique([...whitelistBase, ...(stored.customWhitelist || [])]);

    return { KNOWN_DOMAINS, PROTECTED_PAYMENT_DOMAINS, PROTECTED_GAME_DOMAINS, BLACKLIST, WHITELIST };
  })();

  return loadPromise;
}

async function ensureListsLoaded() {
  if (!loadPromise) return loadAllLists();
  return loadPromise;
}

function getKnownDomains() {
  return KNOWN_DOMAINS;
}

function getProtectedPaymentDomains() {
  return [...PROTECTED_PAYMENT_DOMAINS];
}

function getProtectedGameDomains() {
  return [...PROTECTED_GAME_DOMAINS];
}

function getProtectedTyposquatDomains() {
  return unique([...PROTECTED_PAYMENT_DOMAINS, ...PROTECTED_GAME_DOMAINS]);
}

function getTyposquatReferenceDomains() {
  return unique([...KNOWN_DOMAINS, ...getProtectedTyposquatDomains()]);
}

function getBlacklist() {
  return [...BLACKLIST];
}

function getWhitelist() {
  return [...WHITELIST];
}

function isBlacklisted(domain) {
  return BLACKLIST.some(entry => matchesEntry(domain, entry));
}

function isWhitelisted(domain) {
  return WHITELIST.some(entry => matchesEntry(domain, entry));
}

async function updateCustomList(storageKey, domain, shouldAdd) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return;

  const stored = await chrome.storage.local.get(storageKey);
  const set = new Set((stored[storageKey] || []).map(normalizeDomain));
  if (shouldAdd) set.add(normalized);
  else set.delete(normalized);

  await chrome.storage.local.set({ [storageKey]: [...set] });
  await loadAllLists();
}

async function addToWhitelist(domain) {
  await updateCustomList("customWhitelist", domain, true);
}

async function removeFromWhitelist(domain) {
  await updateCustomList("customWhitelist", domain, false);
}

async function addToBlacklist(domain) {
  await updateCustomList("customBlacklist", domain, true);
}

async function removeFromBlacklist(domain) {
  await updateCustomList("customBlacklist", domain, false);
}

export {
  normalizeDomain,
  loadAllLists,
  ensureListsLoaded,
  getKnownDomains,
  getProtectedPaymentDomains,
  getProtectedGameDomains,
  getProtectedTyposquatDomains,
  getTyposquatReferenceDomains,
  getBlacklist,
  getWhitelist,
  isBlacklisted,
  isWhitelisted,
  addToWhitelist,
  removeFromWhitelist,
  addToBlacklist,
  removeFromBlacklist
};
