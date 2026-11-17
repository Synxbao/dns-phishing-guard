// DNR blocking and restricted-mode helpers.

const BLOCK_RULE_MIN = 10000;
const BLOCK_RULE_RANGE = 800000000;
const ALLOW_RULE_BASE = 900000000;
const STRICT_RULE_BASE = 1400000000;
const SAFE_PREVIEW_RULE_BASE = 1800000000;
const ALLOW_ONCE_KEY_PREFIX = "allow_once_";

// Serialize dynamic-rule synchronization so two lifecycle/storage events
// cannot add the same rule IDs at the same time.
let dynamicSyncQueue = Promise.resolve();

function stableHash(text) {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function tabScopedRuleId(base, tabId) {
  return base + (Math.abs(Number(tabId)) % 300000000);
}

function normalizeBlockedDomains(domains) {
  return [...new Set(
    (domains || [])
      .map(item => String(item || "").trim().toLowerCase())
      .filter(Boolean)
  )].slice(0, 4500);
}

async function syncBlockedDomainsInternal(normalized) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const managedRuleIds = [...new Set(
    existing
      .filter(rule => rule.id >= BLOCK_RULE_MIN && rule.id < ALLOW_RULE_BASE)
      .map(rule => rule.id)
  )];

  const blockedPageUrl = chrome.runtime.getURL("blocked.html");
  const rules = normalized.map((domain, index) => ({
    id: BLOCK_RULE_MIN + index,
    priority: 100,
    action: {
      type: "redirect",
      redirect: { url: `${blockedPageUrl}?domain=${encodeURIComponent(domain)}` }
    },
    condition: {
      requestDomains: [domain],
      resourceTypes: ["main_frame"]
    }
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: managedRuleIds,
    addRules: rules
  });

  return rules.length;
}

function syncBlockedDomains(domains) {
  const normalized = normalizeBlockedDomains(domains);

  const task = dynamicSyncQueue
    .catch(() => {})
    .then(() => syncBlockedDomainsInternal(normalized));

  dynamicSyncQueue = task.catch(() => {});
  return task;
}

async function allowDomainOnce(tabId, domain) {
  const ruleId = tabScopedRuleId(ALLOW_RULE_BASE, tabId);
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [ruleId],
    addRules: [{
      id: ruleId,
      priority: 1000,
      action: { type: "allow" },
      condition: {
        tabIds: [tabId],
        requestDomains: [domain],
        resourceTypes: ["main_frame"]
      }
    }]
  });
  await chrome.storage.session.set({
    [`${ALLOW_ONCE_KEY_PREFIX}${tabId}`]: {
      tabId,
      domain,
      ruleId,
      createdAt: Date.now()
    }
  });
  return ruleId;
}

async function consumeAllowDomainOnce(tabId) {
  const key = `${ALLOW_ONCE_KEY_PREFIX}${tabId}`;
  const data = await chrome.storage.session.get(key);
  const metadata = data[key] || null;
  if (!metadata) return null;
  const ruleId = metadata.ruleId || tabScopedRuleId(ALLOW_RULE_BASE, tabId);
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] }).catch(() => {});
  await chrome.storage.session.remove(key).catch(() => {});
  return metadata;
}

async function enableStrictMode(tabId) {
  const ruleId = tabScopedRuleId(STRICT_RULE_BASE, tabId);
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [ruleId],
    addRules: [{
      id: ruleId,
      priority: 500,
      action: { type: "block" },
      condition: {
        tabIds: [tabId],
        domainType: "thirdParty",
        resourceTypes: ["script", "sub_frame", "object"]
      }
    }]
  });
  await chrome.storage.session.set({ [`strict_${tabId}`]: true });
  return ruleId;
}

async function disableStrictMode(tabId) {
  const ruleId = tabScopedRuleId(STRICT_RULE_BASE, tabId);
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] });
  await chrome.storage.session.remove(`strict_${tabId}`);
}

async function isStrictModeEnabled(tabId) {
  const data = await chrome.storage.session.get(`strict_${tabId}`);
  return Boolean(data[`strict_${tabId}`]);
}

async function enableSafePreviewMode(tabId) {
  const ruleId = tabScopedRuleId(SAFE_PREVIEW_RULE_BASE, tabId);
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [ruleId],
    addRules: [{
      id: ruleId,
      priority: 2000,
      action: { type: "block" },
      condition: {
        tabIds: [tabId],
        resourceTypes: [
          "script", "object", "xmlhttprequest", "ping", "media",
          "font", "websocket"
        ]
      }
    }]
  });
  await chrome.storage.session.set({ [`safe_preview_${tabId}`]: true });
  return ruleId;
}

async function cleanupTabRules(tabId) {
  const ids = [
    tabScopedRuleId(ALLOW_RULE_BASE, tabId),
    tabScopedRuleId(STRICT_RULE_BASE, tabId),
    tabScopedRuleId(SAFE_PREVIEW_RULE_BASE, tabId)
  ];
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }).catch(() => {});
  await chrome.storage.session.remove([
    `${ALLOW_ONCE_KEY_PREFIX}${tabId}`,
    `block_seen_${tabId}`,
    `strict_${tabId}`,
    `safe_preview_${tabId}`
  ]).catch(() => {});
}

export {
  syncBlockedDomains,
  allowDomainOnce,
  consumeAllowDomainOnce,
  enableStrictMode,
  disableStrictMode,
  isStrictModeEnabled,
  enableSafePreviewMode,
  cleanupTabRules
};
