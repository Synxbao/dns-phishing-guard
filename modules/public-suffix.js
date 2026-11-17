// Public Suffix List parser.
// Data source is bundled at data/public_suffix_list.dat.

let exactRules = new Set();
let wildcardRules = new Set();
let exceptionRules = new Set();
let loaded = false;
let loadingPromise = null;

function normalizeHostname(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/^\.+|\.+$/g, "");
}

function isIpAddress(hostname) {
  const host = normalizeHostname(hostname).replace(/^\[|\]$/g, "");
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) &&
    host.split(".").every(part => Number(part) >= 0 && Number(part) <= 255);
  const ipv6 = host.includes(":") && /^[0-9a-f:]+$/i.test(host);
  return ipv4 || ipv6;
}

function initializeFromText(text) {
  exactRules = new Set();
  wildcardRules = new Set();
  exceptionRules = new Set();

  for (const rawLine of String(text || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("//")) continue;

    if (line.startsWith("!")) {
      exceptionRules.add(line.slice(1).toLowerCase());
    } else if (line.startsWith("*.")) {
      wildcardRules.add(line.slice(2).toLowerCase());
    } else {
      exactRules.add(line.toLowerCase());
    }
  }

  loaded = exactRules.size > 0;
  return {
    exact: exactRules.size,
    wildcard: wildcardRules.size,
    exceptions: exceptionRules.size
  };
}

async function loadPublicSuffixList() {
  if (loaded) return true;
  if (loadingPromise) return loadingPromise;

  loadingPromise = (async () => {
    try {
      const response = await fetch(chrome.runtime.getURL("data/public_suffix_list.dat"));
      if (!response.ok) throw new Error(`PSL HTTP ${response.status}`);
      initializeFromText(await response.text());
      return loaded;
    } catch (error) {
      console.warn("Không tải được Public Suffix List:", error);
      // Minimal fallback for common Vietnamese and global suffixes.
      initializeFromText(`
com
net
org
edu
gov
vn
com.vn
net.vn
org.vn
edu.vn
gov.vn
uk
co.uk
org.uk
ac.uk
au
com.au
jp
co.jp
`);
      return false;
    }
  })();

  return loadingPromise;
}

function findRule(labels) {
  let best = { type: "default", labelCount: 1, rule: "*" };

  for (let i = 0; i < labels.length; i += 1) {
    const candidate = labels.slice(i).join(".");

    if (exceptionRules.has(candidate)) {
      return {
        type: "exception",
        labelCount: Math.max(1, labels.length - i - 1),
        rule: `!${candidate}`
      };
    }

    if (exactRules.has(candidate)) {
      const count = labels.length - i;
      if (count > best.labelCount) {
        best = { type: "exact", labelCount: count, rule: candidate };
      }
    }

    if (i < labels.length - 1) {
      const wildcardBase = labels.slice(i + 1).join(".");
      if (wildcardRules.has(wildcardBase)) {
        const count = labels.length - i;
        if (count > best.labelCount) {
          best = { type: "wildcard", labelCount: count, rule: `*.${wildcardBase}` };
        }
      }
    }
  }

  return best;
}

function getDomainParts(hostname) {
  const normalized = normalizeHostname(hostname);

  if (!normalized) {
    return {
      hostname: "",
      publicSuffix: "",
      registrableDomain: "",
      subdomain: "",
      subdomainDepth: 0,
      isIpAddress: false,
      rule: null
    };
  }

  if (isIpAddress(normalized) || normalized === "localhost") {
    return {
      hostname: normalized,
      publicSuffix: "",
      registrableDomain: normalized,
      subdomain: "",
      subdomainDepth: 0,
      isIpAddress: isIpAddress(normalized),
      rule: null
    };
  }

  const labels = normalized.split(".").filter(Boolean);
  if (labels.length === 1) {
    return {
      hostname: normalized,
      publicSuffix: labels[0],
      registrableDomain: normalized,
      subdomain: "",
      subdomainDepth: 0,
      isIpAddress: false,
      rule: "*"
    };
  }

  const matched = findRule(labels);
  const suffixCount = Math.min(labels.length, matched.labelCount);
  const publicSuffix = labels.slice(-suffixCount).join(".");
  const registrableDomain = labels.length > suffixCount
    ? labels.slice(-(suffixCount + 1)).join(".")
    : normalized;
  const subdomainLabels = labels.slice(0, Math.max(0, labels.length - suffixCount - 1));

  return {
    hostname: normalized,
    publicSuffix,
    registrableDomain,
    subdomain: subdomainLabels.join("."),
    subdomainDepth: subdomainLabels.length,
    isIpAddress: false,
    rule: matched.rule,
    ruleType: matched.type
  };
}

function isLoaded() {
  return loaded;
}

export {
  loadPublicSuffixList,
  initializeFromText,
  getDomainParts,
  normalizeHostname,
  isIpAddress,
  isLoaded
};
