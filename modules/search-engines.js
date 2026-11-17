const SEARCH_ENGINE_PAGE_RULES = Object.freeze([
  {
    id: "GOOGLE",
    hosts: ["google.com", "www.google.com"],
    paths: ["*"]
  },
  {
    id: "BING",
    hosts: ["bing.com", "www.bing.com"],
    paths: ["*"]
  },
  {
    id: "DUCKDUCKGO",
    hosts: ["duckduckgo.com", "www.duckduckgo.com"],
    paths: ["*"]
  },
  {
    id: "YAHOO",
    hosts: ["yahoo.com", "www.yahoo.com", "search.yahoo.com"],
    paths: ["*"]
  },
  {
    id: "BRAVE_SEARCH",
    hosts: ["search.brave.com"],
    paths: ["*"]
  },
  {
    id: "COCCOC",
    hosts: ["coccoc.com", "www.coccoc.com", "search.coccoc.com"],
    paths: ["*"]
  }
]);

function normalizePath(pathname) {
  const value = String(pathname || "/").replace(/\/{2,}/g, "/");
  return value || "/";
}

function matchesPath(pathname, allowedPath) {
  if (allowedPath === "*") return true;
  if (allowedPath === "/") return pathname === "/";
  return pathname === allowedPath || pathname.startsWith(`${allowedPath}/`);
}

function classifySearchEnginePage(value) {
  let parsed;
  try {
    parsed = value instanceof URL ? value : new URL(String(value || ""));
  } catch {
    return { isSearchEngineHome: false, searchEngineId: null };
  }

  if (!/^https?:$/.test(parsed.protocol)) {
    return { isSearchEngineHome: false, searchEngineId: null };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const pathname = normalizePath(parsed.pathname);
  const rule = SEARCH_ENGINE_PAGE_RULES.find(item =>
    item.hosts.includes(hostname) && item.paths.some(path => matchesPath(pathname, path))
  );

  return rule
    ? { isSearchEngineHome: true, searchEngineId: rule.id }
    : { isSearchEngineHome: false, searchEngineId: null };
}

function isSearchEngineHome(value) {
  return classifySearchEnginePage(value).isSearchEngineHome;
}

export {
  SEARCH_ENGINE_PAGE_RULES,
  classifySearchEnginePage,
  isSearchEngineHome
};
