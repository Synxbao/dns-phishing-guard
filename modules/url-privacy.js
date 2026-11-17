// Shared URL minimization helpers for local storage and optional external checks.

const MAX_QUERY_KEYS = 32;

function parseHttpUrl(rawUrl) {
  try {
    const url = new URL(String(rawUrl || ""));
    return ["http:", "https:"].includes(url.protocol) ? url : null;
  } catch {
    return null;
  }
}

function redactUrl(rawUrl, { keepQueryKeys = true } = {}) {
  const url = parseHttpUrl(rawUrl);
  if (!url) return String(rawUrl || "").slice(0, 4096);

  const keys = keepQueryKeys
    ? [...new Set([...url.searchParams.keys()])].slice(0, MAX_QUERY_KEYS)
    : [];
  url.username = "";
  url.password = "";
  url.search = "";
  url.hash = "";
  for (const key of keys) url.searchParams.append(key, "<redacted>");
  return url.href;
}

function sanitizeUrlForHistory(rawUrl) {
  return redactUrl(rawUrl, { keepQueryKeys: true });
}

function buildThreatIntelPayload(rawUrl) {
  const url = parseHttpUrl(rawUrl);
  if (!url) {
    return {
      url: redactUrl(rawUrl),
      hostname: "",
      path: "",
      privacy: "query-values-and-fragment-redacted"
    };
  }

  return {
    url: redactUrl(url.href, { keepQueryKeys: true }),
    hostname: url.hostname.toLowerCase(),
    path: url.pathname.slice(0, 2048),
    privacy: "query-values-and-fragment-redacted"
  };
}

export {
  buildThreatIntelPayload,
  redactUrl,
  sanitizeUrlForHistory
};
