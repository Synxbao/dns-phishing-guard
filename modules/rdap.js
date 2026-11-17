// RDAP domain-age lookup with timeout and 24-hour cache.

const RDAP_CACHE_TTL = 24 * 60 * 60 * 1000;
const RDAP_TIMEOUT_MS = 5000;
const RDAP_SOURCES = [
  "https://rdap.org/domain/",
  "https://rdap.verisign.com/com/v1/domain/",
  "https://rdap.markmonitor.com/rdap/domain/"
];

async function getRdapCache(domain) {
  const key = `rdap_cache_${domain}`;
  const data = await chrome.storage.local.get(key);
  const cached = data[key];

  if (!cached) return { found: false, value: null };

  if (Date.now() - cached.cachedAt > RDAP_CACHE_TTL) {
    await chrome.storage.local.remove(key);
    return { found: false, value: null };
  }

  return { found: true, value: cached.value };
}

async function setRdapCache(domain, value) {
  await chrome.storage.local.set({
    [`rdap_cache_${domain}`]: {
      value,
      cachedAt: Date.now()
    }
  });
}

async function fetchJsonWithTimeout(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RDAP_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json, application/json" }
    });
    if (!response.ok) return null;
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

function extractRegistrationEvent(data) {
  const acceptedActions = new Set([
    "registration",
    "domain registration",
    "registrar registration"
  ]);

  return data?.events?.find(event =>
    acceptedActions.has(String(event.eventAction || "").toLowerCase())
  );
}

async function checkDomainAge(domain) {
  const cached = await getRdapCache(domain);
  if (cached.found) {
    return {
      value: cached.value,
      cacheHit: true,
      available: cached.value !== null
    };
  }

  for (const base of RDAP_SOURCES) {
    const url = `${base}${domain}`;

    try {
      const data = await fetchJsonWithTimeout(url);
      if (!data) continue;

      const event = extractRegistrationEvent(data);
      if (!event?.eventDate) continue;

      const createdDate = new Date(event.eventDate);
      if (Number.isNaN(createdDate.getTime())) continue;

      const ageDays = Math.max(
        0,
        Math.floor((Date.now() - createdDate.getTime()) / 86400000)
      );

      const result = {
        created: createdDate.toISOString(),
        ageDays,
        source: url
      };

      await setRdapCache(domain, result);
      return { value: result, cacheHit: false, available: true };
    } catch {
      // Thử nguồn tiếp theo.
    }
  }

  await setRdapCache(domain, null);
  return { value: null, cacheHit: false, available: false };
}

export { checkDomainAge, RDAP_CACHE_TTL };
