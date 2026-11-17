// Optional threat-intelligence backend adapter.
// The endpoint is disabled by default. It should accept POST { url } and return:
// { checked: true, isUnsafe: boolean, threats: string[], source: string }

import { buildThreatIntelPayload } from "./url-privacy.js";

const CACHE_TTL = 15 * 60 * 1000;

function hashText(text) {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function normalizeResponse(value) {
  return {
    checked: Boolean(value?.checked),
    isUnsafe: Boolean(value?.isUnsafe),
    threats: Array.isArray(value?.threats)
      ? value.threats.map(item => String(item)).slice(0, 20)
      : [],
    source: String(value?.source || "Threat Intelligence"),
    error: value?.error ? String(value.error) : null
  };
}

async function checkThreatIntel(url, settings = {}) {
  if (!settings.threatIntelEnabled || !settings.threatIntelEndpoint) {
    return {
      checked: false,
      isUnsafe: false,
      threats: [],
      source: "Chưa cấu hình",
      disabled: true
    };
  }

  let endpoint;
  try {
    endpoint = new URL(settings.threatIntelEndpoint);
    if (endpoint.protocol !== "https:" && endpoint.hostname !== "localhost") {
      throw new Error("Endpoint phải dùng HTTPS");
    }
  } catch (error) {
    return normalizeResponse({ checked: false, error: error.message });
  }

  const payload = buildThreatIntelPayload(url);
  const key = `threat_cache_${hashText(payload.url)}`;
  const cachedData = await chrome.storage.local.get(key);
  const cached = cachedData[key];
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL) {
    return { ...normalizeResponse(cached.value), cacheHit: true };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(endpoint.href, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const value = normalizeResponse(await response.json());
    await chrome.storage.local.set({ [key]: { value, cachedAt: Date.now() } });
    return { ...value, cacheHit: false };
  } catch (error) {
    return normalizeResponse({
      checked: false,
      error: error.name === "AbortError" ? "Hết thời gian chờ" : error.message
    });
  } finally {
    clearTimeout(timer);
  }
}

export { checkThreatIntel };
