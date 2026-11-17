const SITE_CONTEXT_TYPES = Object.freeze({
  PUBLIC_WEB: "PUBLIC_WEB",
  LOCAL_DEVELOPMENT: "LOCAL_DEVELOPMENT",
  PRIVATE_NETWORK: "PRIVATE_NETWORK"
});

const LOCAL_HOST_SUFFIXES = [".localhost", ".test", ".invalid"];
const PRIVATE_HOST_SUFFIXES = [".local", ".internal", ".lan", ".home.arpa"];

function normalizeHostname(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
}

function parseIpv4(hostname) {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return null;
  const parts = hostname.split(".").map(Number);
  return parts.every(part => part >= 0 && part <= 255) ? parts : null;
}

function isIpv6(hostname) {
  return hostname.includes(":") && /^[0-9a-f:.]+$/i.test(hostname);
}

function isLoopbackIpv4(parts) {
  return Boolean(parts && parts[0] === 127);
}

function isPrivateIpv4(parts) {
  if (!parts) return false;
  return parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127);
}

function isLoopbackIpv6(hostname) {
  return hostname === "::1" || hostname === "0:0:0:0:0:0:0:1";
}

function isPrivateIpv6(hostname) {
  const first = hostname.split(":", 1)[0];
  if (/^f[cd]/i.test(first)) return true;
  if (/^fe[89ab]/i.test(first)) return true;
  return /^::ffff:(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/i.test(hostname);
}

function result(type, hostname, reason, details = {}) {
  const isPublic = type === SITE_CONTEXT_TYPES.PUBLIC_WEB;
  return {
    type,
    hostname,
    reason,
    isPublic,
    skipPublicReputation: !isPublic,
    ...details
  };
}

function classifySiteContext(input) {
  let hostname = "";
  try {
    const parsed = input instanceof URL ? input : new URL(String(input || ""));
    hostname = normalizeHostname(parsed.hostname);
  } catch {
    hostname = normalizeHostname(input);
  }

  if (!hostname) {
    return result(SITE_CONTEXT_TYPES.PUBLIC_WEB, hostname, "missing-hostname");
  }

  if (
    hostname === "localhost" ||
    hostname === "0.0.0.0" ||
    hostname === "::" ||
    LOCAL_HOST_SUFFIXES.some(suffix => hostname.endsWith(suffix))
  ) {
    return result(SITE_CONTEXT_TYPES.LOCAL_DEVELOPMENT, hostname, "local-development-host", {
      isLoopback: true
    });
  }

  const ipv4 = parseIpv4(hostname);
  if (isLoopbackIpv4(ipv4) || isLoopbackIpv6(hostname)) {
    return result(SITE_CONTEXT_TYPES.LOCAL_DEVELOPMENT, hostname, "loopback-address", {
      isLoopback: true,
      isIpAddress: true
    });
  }

  if (isPrivateIpv4(ipv4) || (isIpv6(hostname) && isPrivateIpv6(hostname))) {
    return result(SITE_CONTEXT_TYPES.PRIVATE_NETWORK, hostname, "private-network-address", {
      isPrivateNetwork: true,
      isIpAddress: true
    });
  }

  if (
    (!hostname.includes(".") && !ipv4 && !isIpv6(hostname)) ||
    PRIVATE_HOST_SUFFIXES.some(suffix => hostname.endsWith(suffix))
  ) {
    return result(SITE_CONTEXT_TYPES.PRIVATE_NETWORK, hostname, "private-network-host", {
      isPrivateNetwork: true
    });
  }

  return result(SITE_CONTEXT_TYPES.PUBLIC_WEB, hostname, "public-web-host", {
    isIpAddress: Boolean(ipv4) || isIpv6(hostname)
  });
}

export {
  SITE_CONTEXT_TYPES,
  classifySiteContext,
  isPrivateIpv4,
  isPrivateIpv6,
  isLoopbackIpv4,
  isLoopbackIpv6
};
