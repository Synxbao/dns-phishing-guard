// Recognize normal OAuth/OpenID Connect navigation through official identity providers.
// This module does not declare the relying-party application trustworthy. It only marks
// the cross-domain transition as expected authentication flow while the user is on the
// provider's official HTTPS domain.

const IDENTITY_PROVIDERS = [
  {
    name: "Google",
    hosts: ["accounts.google.com"],
    domains: ["google.com"],
    pathPatterns: [
      /^\/v\d+\/signin\//i,
      /^\/signin\//i,
      /^\/o\/oauth2\//i,
      /^\/ServiceLogin/i,
      /^\/AccountChooser/i
    ]
  },
  {
    name: "Microsoft",
    hosts: ["login.microsoftonline.com", "login.live.com"],
    domains: ["microsoftonline.com", "live.com"],
    pathPatterns: [
      /\/oauth2\//i,
      /\/authorize/i,
      /\/login/i,
      /\/common\/oauth/i
    ]
  },
  {
    name: "Apple",
    hosts: ["appleid.apple.com"],
    domains: ["apple.com"],
    pathPatterns: [/\/auth\/authorize/i, /\/signin/i]
  }
];

const REDIRECT_PARAMETER_NAMES = [
  "redirect_uri", "redirect_url", "return_url", "return_to", "continue", "callback", "target"
];

function safeUrl(value, base) {
  try {
    return new URL(String(value || ""), base);
  } catch {
    return null;
  }
}

function decodeRepeated(value, rounds = 3) {
  let current = String(value || "");
  for (let index = 0; index < rounds; index += 1) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
      current = decoded;
    } catch {
      break;
    }
  }
  return current;
}

function providerForUrl(rawUrl) {
  const url = safeUrl(rawUrl);
  if (!url || url.protocol !== "https:") return null;
  const hostname = url.hostname.toLowerCase();
  return IDENTITY_PROVIDERS.find(provider => (
    provider.hosts.includes(hostname) && provider.pathPatterns.some(pattern => pattern.test(url.pathname))
  )) || null;
}

function extractRedirectTarget(rawUrl) {
  const url = safeUrl(rawUrl);
  if (!url) return null;

  for (const name of REDIRECT_PARAMETER_NAMES) {
    const rawValue = url.searchParams.get(name);
    if (!rawValue) continue;
    const decoded = decodeRepeated(rawValue);
    const target = safeUrl(decoded, url.origin);
    if (target && ["http:", "https:"].includes(target.protocol)) return target;
  }
  return null;
}

function registrableDomain(rawUrl, getDomainParts) {
  const url = safeUrl(rawUrl);
  if (!url) return "";
  try {
    return getDomainParts(url.hostname)?.registrableDomain || url.hostname.toLowerCase();
  } catch {
    return url.hostname.toLowerCase();
  }
}

function isTrustedIdentityProviderUrl(rawUrl) {
  const provider = providerForUrl(rawUrl);
  if (!provider) return null;
  const url = safeUrl(rawUrl);
  const hasAuthShape = Boolean(
    url.searchParams.get("client_id") ||
    url.searchParams.get("response_type") ||
    url.searchParams.get("scope") ||
    url.searchParams.get("continue") ||
    url.searchParams.get("redirect_uri") ||
    /signin|login|oauth|authorize|accountchooser/i.test(url.pathname)
  );
  if (!hasAuthShape) return null;
  return {
    providerName: provider.name,
    providerHost: url.hostname.toLowerCase(),
    providerDomain: provider.domains[0]
  };
}

function analyzeFederatedAuthRedirect(initialUrl, finalUrl, getDomainParts) {
  const providerContext = isTrustedIdentityProviderUrl(finalUrl);
  if (!providerContext) {
    return {
      isFederatedAuthFlow: false,
      providerName: null,
      providerHost: null,
      relyingPartyDomain: null,
      redirectTargetDomain: null
    };
  }

  const initialDomain = registrableDomain(initialUrl, getDomainParts);
  const redirectTarget = extractRedirectTarget(finalUrl);
  const redirectTargetDomain = redirectTarget
    ? registrableDomain(redirectTarget.href, getDomainParts)
    : "";

  return {
    isFederatedAuthFlow: true,
    providerName: providerContext.providerName,
    providerHost: providerContext.providerHost,
    relyingPartyDomain: redirectTargetDomain || initialDomain || null,
    redirectTargetDomain: redirectTargetDomain || null
  };
}

export {
  IDENTITY_PROVIDERS,
  isTrustedIdentityProviderUrl,
  analyzeFederatedAuthRedirect,
  extractRedirectTarget
};
