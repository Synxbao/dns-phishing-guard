(() => {
  const DATA_PATH = "data/brand-rules.json";
  const EMPTY_DATA = Object.freeze({
    schemaVersion: 1,
    trustAllowlist: false,
    officialClaimTerms: [],
    rules: []
  });

  let cachedData = EMPTY_DATA;
  let loadPromise = null;

  function foldText(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/đ/g, "d")
      .replace(/Đ/g, "D")
      .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
      .replace(/[‐‑‒–—―_\-\/\\|.]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  }

  function normalizeDomain(value) {
    return String(value || "")
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/^www\./, "")
      .replace(/\/$/, "");
  }

  function uniqueStrings(values, mapper = value => String(value || "").trim()) {
    return [...new Set((Array.isArray(values) ? values : []).map(mapper).filter(Boolean))];
  }

  function normalizeBrandRuleData(value) {
    const input = value && typeof value === "object" ? value : {};
    const rules = (Array.isArray(input.rules) ? input.rules : [])
      .map(rule => ({
        id: String(rule?.id || "").trim(),
        name: String(rule?.name || "").trim(),
        vertical: String(rule?.vertical || "general").trim(),
        minimumRepeatedMentions: Math.max(1, Number(rule?.minimumRepeatedMentions) || 3),
        terms: uniqueStrings(rule?.terms),
        domains: uniqueStrings(rule?.domains, normalizeDomain),
        authorizedDomains: uniqueStrings(rule?.authorizedDomains, normalizeDomain),
        sourceRefs: uniqueStrings(rule?.sourceRefs),
        verificationStatus: String(rule?.verificationStatus || "legacy").trim()
      }))
      .filter(rule => rule.id && rule.name && rule.terms.length > 0 && rule.domains.length > 0);

    return {
      schemaVersion: Number(input.schemaVersion) || 1,
      purpose: String(input.purpose || "runtime-brand-rules"),
      trustAllowlist: input.trustAllowlist === true,
      snapshotDate: String(input.snapshotDate || ""),
      officialClaimTerms: uniqueStrings(input.officialClaimTerms),
      sources: Array.isArray(input.sources) ? input.sources : [],
      rules,
      unresolved: Array.isArray(input.unresolved) ? input.unresolved : []
    };
  }

  function sameOrSubdomain(hostname, domain) {
    const host = normalizeDomain(hostname);
    const target = normalizeDomain(domain);
    return Boolean(target && (host === target || host.endsWith(`.${target}`)));
  }

  function isShortToken(term) {
    return /^[a-z0-9]{1,3}$/.test(term);
  }

  function containsTerm(text, term) {
    if (!term) return false;
    if (!isShortToken(term)) return text.includes(term);
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(^|[^a-z0-9])${escaped}(?=$|[^a-z0-9])`, "i").test(text);
  }

  function countTermOccurrences(text, term) {
    if (!term) return 0;
    if (isShortToken(term)) {
      const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return [...text.matchAll(new RegExp(`(^|[^a-z0-9])${escaped}(?=$|[^a-z0-9])`, "gi"))].length;
    }
    let count = 0;
    let offset = 0;
    while ((offset = text.indexOf(term, offset)) !== -1) {
      count += 1;
      offset += Math.max(1, term.length);
    }
    return count;
  }

  function analyzeBrandPresentation(options = {}) {
    const data = options.data || cachedData;
    const rules = Array.isArray(options.rules) ? options.rules : (data.rules || []);
    const text = foldText(options.text);
    const prominentText = foldText(options.prominentText);
    const currentDomain = normalizeDomain(options.currentDomain);
    const officialClaimTerms = uniqueStrings(
      options.officialClaimTerms || data.officialClaimTerms,
      foldText
    );
    const officialClaimHits = officialClaimTerms.filter(term => containsTerm(text, term));
    const matches = [];

    for (const rule of rules) {
      const foldedTerms = uniqueStrings(rule.terms, foldText);
      const mentionCount = foldedTerms.reduce(
        (total, term) => total + countTermOccurrences(text, term),
        0
      );
      const mentionsProminently = foldedTerms.some(term => containsTerm(prominentText, term));
      const presentsBrandAsPageIdentity = mentionsProminently ||
        mentionCount >= Math.max(1, Number(rule.minimumRepeatedMentions) || 3);
      if (!presentsBrandAsPageIdentity) continue;

      const acceptedDomains = [...(rule.domains || []), ...(rule.authorizedDomains || [])];
      matches.push({
        rule,
        mentionCount,
        mentionsProminently,
        presentsBrandAsPageIdentity,
        matchesBrandDomain: acceptedDomains.some(domain => sameOrSubdomain(currentDomain, domain))
      });
    }

    matches.sort((left, right) =>
      Number(right.mentionsProminently) - Number(left.mentionsProminently) ||
      right.mentionCount - left.mentionCount
    );

    return {
      officialClaim: officialClaimHits.length > 0,
      officialClaimHits,
      matches
    };
  }

  function isGameBrandRule(rule) {
    return String(rule?.vertical || "").startsWith("game");
  }

  function deriveCommerceBrandSignals(presentation, options = {}) {
    const matches = Array.isArray(presentation?.matches) ? presentation.matches : [];
    const hasSensitiveCommerceAction = Boolean(options.hasSensitiveCommerceAction);
    const hasSensitiveTransactionInput = Boolean(options.hasSensitiveTransactionInput);
    const hasGameCommerceContext = Boolean(options.hasGameCommerceContext);
    const officialPageMatch = matches.find(match => match.matchesBrandDomain);
    const commerceMismatch = hasSensitiveCommerceAction && !officialPageMatch
      ? matches.find(match => !match.matchesBrandDomain)
      : null;
    const gameMatches = matches.filter(match => isGameBrandRule(match.rule));
    const officialGameMatch = hasGameCommerceContext
      ? gameMatches.find(match => match.matchesBrandDomain)
      : null;
    const gameMismatch = hasGameCommerceContext && !officialGameMatch
      ? gameMatches.find(match => !match.matchesBrandDomain)
      : null;
    const officialClaimMismatchMatch = presentation?.officialClaim && hasSensitiveTransactionInput && !officialGameMatch
      ? gameMatches.find(match => !match.matchesBrandDomain)
      : null;
    const effectiveGameMismatch = officialClaimMismatchMatch || gameMismatch;

    return {
      commerceBrandMismatch: Boolean(commerceMismatch),
      commerceBrandName: commerceMismatch?.rule?.name || null,
      commerceBrandMentionContext: commerceMismatch
        ? (commerceMismatch.mentionsProminently ? "prominent-identity" : "repeated-branding")
        : null,
      officialClaim: Boolean(presentation?.officialClaim),
      officialClaimHitCount: Array.isArray(presentation?.officialClaimHits)
        ? presentation.officialClaimHits.length
        : 0,
      officialClaimMismatch: Boolean(officialClaimMismatchMatch),
      officialClaimBrandName: officialClaimMismatchMatch?.rule?.name || null,
      gameCommerceBrandMismatch: Boolean(effectiveGameMismatch),
      gameCommerceOfficialBrand: Boolean(officialGameMatch) && !officialClaimMismatchMatch,
      gameCommerceOfficialClaimMismatch: Boolean(officialClaimMismatchMatch) && hasGameCommerceContext,
      gameCommerceBrandName: officialGameMatch?.rule?.name || effectiveGameMismatch?.rule?.name || null,
      gameCommerceBrandMentionContext: officialClaimMismatchMatch
        ? (officialClaimMismatchMatch.mentionsProminently ? "prominent-official-claim" : "repeated-official-claim")
        : officialGameMatch || effectiveGameMismatch
          ? ((officialGameMatch || effectiveGameMismatch).mentionsProminently ? "prominent-identity" : "repeated-branding")
          : null
    };
  }

  async function loadBrandRuleData() {
    if (loadPromise) return loadPromise;
    loadPromise = (async () => {
      const runtime = globalThis.chrome?.runtime;
      if (!runtime?.getURL || typeof fetch !== "function") {
        throw new Error("Extension runtime is unavailable for brand-rule loading");
      }
      const response = await fetch(runtime.getURL(DATA_PATH));
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      cachedData = normalizeBrandRuleData(await response.json());
      return cachedData;
    })().catch(error => {
      loadPromise = null;
      throw error;
    });
    return loadPromise;
  }

  function getBrandRuleData() {
    return cachedData;
  }

  globalThis.DPGBrandRules = Object.freeze({
    DATA_PATH,
    foldText,
    normalizeBrandRuleData,
    sameOrSubdomain,
    analyzeBrandPresentation,
    deriveCommerceBrandSignals,
    loadBrandRuleData,
    getBrandRuleData
  });
})();
