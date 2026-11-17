(() => {
  const STANDARD_AD_SIZES = new Set([
    "120x600", "160x600", "180x150", "200x200", "234x60", "250x250",
    "300x50", "300x100", "300x250", "300x600", "320x50", "320x100",
    "336x280", "468x60", "728x90", "970x90", "970x250"
  ]);

  const AD_MARKER_TOKENS = new Set([
    "ad", "ads", "advert", "advertisement", "advertising", "adslot", "adunit",
    "adsbygoogle", "adv", "advertorial", "sponsor", "sponsored", "sponsorship",
    "qc", "quangcao"
  ]);

  const AD_MARKER_PHRASES = [
    "banner ad", "banner ads", "ad banner", "ad container", "ad wrapper",
    "ad placement", "google ad", "native ad", "paid promotion", "quang cao"
  ];

  const STRONG_AD_REGION_SELECTOR = [
    "ins", "iframe", "[data-ad]", "[data-ad-id]", "[data-ad-slot]", "[data-ad-client]",
    "[data-ad-format]", "[data-ad-region]", "[class*='adsbygoogle' i]",
    "[data-google-query-id]", "[aria-label*='advert' i]", "[aria-label*='sponsor' i]",
    "[aria-label*='quang cao' i]", "[aria-label*='quảng cáo' i]",
    "[id~='ad' i]", "[class~='ad' i]", "[id~='adv' i]", "[class~='adv' i]",
    "[id~='qc' i]", "[class~='qc' i]",
    "[id~='ads' i]", "[class~='ads' i]", "[id*='ad-' i]", "[class*='ad-' i]",
    "[id*='-ad' i]", "[class*='-ad' i]", "[id*='_ad' i]", "[class*='_ad' i]",
    "[id*='advert' i]", "[class*='advert' i]", "[id*='sponsor' i]",
    "[class*='sponsor' i]", "[id*='banner-ad' i]", "[class*='banner-ad' i]",
    "[id*='quang-cao' i]", "[class*='quang-cao' i]", "[id*='quangcao' i]",
    "[class*='quangcao' i]", "[width][height]",
    "[style*='width' i][style*='height' i]"
  ].join(",");

  // These wrappers are common around direct-DOM ads, but are not sufficient by
  // themselves. They still need a standard ad size or a third-party creative.
  const WEAK_AD_REGION_SELECTOR = [
    "aside", "[role='complementary' i]", "[data-zone]", "[data-banner]",
    "[id*='banner' i]", "[class*='banner' i]", "[id*='promo' i]",
    "[class*='promo' i]", "[id*='placement' i]", "[class*='placement' i]",
    "[id*='creative' i]", "[class*='creative' i]", "[id*='widget' i]",
    "[class*='widget' i]", "[id*='slot' i]", "[class*='slot' i]"
  ].join(",");

  const AD_REGION_CANDIDATE_SELECTOR = `${STRONG_AD_REGION_SELECTOR},${WEAK_AD_REGION_SELECTOR}`;

  function foldMarker(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/đ/g, "d")
      .replace(/Đ/g, "D")
      .toLowerCase();
  }

  function markerTokens(value) {
    return foldMarker(String(value || "").replace(/([a-z0-9])([A-Z])/g, "$1 $2"))
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
  }

  function containsAdMarker(value) {
    const folded = foldMarker(value);
    if (!folded) return false;
    const tokens = markerTokens(value);
    const spaced = tokens.join(" ");
    if (AD_MARKER_PHRASES.some(phrase => spaced.includes(phrase))) return true;
    if (AD_MARKER_TOKENS.has(tokens.join(""))) return true;
    return tokens.some(token => AD_MARKER_TOKENS.has(token));
  }

  function containsPromotionalMarker(value) {
    const tokens = markerTokens(value);
    return tokens.some(token => [
      "banner", "promo", "promotion", "placement", "creative", "commercial"
    ].includes(token));
  }

  function parsePixels(value) {
    const match = String(value ?? "").trim().match(/^(\d+(?:\.\d+)?)(?:px)?$/i);
    return match ? Math.round(Number(match[1])) : null;
  }

  function readDimension(element, name) {
    const attributeValue = parsePixels(element?.getAttribute?.(name));
    if (Number.isFinite(attributeValue) && attributeValue > 0) return attributeValue;

    const styleValue = parsePixels(element?.style?.[name]);
    if (Number.isFinite(styleValue) && styleValue > 0) return styleValue;

    const rectangle = element?.getBoundingClientRect?.();
    const rectangleValue = Math.round(Number(rectangle?.[name]));
    return Number.isFinite(rectangleValue) && rectangleValue > 0 ? rectangleValue : null;
  }

  function hasStandardAdSize(width, height) {
    if (!Number.isFinite(width) || !Number.isFinite(height)) return false;
    return STANDARD_AD_SIZES.has(`${Math.round(width)}x${Math.round(height)}`);
  }

  function isThirdPartyResourceUrl(value, currentOrigin) {
    try {
      const parsed = new URL(value, currentOrigin || "https://invalid.local");
      return /^https?:$/.test(parsed.protocol) && Boolean(currentOrigin) && parsed.origin !== currentOrigin;
    } catch {
      return false;
    }
  }

  function resourceElements(element) {
    const nested = Array.from(element?.querySelectorAll?.("iframe[src],script[src],img[src],a[href]") || []).slice(0, 40);
    return [element, ...nested];
  }

  function hasThirdPartyResource(element, currentOrigin) {
    return resourceElements(element).some(candidate => {
      const value = candidate?.getAttribute?.("src") || candidate?.getAttribute?.("href") || "";
      return isThirdPartyResourceUrl(value, currentOrigin);
    });
  }

  function hasEmbeddedCreative(element) {
    const tagName = String(element?.tagName || "").toUpperCase();
    if (["IFRAME", "INS", "IMG", "PICTURE", "VIDEO"].includes(tagName)) return true;
    return Boolean(element?.querySelector?.("iframe,img,picture,video,a[href],script[src]"));
  }

  function describeElement(element, currentOrigin) {
    const markerText = [
      element?.id,
      typeof element?.className === "string" ? element.className : element?.getAttribute?.("class"),
      element?.getAttribute?.("aria-label"),
      element?.getAttribute?.("title"),
      element?.getAttribute?.("data-zone"),
      element?.getAttribute?.("data-banner"),
      element?.getAttribute?.("data-ad-id"),
      element?.getAttribute?.("data-ad-format")
    ].filter(Boolean).join(" ");
    const width = readDimension(element, "width");
    const height = readDimension(element, "height");
    const tagName = String(element?.tagName || "").toUpperCase();
    const explicitAdAttribute = [
      "data-ad", "data-ad-id", "data-ad-slot", "data-ad-client", "data-ad-format",
      "data-ad-region", "data-google-query-id"
    ].some(name => element?.hasAttribute?.(name));

    return {
      tagName,
      markerText,
      explicitAdAttribute,
      promotionalMarker: containsPromotionalMarker(markerText),
      standardAdSize: hasStandardAdSize(width, height),
      embeddedCreative: hasEmbeddedCreative(element),
      thirdPartyResource: hasThirdPartyResource(element, currentOrigin)
    };
  }

  function isLikelyAdDescriptor(descriptor) {
    if (!descriptor) return false;
    if (descriptor.explicitAdAttribute || containsAdMarker(descriptor.markerText)) return true;
    if (descriptor.promotionalMarker && descriptor.embeddedCreative && descriptor.thirdPartyResource) return true;
    if (!descriptor.standardAdSize) return false;
    return ["IFRAME", "INS"].includes(descriptor.tagName) ||
      (descriptor.embeddedCreative && descriptor.thirdPartyResource);
  }

  function isLikelyAdElement(element, currentOrigin) {
    return isLikelyAdDescriptor(describeElement(element, currentOrigin));
  }

  function findLikelyAdRegions(root, currentOrigin, limit = 1800) {
    if (!root) return [];
    const strongCandidates = Array.from(root.querySelectorAll?.(STRONG_AD_REGION_SELECTOR) || [])
      .slice(0, Math.max(1, limit));
    const weakCandidates = Array.from(root.querySelectorAll?.(WEAK_AD_REGION_SELECTOR) || [])
      .slice(0, Math.max(120, Math.ceil(limit / 2)));
    const candidates = [...new Set([...strongCandidates, ...weakCandidates])];
    const regions = [];

    for (const candidate of candidates) {
      if (!isLikelyAdElement(candidate, currentOrigin)) continue;
      if (regions.some(region => region === candidate || region.contains?.(candidate))) continue;

      for (let index = regions.length - 1; index >= 0; index -= 1) {
        if (candidate.contains?.(regions[index])) regions.splice(index, 1);
      }
      regions.push(candidate);
    }
    return regions;
  }

  function isInsideAdRegion(element, adRegions) {
    if (!element) return false;
    return (adRegions || []).some(region => region === element || region?.contains?.(element));
  }

  function filterElementsOutsideAdRegions(elements, adRegions) {
    return Array.from(elements || []).filter(element => !isInsideAdRegion(element, adRegions));
  }

  function escapePattern(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function removeRegionText(source, regionText) {
    const exactIndex = source.indexOf(regionText);
    if (exactIndex >= 0) {
      return `${source.slice(0, exactIndex)} ${source.slice(exactIndex + regionText.length)}`;
    }

    const tokens = regionText.trim().split(/\s+/).filter(Boolean);
    if (tokens.length < 2 || tokens.length > 500) return source;
    const patternText = tokens.map(escapePattern).join("\\s+");
    if (patternText.length > 12000) return source;
    return source.replace(new RegExp(patternText, "i"), " ");
  }

  function collectTextOutsideAdRegions(body, adRegions, maxLength = 120000) {
    const allRegions = Array.from(adRegions || []);
    const regions = allRegions
      .map(region => ({ region, text: String(region?.innerText || "").trim() }))
      .filter(item => item.text.length >= 2)
      .sort((left, right) => right.text.length - left.text.length);
    let text = String(body?.innerText || "");
    let excludedTextLength = 0;

    for (const item of regions) {
      const filtered = removeRegionText(text, item.text);
      if (filtered !== text) excludedTextLength += item.text.length;
      text = filtered;
    }

    return {
      text: text.slice(0, Math.max(0, maxLength)),
      excludedRegionCount: allRegions.length,
      excludedTextLength
    };
  }

  globalThis.DPGPageSignalFilter = Object.freeze({
    AD_REGION_CANDIDATE_SELECTOR,
    STRONG_AD_REGION_SELECTOR,
    WEAK_AD_REGION_SELECTOR,
    containsAdMarker,
    containsPromotionalMarker,
    hasStandardAdSize,
    isLikelyAdDescriptor,
    isLikelyAdElement,
    findLikelyAdRegions,
    isInsideAdRegion,
    filterElementsOutsideAdRegions,
    collectTextOutsideAdRegions
  });
})();
