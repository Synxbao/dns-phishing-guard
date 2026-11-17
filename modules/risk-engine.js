import { MODEL_CONFIG } from "./model-config.js";
import { normalizeUrlForMl } from "./url-ml-features.js";
import { isTrustedIdentityProviderUrl } from "./auth-flow.js";
import { SITE_CONTEXT_TYPES } from "./site-context.js";

// Multi-layer risk and confidence scoring engine.

const RISKY_TLDS = [
  "xyz", "top", "click", "shop", "loan", "monster", "live", "site",
  "buzz", "work", "gq", "tk", "ml", "cf", "icu", "support", "cam"
];

const SHORTENER_DOMAINS = [
  "bit.ly", "t.co", "tinyurl.com", "cutt.ly", "is.gd", "rebrand.ly",
  "shorturl.at", "tiny.cc", "ow.ly", "buff.ly"
];

const PHISHING_KEYWORDS = [
  "login", "signin", "verify", "verification", "secure", "security",
  "account", "update", "confirm", "password", "wallet", "banking",
  "invoice", "payment", "unlock", "suspended", "support", "gift"
];

const COMMON_SECOND_LEVEL_SUFFIXES = new Set([
  "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
  "co.uk", "org.uk", "ac.uk", "com.au", "com.br", "co.jp"
]);

function clamp(value, min = 0, max = 100) {
  return Math.min(max, Math.max(min, Number(value) || 0));
}

function countMatches(text, regex) {
  return (String(text).match(regex) || []).length;
}

function getTLD(domain) {
  return String(domain).split(".").pop()?.toLowerCase() || "";
}

function isIpHost(hostname) {
  const host = String(hostname).replace(/^\[|\]$/g, "");
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) &&
    host.split(".").every(part => Number(part) >= 0 && Number(part) <= 255);
  const ipv6 = host.includes(":") && /^[0-9a-f:]+$/i.test(host);
  return ipv4 || ipv6;
}

function fallbackSubdomainDepth(domain) {
  const labels = String(domain).split(".").filter(Boolean);
  if (labels.length <= 2) return 0;
  const suffix2 = labels.slice(-2).join(".");
  const registrableLabels = COMMON_SECOND_LEVEL_SUFFIXES.has(suffix2) ? 3 : 2;
  return Math.max(0, labels.length - registrableLabels);
}

function safeDecode(value) {
  try {
    return decodeURIComponent(String(value || ""));
  } catch {
    return String(value || "");
  }
}

function analyzeUrlSignals(url, domain, domainInfo = null, siteContext = null) {
  const rawParsed = new URL(url);
  const normalized = normalizeUrlForMl(url);
  const parsed = normalized?.parsed || rawParsed;
  const normalizedUrl = normalized?.normalizedHref || parsed.href;
  const keywordSurface = `${parsed.hostname}${safeDecode(parsed.pathname)} ${[...parsed.searchParams.keys()].join(" ")}`.toLowerCase();
  const keywordHits = PHISHING_KEYWORDS.filter(keyword => keywordSurface.includes(keyword));
  // Percent-encoding inside OAuth/SSO query values is normal. Only encoded path
  // segments are scored by the heuristic layer; the raw query count remains diagnostic.
  const encodingCount = countMatches(rawParsed.pathname, /%[0-9a-f]{2}/gi);
  const rawQueryEncodingCount = countMatches(rawParsed.search, /%[0-9a-f]{2}/gi);
  const subdomainDepth = Number.isInteger(domainInfo?.subdomainDepth)
    ? domainInfo.subdomainDepth
    : fallbackSubdomainDepth(domain);
  const queryParamCount = [...parsed.searchParams.keys()].length;
  const registrableDomain = domainInfo?.registrableDomain || domain;
  const hasUserInfo = Boolean(rawParsed.username || rawParsed.password);

  return {
    usesHttps: parsed.protocol === "https:",
    isIpAddress: Boolean(domainInfo?.isIpAddress) || isIpHost(parsed.hostname),
    isShortener: SHORTENER_DOMAINS.some(item => registrableDomain === item),
    // @ in a path (for example TikTok /@handle) is ordinary content. Only
    // userinfo in the URL authority can visually hide the destination host.
    containsAtSymbol: hasUserInfo,
    hasCredentials: hasUserInfo,
    domainLength: domain.length,
    hyphenCount: countMatches(domain, /-/g),
    digitCount: countMatches(domain, /\d/g),
    tld: getTLD(domainInfo?.publicSuffix || domain),
    subdomainDepth,
    encodingCount,
    rawQueryEncodingCount,
    urlLength: normalizedUrl.length,
    rawUrlLength: url.length,
    queryParamCount,
    rawQueryParamCount: normalized?.rawQueryParameterCount ?? [...rawParsed.searchParams.keys()].length,
    removedTrackingParameterCount: normalized?.removedTrackingParameterCount || 0,
    normalizedUrl,
    keywordHits,
    registrableDomain,
    publicSuffix: domainInfo?.publicSuffix || "",
    subdomain: domainInfo?.subdomain || "",
    isPublicContext: siteContext?.isPublic !== false
  };
}

function pushSignal(bucket, points, reason, evidence, confidenceWeight = 0) {
  bucket.score += points;
  bucket.reasons.push(reason);
  bucket.evidence.push(evidence);
  bucket.confidence += confidenceWeight;
}

function buildRecommendations(level, pageSignals, redirectInfo, threatInfo) {
  if (level === "HIGH") {
    const recommendations = [
      "Không nhập mật khẩu, OTP, số thẻ hoặc thông tin cá nhân.",
      "Không tải hoặc mở file từ trang này.",
      "Đóng trang và tự gõ địa chỉ chính thức của dịch vụ.",
      "Nếu đã nhập mật khẩu, hãy đổi mật khẩu và bật xác thực đa yếu tố."
    ];
    if (redirectInfo?.crossDomainCount > 0 && !redirectInfo?.isFederatedAuthFlow) {
      recommendations.unshift("Bạn đã bị chuyển qua domain khác; hãy kiểm tra địa chỉ cuối cùng thật kỹ.");
    }
    if (threatInfo?.isUnsafe) {
      recommendations.unshift("Nguồn threat intelligence đã xác nhận URL nguy hiểm; nên quay lại ngay.");
    }
    return recommendations;
  }

  if (level === "SUSPICIOUS") {
    const recommendations = [
      "Website có một số tín hiệu cần kiểm tra thêm; chưa đủ bằng chứng để kết luận phishing.",
      "Không nhập mật khẩu, OTP hoặc thông tin thanh toán khi chưa xác minh domain.",
      "Ưu tiên truy cập dịch vụ từ bookmark hoặc ứng dụng chính thức."
    ];
    if (pageSignals?.passwordInputCount > 0) {
      recommendations.unshift("Trang đang yêu cầu mật khẩu; hãy kiểm tra domain thật trước khi nhập.");
    }
    if (redirectInfo?.hopCount >= 2 && !redirectInfo?.isFederatedAuthFlow) {
      recommendations.unshift("Trang đã chuyển hướng; hãy kiểm tra domain cuối cùng.");
    }
    return recommendations;
  }

  if (level === "MEDIUM") {
    const recommendations = [
      "Kiểm tra kỹ domain thật trước khi tiếp tục.",
      "Không cung cấp OTP hoặc thông tin thanh toán khi chưa xác minh.",
      "Ưu tiên truy cập dịch vụ từ bookmark hoặc ứng dụng chính thức."
    ];
    if (pageSignals?.passwordInputCount > 0) {
      recommendations.unshift("Trang đang yêu cầu mật khẩu; chỉ nhập khi bạn chắc chắn domain là chính xác.");
    }
    if (redirectInfo?.hopCount >= 2 && !redirectInfo?.isFederatedAuthFlow) {
      recommendations.unshift("Trang đã chuyển hướng nhiều lần; hãy kiểm tra domain cuối cùng.");
    }
    return recommendations;
  }

  return [
    "Không phát hiện dấu hiệu rủi ro rõ ràng, nhưng vẫn cần thận trọng với thông tin nhạy cảm.",
    "HTTPS và điểm thấp không phải là bảo đảm an toàn tuyệt đối."
  ];
}

function buildIdentityStatus({
  siteContext,
  isBlacklisted,
  isWhitelisted,
  isKnownDomain,
  officialSuffix,
  ageInfo
}) {
  if (siteContext.type === SITE_CONTEXT_TYPES.LOCAL_DEVELOPMENT) {
    return {
      code: "LOCAL_DEVELOPMENT",
      label: "Môi trường phát triển cục bộ",
      detail: "Không áp dụng RDAP hoặc URL ML dành cho Internet công cộng",
      publicModelApplicable: false
    };
  }
  if (siteContext.type === SITE_CONTEXT_TYPES.PRIVATE_NETWORK) {
    return {
      code: "PRIVATE_NETWORK",
      label: "Mạng riêng / nội bộ",
      detail: "Tiếp tục kiểm tra hành vi trang, nhưng bỏ qua uy tín domain công cộng",
      publicModelApplicable: false
    };
  }
  if (isBlacklisted) {
    return { code: "BLACKLISTED", label: "Có trong blacklist", detail: "Nguồn cục bộ đánh dấu nguy hiểm", publicModelApplicable: true };
  }
  if (isWhitelisted) {
    return { code: "USER_TRUSTED", label: "Được người dùng tin cậy", detail: "Whitelist không vô hiệu hóa kiểm tra hành vi", publicModelApplicable: true };
  }
  if (isKnownDomain) {
    return { code: "KNOWN_DOMAIN", label: "Domain đã biết / phổ biến", detail: "Không đồng nghĩa được bảo đảm an toàn", publicModelApplicable: true };
  }
  if (officialSuffix) {
    return { code: "OFFICIAL_SUFFIX", label: "Tên miền tổ chức công", detail: "Hậu tố giáo dục/chính phủ; vẫn kiểm tra hành vi", publicModelApplicable: true };
  }
  if (Number(ageInfo?.ageDays) >= 730) {
    return { code: "ESTABLISHED_DOMAIN", label: "Domain lâu năm", detail: "Uy tín thời gian là tín hiệu hỗ trợ, không phải chứng nhận", publicModelApplicable: true };
  }
  if (Number(ageInfo?.ageDays) >= 365) {
    return {
      code: "MODERATELY_ESTABLISHED",
      label: "Domain đã hoạt động hơn một năm",
      detail: "Tuổi domain 1-2 năm là tín hiệu nhận diện hỗ trợ; chưa đạt mức uy tín thời gian của domain lâu năm",
      publicModelApplicable: true
    };
  }
  if (Number.isFinite(Number(ageInfo?.ageDays)) && Number(ageInfo.ageDays) < 180) {
    return { code: "NEW_DOMAIN", label: "Domain mới", detail: "Cần thêm bằng chứng trước khi cung cấp dữ liệu nhạy cảm", publicModelApplicable: true };
  }
  return { code: "UNVERIFIED", label: "Chưa xác minh", detail: "Chưa đủ dữ liệu nhận diện domain", publicModelApplicable: true };
}

function calculateRisk({
  url,
  domain,
  domainInfo = null,
  ageInfo,
  typoMatch,
  homoglyphInfo,
  isBlacklisted,
  isWhitelisted,
  isKnownDomain = false,
  pageSignals = null,
  redirectInfo = null,
  threatInfo = null,
  mlInfo = null,
  siteContext = null
}) {
  const domainBucket = { score: 0, reasons: [], evidence: [], confidence: 0 };
  const urlBucket = { score: 0, reasons: [], evidence: [], confidence: 0 };
  const pageBucket = { score: 0, reasons: [], evidence: [], confidence: 0 };
  const networkBucket = { score: 0, reasons: [], evidence: [], confidence: 0 };
  const threatBucket = { score: 0, reasons: [], evidence: [], confidence: 0 };
  const mlBucket = { score: 0, reasons: [], evidence: [], confidence: 0 };
  const effectiveSiteContext = siteContext || {
    type: SITE_CONTEXT_TYPES.PUBLIC_WEB,
    isPublic: true,
    skipPublicReputation: false
  };
  const isPublicContext = effectiveSiteContext.isPublic !== false;
  const urlSignals = analyzeUrlSignals(url, domain, domainInfo, effectiveSiteContext);

  if (!isPublicContext) {
    domainBucket.evidence.push("non-public-site-context");
    domainBucket.confidence += 8;
    domainBucket.reasons.push(
      effectiveSiteContext.type === SITE_CONTEXT_TYPES.LOCAL_DEVELOPMENT
        ? "Đây là môi trường phát triển cục bộ; đã bỏ qua RDAP, URL ML và các quy tắc uy tín dành cho Internet công cộng"
        : "Đây là địa chỉ mạng riêng; đã bỏ qua RDAP, URL ML và các quy tắc uy tín dành cho Internet công cộng"
    );
  }

  if (isBlacklisted) {
    pushSignal(threatBucket, 100, "Domain nằm trong blacklist đã biết là lừa đảo", "blacklist", 65);
  }

  if (threatInfo?.checked) {
    threatBucket.evidence.push("threat-intel-checked");
    threatBucket.confidence += 12;
  }
  if (threatInfo?.isUnsafe) {
    const threats = (threatInfo.threats || []).slice(0, 5).join(", ");
    pushSignal(
      threatBucket,
      100,
      `${threatInfo.source || "Threat Intelligence"} xác nhận URL nguy hiểm${threats ? `: ${threats}` : ""}`,
      "threat-intel-unsafe",
      70
    );
  }


  let mlProbability = 0;
  if (isPublicContext && mlInfo?.available) {
    mlProbability = Math.max(0, Math.min(1, Number(mlInfo.probability) || 0));
    const percent = Math.round(mlProbability * 100);
    mlBucket.evidence.push("url-ml-checked");
    mlBucket.confidence += 6;

    // Lexical ML is an anomaly indicator, not a verdict. It needs another
    // independent layer before it can create a MEDIUM/HIGH browser warning.
    if (mlProbability >= 0.90) {
      pushSignal(
        mlBucket,
        30,
        `Độ bất thường cấu trúc URL ở mức rất cao (${percent}%); đây chỉ là chỉ báo và cần bằng chứng độc lập`,
        "url-ml-high-advisory",
        16
      );
    } else if (mlProbability >= 0.75) {
      pushSignal(
        mlBucket,
        20,
        `Độ bất thường cấu trúc URL ở mức cao (${percent}%); cần đối chiếu thêm các lớp khác`,
        "url-ml-moderate-advisory",
        11
      );
    } else if (mlProbability >= 0.55) {
      pushSignal(
        mlBucket,
        10,
        `Một số đặc trưng cấu trúc URL khác mẫu phổ biến (${percent}%); chỉ ghi nhận để theo dõi`,
        "url-ml-weak-advisory",
        6
      );
    }
  }

  if (isPublicContext && homoglyphInfo?.isPunycode) {
    pushSignal(
      domainBucket,
      homoglyphInfo.decodeFailed ? 50 : 35,
      homoglyphInfo.decodeFailed
        ? "Domain dùng Punycode (xn--) nhưng không giải mã được"
        : `Domain dùng Punycode/IDN, dạng hiển thị: ${homoglyphInfo.displayDomain}`,
      "punycode",
      18
    );
  }

  if (isPublicContext && homoglyphInfo?.hasHomoglyph) {
    pushSignal(domainBucket, 45, "Domain chứa ký tự Unicode giống chữ Latin (homoglyph)", "homoglyph", 28);
  }

  if (isPublicContext && ageInfo && typeof ageInfo.ageDays === "number") {
    if (ageInfo.ageDays < 30) {
      pushSignal(domainBucket, 40, "Domain mới đăng ký dưới 30 ngày", "domain-age", 15);
    } else if (ageInfo.ageDays < 180) {
      pushSignal(domainBucket, 20, "Domain khá mới, dưới 6 tháng tuổi", "domain-age", 10);
    } else {
      domainBucket.evidence.push("rdap-age-known");
      domainBucket.confidence += 4;
    }
  }

  if (isPublicContext && typoMatch) {
    pushSignal(
      domainBucket,
      40,
      typoMatch.exactBrandDifferentSuffix
        ? `Domain dùng đúng tên thương hiệu của ${typoMatch.closest} nhưng đổi hậu tố tên miền`
        : `Domain rất giống domain nổi tiếng ${typoMatch.closest} (khoảng cách ${typoMatch.distance}, tương đồng ${Math.round((typoMatch.similarity || 0) * 100)}%)`,
      typoMatch.exactBrandDifferentSuffix ? "brand-suffix-mismatch" : "typosquatting",
      25
    );
  }

  if (isPublicContext && !urlSignals.usesHttps) pushSignal(urlBucket, 10, "Website công cộng không sử dụng HTTPS", "no-https", 4);
  if (isPublicContext && urlSignals.isIpAddress) pushSignal(urlBucket, 25, "URL công cộng sử dụng địa chỉ IP thay vì tên miền", "ip-address", 12);
  if (isPublicContext && urlSignals.isShortener) pushSignal(urlBucket, 20, "URL sử dụng dịch vụ rút gọn nên khó nhìn thấy đích thật", "shortener", 8);
  if (urlSignals.containsAtSymbol) pushSignal(urlBucket, 25, "URL chứa thông tin người dùng trước ký tự @, có thể che giấu domain đích", "at-symbol", 14);
  if (isPublicContext && urlSignals.domainLength > 30) pushSignal(urlBucket, 10, "Domain dài bất thường", "long-domain", 4);
  if (isPublicContext && urlSignals.hyphenCount >= 2) pushSignal(urlBucket, 10, "Domain có nhiều dấu gạch ngang", "many-hyphens", 4);
  if (isPublicContext && urlSignals.digitCount >= 2) pushSignal(urlBucket, 10, "Domain chứa nhiều chữ số", "many-digits", 4);
  if (isPublicContext && RISKY_TLDS.includes(urlSignals.tld)) pushSignal(urlBucket, 15, `TLD .${urlSignals.tld} thuộc nhóm thường bị lạm dụng`, "risky-tld", 5);
  if (isPublicContext && urlSignals.subdomainDepth >= 3) pushSignal(urlBucket, 15, "URL có quá nhiều tầng subdomain", "deep-subdomain", 7);
  if (isPublicContext && urlSignals.encodingCount >= 4) pushSignal(urlBucket, 10, "Đường dẫn URL chứa nhiều ký tự mã hóa phần trăm", "heavy-path-encoding", 4);
  if (isPublicContext && urlSignals.urlLength > 220) pushSignal(urlBucket, 10, "URL sau chuẩn hóa vẫn dài bất thường", "long-url", 4);
  if (isPublicContext && urlSignals.queryParamCount >= 10) pushSignal(urlBucket, 8, "URL sau khi bỏ tham số theo dõi vẫn chứa nhiều tham số truy vấn", "many-query-params", 3);
  if (isPublicContext && urlSignals.keywordHits.length >= 2) {
    pushSignal(
      urlBucket,
      15,
      `URL chứa nhiều từ khóa thường gặp trong phishing: ${urlSignals.keywordHits.slice(0, 5).join(", ")}`,
      "phishing-keywords",
      7
    );
  }

  if (redirectInfo) {
    if (redirectInfo.httpsDowngrade) {
      pushSignal(networkBucket, 25, "Chuỗi chuyển hướng hạ từ HTTPS xuống HTTP", "https-downgrade", 18);
    }
    if (redirectInfo.crossDomainCount >= 1) {
      if (redirectInfo.isFederatedAuthFlow) {
        networkBucket.evidence.push("official-federated-auth-flow");
        networkBucket.confidence += 2;
      } else {
        pushSignal(
          networkBucket,
          Math.min(20, 8 + redirectInfo.crossDomainCount * 4),
          `Chuỗi chuyển hướng đi qua ${redirectInfo.uniqueDomainCount} domain khác nhau`,
          "cross-domain-redirect",
          8
        );
      }
    }
    if (redirectInfo.hopCount >= 3 && !redirectInfo.isFederatedAuthFlow) {
      pushSignal(networkBucket, 12, `Trang đã chuyển hướng ${redirectInfo.hopCount - 1} lần`, "many-redirects", 6);
    }
    if (redirectInfo.hasServerRedirect || redirectInfo.hasClientRedirect) {
      networkBucket.evidence.push("redirect-observed");
      networkBucket.confidence += 3;
    }
  }

  if (pageSignals) {
    if (pageSignals.externalPasswordFormCount > 0) {
      pushSignal(pageBucket, 70, "Form mật khẩu gửi dữ liệu sang một origin khác", "external-password-form", 35);
    }

    // A password field is normal on official portals. It only corroborates risk when
    // a strong domain/network/URL signal already exists; long URLs, encoded return
    // paths and login/account words alone are not enough.
    const strongPasswordContext = Boolean(
      threatBucket.score >= 100 || domainBucket.score >= 20 ||
      (isPublicContext && (urlSignals.isIpAddress || urlSignals.isShortener)) || urlSignals.containsAtSymbol ||
      (isPublicContext && !urlSignals.usesHttps && RISKY_TLDS.includes(urlSignals.tld)) ||
      redirectInfo?.httpsDowngrade || (!redirectInfo?.isFederatedAuthFlow && Number(redirectInfo?.crossDomainCount || 0) >= 2)
    );
    if (pageSignals.passwordInputCount > 0 && strongPasswordContext) {
      pushSignal(pageBucket, 20, "Trang có tín hiệu nguy hiểm độc lập và đang yêu cầu nhập mật khẩu", "password-on-strong-risk-page", 12);
    }

    // Modern services commonly load many CDN scripts/iframes. Counts alone are
    // diagnostic telemetry, not phishing evidence.
    if (pageSignals.externalIframeCount >= 3) {
      pageBucket.evidence.push("external-iframes-observed");
      pageBucket.confidence += 1;
    }
    if (pageSignals.externalScriptCount >= 12) {
      pageBucket.evidence.push("external-scripts-observed");
      pageBucket.confidence += 1;
    }
    if (pageSignals.hasUrgencyText) pushSignal(pageBucket, 15, "Trang sử dụng nội dung thúc ép hoặc đe dọa", "urgency-language", 8);
    if (pageSignals.brandMismatch) {
      pushSignal(pageBucket, 30, `Trang thể hiện thương hiệu ${pageSignals.brandName} như danh tính chính nhưng domain không tương ứng`, "brand-mismatch", 18);
    }
    if (
      pageSignals.officialClaimMismatch &&
      (Number(pageSignals.prepaidCodeInputCount || 0) > 0 || Number(pageSignals.gameAccountInputCount || 0) > 0)
    ) {
      pushSignal(
        pageBucket,
        70,
        `Trang tự nhận chính thức/đối tác của ${pageSignals.officialClaimBrandName || "một thương hiệu game"}, nhưng domain không khớp và đang yêu cầu ID game hoặc mã trả trước`,
        "official-claim-brand-mismatch",
        38
      );
    }
    if (pageSignals.riskyDownloadLinkCount > 0) {
      pushSignal(pageBucket, 20, "Trang cung cấp liên kết tải loại file có khả năng thực thi", "risky-download-link", 10);
    }
  }

  // Established/known domains frequently have long search, product, game or account URLs.
  // Weak lexical signals such as URL length/query count must not combine with ML to create
  // a warning by themselves. Strong independent evidence still bypasses this guard.
  let mlReduction = 0;
  let weakUrlReduction = 0;
  const isEstablishedDomain = Number(ageInfo?.ageDays) >= 730;
  const officialSuffix = /(^|\.)(edu|gov)$|(^|\.)(edu|ac|gov|go|gob)\.[a-z]{2}$/i.test(String(domainInfo?.publicSuffix || ""));
  const identityProviderContext = isTrustedIdentityProviderUrl(url);
  const officialFederatedAuth = Boolean(redirectInfo?.isFederatedAuthFlow || identityProviderContext);
  const hasTrustedReputation = isPublicContext && (isEstablishedDomain || Boolean(isKnownDomain) || officialSuffix || officialFederatedAuth);
  const hasStrongIndependentSignal = Boolean(
    isBlacklisted || threatInfo?.isUnsafe ||
    (isPublicContext && (homoglyphInfo?.hasHomoglyph || homoglyphInfo?.isPunycode || typoMatch)) ||
    (isPublicContext && ageInfo && Number(ageInfo.ageDays) < 180) ||
    (isPublicContext && (urlSignals.isIpAddress || urlSignals.isShortener)) || urlSignals.containsAtSymbol ||
    redirectInfo?.httpsDowngrade || (!redirectInfo?.isFederatedAuthFlow && Number(redirectInfo?.crossDomainCount || 0) >= 2) ||
    Number(pageSignals?.externalPasswordFormCount || 0) > 0 ||
    Boolean(pageSignals?.brandMismatch) || Boolean(pageSignals?.officialClaimMismatch) ||
    Number(pageSignals?.riskyDownloadLinkCount || 0) > 0
  );

  if (hasTrustedReputation && !hasStrongIndependentSignal && (networkBucket.score === 0 || officialFederatedAuth) && threatBucket.score === 0) {
    // Cap the combined weak URL + ML contribution at 8 points so Bing/Chess/Microsoft-like
    // URLs remain SAFE while still recording that the model was uncertain.
    const weakCombined = urlBucket.score + mlBucket.score;
    const allowedWeakCombined = Math.min(8, weakCombined);
    mlReduction = Math.min(mlBucket.score, Math.max(0, weakCombined - allowedWeakCombined));
    weakUrlReduction = Math.max(0, weakCombined - allowedWeakCombined - mlReduction);
    if (mlReduction > 0 || weakUrlReduction > 0) {
      const rawMlPercent = Math.round(mlProbability * 100);
      mlBucket.reasons = mlBucket.reasons.filter(reason => !reason.startsWith("Độ bất thường") && !reason.startsWith("Một số đặc trưng"));
      mlBucket.reasons.push(
        `Chỉ báo bất thường URL ${rawMlPercent}% không có bằng chứng độc lập đi kèm; domain đã biết/lâu năm nên tín hiệu này được giảm và không dùng để kết luận phishing`
      );
      mlBucket.evidence.push("established-domain-weak-signal-cap");
    }
    if (officialFederatedAuth) {
      mlBucket.reasons.push(
        `Trang đăng nhập chính thức qua ${redirectInfo?.providerName || identityProviderContext?.providerName || "nhà cung cấp danh tính"}; chuyển domain là hành vi OAuth/SSO bình thường`
      );
      mlBucket.evidence.push("official-identity-provider-context");
    }
  }

  const adjustedMlScore = Math.max(0, mlBucket.score - mlReduction);
  const adjustedUrlScore = Math.max(0, urlBucket.score - weakUrlReduction);

  // Whitelist reduces domain/URL/ML reputation signals, but never overrides
  // confirmed threat intelligence, redirect or page behaviour.
  let whitelistReduction = 0;
  if (isWhitelisted && !isBlacklisted && !threatInfo?.isUnsafe) {
    const reducible = domainBucket.score + adjustedUrlScore + adjustedMlScore;
    whitelistReduction = Math.min(60, reducible);
    domainBucket.reasons.push("Domain nằm trong whitelist; giảm tín hiệu uy tín và ML, nhưng vẫn kiểm tra hành vi trang và chuyển hướng");
    domainBucket.evidence.push("user-whitelist");
  }

  const reputationAndMlScore = Math.max(
    0,
    domainBucket.score + adjustedUrlScore + adjustedMlScore - whitelistReduction
  );
  const nonMlScore = Math.max(0, domainBucket.score + adjustedUrlScore - whitelistReduction) +
    pageBucket.score + networkBucket.score;
  const heuristicScore = reputationAndMlScore + pageBucket.score + networkBucket.score;
  const score = clamp(Math.max(threatBucket.score, heuristicScore));

  const evidenceCodes = [
    ...domainBucket.evidence,
    ...urlBucket.evidence,
    ...pageBucket.evidence,
    ...networkBucket.evidence,
    ...threatBucket.evidence
  ];
  const directWarningEvidence = new Set([
    "blacklist", "threat-intel-unsafe", "punycode", "homoglyph", "domain-age",
    "brand-suffix-mismatch", "typosquatting", "ip-address", "shortener", "at-symbol",
    "https-downgrade", "cross-domain-redirect", "external-password-form",
    "password-on-strong-risk-page", "brand-mismatch", "official-claim-brand-mismatch", "risky-download-link"
  ]);
  const lexicalClusterEvidence = new Set([
    "risky-tld", "phishing-keywords", "deep-subdomain", "many-hyphens", "many-digits"
  ]);
  const warningEvidence = [...new Set(evidenceCodes.filter(code => directWarningEvidence.has(code)))];
  const lexicalClusterCount = new Set(evidenceCodes.filter(code => lexicalClusterEvidence.has(code))).size;
  if (lexicalClusterCount >= 2) warningEvidence.push("clustered-url-risk");
  const hasWarningEvidence = warningEvidence.length > 0;

  const mlCorroborated = adjustedMlScore > 0 && hasWarningEvidence;
  // ML lexical output is advisory by itself. It needs an independent layer before
  // it can become a binary phishing decision or a MEDIUM/HIGH warning.
  const binaryPrediction = (
    threatBucket.score >= 100 ||
    pageBucket.score >= 70 ||
    (nonMlScore >= MODEL_CONFIG.thresholds.binaryPhishing && (hasWarningEvidence || nonMlScore >= MODEL_CONFIG.thresholds.high)) ||
    (mlCorroborated && score >= MODEL_CONFIG.thresholds.binaryPhishing)
  ) ? "PHISHING" : "SAFE";

  const thresholds = MODEL_CONFIG.thresholds;
  let level = "SAFE";
  let color = "green";

  const highConfirmed = (
    threatBucket.score >= 100 ||
    pageBucket.score >= 70 ||
    nonMlScore >= thresholds.high ||
    (score >= thresholds.high && nonMlScore >= 20)
  );
  const mediumCorroborated = (
    (nonMlScore >= thresholds.medium && (hasWarningEvidence || nonMlScore >= thresholds.high)) ||
    (score >= thresholds.medium && mlCorroborated)
  );

  if (highConfirmed) {
    level = "HIGH";
    color = "red";
  } else if (mediumCorroborated) {
    level = "MEDIUM";
    color = "yellow";
  } else if (score >= thresholds.suspicious) {
    level = "SUSPICIOUS";
    color = "amber";
  }

  const shouldWarnOnPage = level === "HIGH" || level === "MEDIUM" ||
    (level === "SUSPICIOUS" && hasWarningEvidence);
  const presentationTier = level === "HIGH"
    ? "BLOCKING_WARNING"
    : level === "MEDIUM"
      ? "WARNING_PANEL"
      : level === "SUSPICIOUS" && shouldWarnOnPage
        ? "CAUTION_PANEL"
        : level === "SUSPICIOUS"
          ? "BADGE_ADVISORY"
          : "NONE";

  const independentEvidence = new Set([
    ...domainBucket.evidence,
    ...urlBucket.evidence,
    ...pageBucket.evidence,
    ...networkBucket.evidence,
    ...threatBucket.evidence,
    ...mlBucket.evidence
  ]).size;

  let confidenceScore =
    10 + domainBucket.confidence + urlBucket.confidence + pageBucket.confidence +
    networkBucket.confidence + threatBucket.confidence + mlBucket.confidence + Math.min(20, independentEvidence * 3);

  if (isPublicContext && !ageInfo) confidenceScore -= 5;
  if (score === 0) confidenceScore = Math.min(confidenceScore, 45);
  confidenceScore = clamp(Math.round(confidenceScore));

  let confidenceLevel = "THẤP";
  if (confidenceScore >= 75) confidenceLevel = "RẤT CAO";
  else if (confidenceScore >= 55) confidenceLevel = "CAO";
  else if (confidenceScore >= 35) confidenceLevel = "TRUNG BÌNH";

  const reasons = [
    ...threatBucket.reasons,
    ...domainBucket.reasons,
    ...urlBucket.reasons,
    ...networkBucket.reasons,
    ...mlBucket.reasons,
    ...pageBucket.reasons
  ];
  const identityStatus = buildIdentityStatus({
    siteContext: effectiveSiteContext,
    isBlacklisted,
    isWhitelisted,
    isKnownDomain,
    officialSuffix,
    ageInfo
  });

  return {
    score,
    level,
    color,
    binaryPrediction,
    model: {
      version: MODEL_CONFIG.version,
      method: MODEL_CONFIG.method,
      thresholds: { ...MODEL_CONFIG.thresholds },
      urlModel: mlInfo?.available ? {
        version: mlInfo.modelVersion,
        probability: Math.round((Number(mlInfo.probability) || 0) * 10000) / 10000,
        threshold: mlInfo.threshold,
        prediction: mlInfo.prediction
      } : null
    },
    confidenceScore,
    confidenceLevel,
    identityStatus,
    presentation: {
      tier: presentationTier,
      shouldWarnOnPage,
      warningEvidence
    },
    reasons,
    recommendations: buildRecommendations(level, pageSignals, redirectInfo, threatInfo),
    breakdown: {
      threatIntel: clamp(threatBucket.score),
      domain: clamp(domainBucket.score),
      url: clamp(adjustedUrlScore),
      urlRaw: clamp(urlBucket.score),
      weakUrlReduction,
      network: clamp(networkBucket.score),
      page: clamp(pageBucket.score),
      ml: clamp(adjustedMlScore),
      mlRaw: clamp(mlBucket.score),
      mlReduction,
      whitelistReduction
    },
    urlSignals,
    siteContext: effectiveSiteContext
  };
}

export {
  calculateRisk,
  analyzeUrlSignals,
  RISKY_TLDS,
  SHORTENER_DOMAINS,
  PHISHING_KEYWORDS,
  buildIdentityStatus,
  MODEL_CONFIG
};
