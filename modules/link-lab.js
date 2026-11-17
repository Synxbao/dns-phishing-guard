import { redactUrl } from "./url-privacy.js";

const MAX_URL_LENGTH = 4096;
const MAX_REDIRECTS = 5;
const MAX_RESPONSE_BYTES = 64 * 1024;
const PROBE_TIMEOUT_MS = 8000;

const DOWNLOAD_EXTENSIONS = [
  ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
  ".jar", ".apk", ".dmg", ".pkg", ".iso", ".img", ".zip", ".rar", ".7z"
];

const DOWNLOAD_MIME_MARKERS = [
  "application/octet-stream",
  "application/x-msdownload",
  "application/x-msdos-program",
  "application/vnd.android.package-archive",
  "application/java-archive",
  "application/zip",
  "application/x-rar-compressed",
  "application/x-7z-compressed",
  "application/x-iso9660-image"
];

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

const STATIC_CONTENT_KEYWORDS = {
  gamblingCore: [
    "casino", "sportsbook", "betting", "bookmaker", "live casino", "ca cuoc",
    "dat cuoc", "nha cai", "tai xiu", "xoc dia", "ban ca", "no hu", "jackpot",
    "roulette", "blackjack", "slot game", "poker online"
  ],
  gamblingActions: ["cuoc ngay", "choi ngay", "dang ky ngay", "bet now", "join now", "nhan thuong"],
  gamblingPayments: ["nap tien", "rut tien", "deposit", "withdraw", "cashback", "ty le cuoc", "odds"],
  prepaidValue: [
    "the cao", "ma the", "so seri", "serial the", "ma pin", "gift card",
    "voucher code", "redeem code", "prepaid card", "card pin", "ma nap"
  ],
  gameTopup: ["nap game", "nap robux", "robux", "nap kim cuong", "top up game", "id game", "tai khoan game"],
  gameAccountField: [
    "id game", "idgame", "game id", "gameid", "tai khoan game", "username game",
    "ten nhan vat", "player id", "playerid", "game uid", "gameuid"
  ],
  unofficialCommerce: ["nap lau", "nap chui", "nap ngoai kenh", "khong block acc", "cam ket 100%"],
  promoClaim: ["x2 lan nap", "nhan doi", "gap doi", "bonus 100%", "cam ket 100%", "gia re nhat"],
  commerceAction: ["nap ngay", "nap the", "mua ngay", "thanh toan", "top up", "redeem"],
  gameMarketplace: [
    "acc tu chon", "mua acc", "ban acc", "thu acc", "mua ban acc",
    "mua ban tai khoan", "tai khoan valorant", "acc valorant", "acc game",
    "deadmail", "dropmail", "giao mail goc", "back acc", "cay thue",
    "cay rank", "chuyen vung", "check skin", "kho skin", "skin game"
  ],
  gameTransaction: [
    "nap tien", "thanh toan", "chuyen khoan", "tra gop", "giao dich",
    "mua ban", "nap vi", "banking", "hoan tien", "bao hanh"
  ],
  gameCommerceAction: [
    "nap tien", "mua acc", "ban acc", "thu acc", "mua ngay", "thanh toan",
    "cay thue", "cay rank", "xem kho acc", "xem tai khoan"
  ],
  offPlatformContact: [
    "zalo", "telegram", "discord", "messenger", "facebook admin",
    "zalo.me", "t.me/", "discord.gg", "discord.com/invite", "m.me/"
  ]
};

const STATIC_GAME_BRANDS = [
  { name: "Riot Games", terms: ["riot games", "league of legends", "valorant"], domains: ["riotgames.com", "leagueoflegends.com", "playvalorant.com"] },
  { name: "Roblox", terms: ["roblox", "robux"], domains: ["roblox.com"] },
  { name: "Steam", terms: ["steam", "steam community"], domains: ["steampowered.com", "steamcommunity.com"] }
];

const SENSITIVE_ACTION_PATH = /\/(?:account\/)?(?:activate|activation|confirm|confirmation|magic(?:-|_)?link|passwordless|recover|recovery|reset(?:-|_)?password|unsubscribe|verify|verification|invite|accept(?:-|_)?invite)(?:[\/_-]|$)/i;
const SENSITIVE_ACTION_PARAM = /^(?:action_?code|activation|auth_?token|code|confirm(?:ation)?|invite|key|magic|nonce|one_?time|otp|recover|reset(?:_?token)?|sig|signature|ticket|token|unsubscribe|verify)$/i;

function countMatches(text, regex) {
  return (String(text || "").match(regex) || []).length;
}

function countRedirectResponses(redirects) {
  return (redirects || []).filter(item => REDIRECT_STATUSES.has(Number(item?.status))).length;
}

function foldText(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/đ/g, "d");
}

function decodeHtmlEntities(value) {
  return String(value || "")
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => {
      const point = Number.parseInt(code, 16);
      return Number.isInteger(point) && point >= 0 && point <= 0x10ffff ? String.fromCodePoint(point) : " ";
    })
    .replace(/&#(\d+);/g, (_, code) => {
      const point = Number.parseInt(code, 10);
      return Number.isInteger(point) && point >= 0 && point <= 0x10ffff ? String.fromCodePoint(point) : " ";
    })
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">");
}

function uniqueKeywordHits(text, keywords) {
  return [...new Set(keywords.filter(keyword => text.includes(keyword)))];
}

function sameOrSubdomain(domain, expected) {
  return domain === expected || domain.endsWith(`.${expected}`);
}

function countTextOccurrences(text, keyword) {
  if (!keyword) return 0;
  return Math.max(0, String(text || "").split(keyword).length - 1);
}

function summarizeStaticContent(html, context = {}) {
  const rawHtml = String(html || "");
  const visibleText = foldText(decodeHtmlEntities(rawHtml
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")));
  const inputDescriptors = (rawHtml.match(/<(?:input|textarea|select)\b[^>]*>/gi) || []).map(value => foldText(decodeHtmlEntities(value)));
  const actionDescriptors = [
    ...(rawHtml.match(/<(?:a|button)\b[^>]*>[\s\S]*?<\/(?:a|button)>/gi) || []),
    ...(rawHtml.match(/<input\b[^>]*\btype\s*=\s*["']?(?:submit|button)\b[^>]*>/gi) || [])
  ];
  const actionableText = foldText(decodeHtmlEntities(actionDescriptors.join(" ").replace(/<[^>]+>/g, " ")));
  const gamblingCore = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.gamblingCore);
  const gamblingActions = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.gamblingActions);
  const gamblingPayments = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.gamblingPayments);
  const prepaidValue = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.prepaidValue);
  const gameTopup = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.gameTopup);
  const unofficialCommerce = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.unofficialCommerce);
  const promoClaim = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.promoClaim);
  const commerceAction = uniqueKeywordHits(actionableText, STATIC_CONTENT_KEYWORDS.commerceAction);
  const gameMarketplace = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.gameMarketplace);
  const gameTransaction = uniqueKeywordHits(visibleText, STATIC_CONTENT_KEYWORDS.gameTransaction);
  const gameCommerceAction = uniqueKeywordHits(actionableText, STATIC_CONTENT_KEYWORDS.gameCommerceAction);
  const offPlatformContactCount = actionDescriptors.filter(descriptor => {
    const folded = foldText(decodeHtmlEntities(descriptor.replace(/<[^>]+>/g, " ")));
    const href = foldText(descriptor);
    return STATIC_CONTENT_KEYWORDS.offPlatformContact.some(keyword => folded.includes(keyword) || href.includes(keyword));
  }).length;
  const prepaidInputs = inputDescriptors.filter(descriptor =>
    STATIC_CONTENT_KEYWORDS.prepaidValue.some(keyword => descriptor.includes(keyword))
  ).length;
  const gameAccountInputs = inputDescriptors.filter(descriptor =>
    STATIC_CONTENT_KEYWORDS.gameAccountField.some(keyword => descriptor.includes(keyword))
  ).length;
  const hasSensitiveTransactionInput = prepaidInputs > 0 || gameAccountInputs > 0;
  const findings = [];

  let targetHostname = "";
  try {
    targetHostname = new URL(context.url || `https://${context.hostname || ""}`).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    targetHostname = String(context.hostname || "").toLowerCase().replace(/^www\./, "");
  }
  const prominentText = foldText(decodeHtmlEntities([
    ...(rawHtml.match(/<title\b[^>]*>[\s\S]*?<\/title>/gi) || []),
    ...(rawHtml.match(/<h1\b[^>]*>[\s\S]*?<\/h1>/gi) || [])
  ].join(" ").replace(/<[^>]+>/g, " ")));
  let gameBrandMismatch = false;
  let officialGameBrandContext = false;
  let gameBrandName = null;
  for (const rule of STATIC_GAME_BRANDS) {
    const mentionsProminently = rule.terms.some(term => prominentText.includes(term));
    const mentionCount = rule.terms.reduce((total, term) => total + countTextOccurrences(visibleText, term), 0);
    const matchesOfficialDomain = rule.domains.some(domain => sameOrSubdomain(targetHostname, domain));
    if ((mentionsProminently || mentionCount >= 3) && matchesOfficialDomain) {
      officialGameBrandContext = true;
      gameBrandName = rule.name;
      break;
    }
    if ((mentionsProminently || mentionCount >= 3) && targetHostname && !matchesOfficialDomain) {
      gameBrandMismatch = true;
      gameBrandName = rule.name;
      break;
    }
  }

  if (gamblingCore.length >= 2 && (gamblingActions.length > 0 || gamblingPayments.length > 0)) {
    const score = Math.min(90, 35 + gamblingCore.length * 7 + gamblingActions.length * 8 + gamblingPayments.length * 7);
    findings.push({
      id: "GAMBLING",
      score,
      level: score >= 75 ? "HIGH" : "WARNING",
      reason: "Phần HTML đầu trang có cụm từ cờ bạc/cá cược kèm hành động chơi hoặc nạp/rút tiền."
    });
  }

  const strongScamCommerce = (
    unofficialCommerce.length > 0 &&
    (prepaidValue.length > 0 || gameTopup.length > 0) &&
    (hasSensitiveTransactionInput || (commerceAction.length >= 2 && promoClaim.length > 0))
  ) || (
    prepaidInputs >= 2 && promoClaim.length > 0
  );
  if (strongScamCommerce) {
    const score = Math.min(100,
      45 + unofficialCommerce.length * 15 + prepaidValue.length * 7 +
      gameTopup.length * 6 + promoClaim.length * 5 + prepaidInputs * 12 +
      gameAccountInputs * 8
    );
    findings.push({
      id: "SCAM_COMMERCE",
      score,
      level: score >= 75 ? "HIGH" : "WARNING",
      reason: "HTML có dấu hiệu giao dịch game/mã trả trước ngoài kênh chính thức hoặc khuyến mãi cần xác minh."
    });
  }

  const strongGameCommerce = !officialGameBrandContext &&
    gameMarketplace.length >= 2 &&
    gameTransaction.length >= 1 &&
    gameCommerceAction.length >= 1 &&
    (offPlatformContactCount >= 1 || gameBrandMismatch) &&
    (gameBrandMismatch || offPlatformContactCount >= 2 || gameMarketplace.length >= 4);
  if (strongGameCommerce) {
    const score = Math.min(70, Math.max(45,
      Math.min(30, gameMarketplace.length * 5) +
      Math.min(18, gameTransaction.length * 6) +
      Math.min(12, offPlatformContactCount * 4) +
      Math.min(10, gameCommerceAction.length * 4) +
      (gameBrandMismatch ? 12 : 0)
    ));
    findings.push({
      id: "GAME_COMMERCE",
      score,
      level: "WARNING",
      reason: `HTML có ngữ cảnh mua bán tài khoản/dịch vụ game qua kênh bên thứ ba${gameBrandMismatch ? ` và dùng thương hiệu ${gameBrandName} trên domain không chính thức` : ""}; cần xác minh chủ thể và thanh toán.`
    });
  }

  findings.sort((a, b) => b.score - a.score);
  return {
    findings,
    level: findings[0]?.level || "NONE",
    score: findings[0]?.score || 0,
    reasons: findings.map(item => item.reason),
    prepaidInputCount: prepaidInputs,
    gameAccountInputCount: gameAccountInputs,
    commerceActionCount: commerceAction.length,
    samples: [...new Set([
      ...unofficialCommerce, ...prepaidValue, ...gameTopup, ...promoClaim,
      ...gameMarketplace, ...gameTransaction,
      ...gamblingCore, ...gamblingActions, ...gamblingPayments
    ])].slice(0, 12)
  };
}

function normalizeIpv4(hostname) {
  const parts = String(hostname || "").split(".");
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some(value => value < 0 || value > 255)) return null;
  return octets;
}

function isBlockedLiteralHost(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return true;
  if (
    host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
    host.endsWith(".internal") || host.endsWith(".lan") || host.endsWith(".home")
  ) return true;

  const ipv4 = normalizeIpv4(host);
  if (ipv4) {
    const [a, b, c] = ipv4;
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    );
  }

  if (host.includes(":")) {
    return (
      host === "::" || host === "::1" || host.startsWith("fe8") || host.startsWith("fe9") ||
      host.startsWith("fea") || host.startsWith("feb") || host.startsWith("fc") || host.startsWith("fd") ||
      host.startsWith("::ffff:10.") || host.startsWith("::ffff:127.") ||
      host.startsWith("::ffff:169.254.") || host.startsWith("::ffff:192.168.")
    );
  }

  return false;
}

function normalizeLinkLabUrl(rawValue, baseUrl = null) {
  let value = String(rawValue || "").trim();
  if (!value) throw new Error("Hãy nhập một URL cần kiểm tra.");
  if (value.length > MAX_URL_LENGTH) throw new Error("URL quá dài để kiểm tra an toàn.");
  if (!baseUrl && !/^[a-z][a-z0-9+.-]*:/i.test(value)) value = `https://${value}`;

  let parsed;
  try {
    parsed = baseUrl ? new URL(value, baseUrl) : new URL(value);
  } catch {
    throw new Error("URL không hợp lệ.");
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error("Link Lab chỉ chấp nhận URL HTTP hoặc HTTPS.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URL chứa thông tin đăng nhập nhúng và đã bị từ chối.");
  }
  if (isBlockedLiteralHost(parsed.hostname)) {
    throw new Error("Link Lab không truy cập localhost, mạng nội bộ hoặc địa chỉ dành riêng.");
  }

  parsed.hash = "";
  return parsed;
}

function classifySensitiveActionUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const sensitiveParams = [...url.searchParams.entries()]
      .filter(([key, value]) => SENSITIVE_ACTION_PARAM.test(key) && String(value || "").length >= 6)
      .map(([key]) => key)
      .slice(0, 8);
    const pathMatch = SENSITIVE_ACTION_PATH.test(url.pathname);
    const sensitive = pathMatch || sensitiveParams.length > 0;
    return {
      sensitive,
      category: sensitive ? "ACTION_TOKEN" : "NONE",
      label: sensitive ? "Link có thể thực hiện hành động một lần" : "Không phát hiện action token",
      parameterNames: sensitiveParams,
      reasons: sensitive
        ? [
            "URL có dấu hiệu chứa mã xác nhận, khôi phục, đăng nhập một lần hoặc hủy đăng ký.",
            "Link Lab không gửi yêu cầu mạng để tránh làm tiêu thụ token hoặc kích hoạt hành động phía máy chủ."
          ]
        : []
    };
  } catch {
    return { sensitive: false, category: "NONE", label: "URL không hợp lệ", parameterNames: [], reasons: [] };
  }
}

function createSkippedProbeResult(url, sensitiveAction, redirects = []) {
  return {
    reachable: false,
    probeSkipped: true,
    previewAllowed: false,
    skipReason: "sensitive-action-url",
    sensitiveAction,
    finalUrl: url.href,
    displayFinalUrl: redactUrl(url.href),
    status: null,
    ok: false,
    contentType: "Không truy cập để bảo vệ token",
    contentLength: null,
    contentDisposition: null,
    redirects,
    redirectCount: countRedirectResponses(redirects),
    redirectAnomaly: null,
    bytesInspected: 0,
    truncated: false,
    htmlSignals: summarizeHtml(""),
    downloadRisk: {
      level: "UNKNOWN",
      label: "Không probe vì URL có action token",
      reasons: sensitiveAction.reasons
    },
    error: null
  };
}

function summarizeHtml(source, context = {}) {
  const html = String(source || "");
  const riskyExtensionPattern = DOWNLOAD_EXTENSIONS
    .map(value => value.replace(".", "\\."))
    .join("|");

  const formCount = countMatches(html, /<form\b/gi);
  return {
    scriptCount: countMatches(html, /<script\b/gi),
    formCount,
    passwordInputCount: countMatches(html, /<input\b[^>]*\btype\s*=\s*["']?password\b/gi),
    iframeCount: countMatches(html, /<iframe\b/gi),
    metaRefreshCount: countMatches(html, /<meta\b[^>]*http-equiv\s*=\s*["']?refresh\b/gi),
    downloadAttributeCount: countMatches(html, /<(?:a|area)\b[^>]*\bdownload(?:\s|=|>)/gi),
    riskyDownloadLinkCount: countMatches(
      html,
      new RegExp(`<(?:a|area)\\b[^>]*\\bhref\\s*=\\s*["'][^"']*(?:${riskyExtensionPattern})(?:[?#"']|$)`, "gi")
    ),
    autoNavigationSignalCount: countMatches(
      html,
      /(?:window\.)?(?:location(?:\.href)?\s*=|location\.(?:assign|replace)\s*\(|window\.open\s*\(|\.click\s*\(\s*\))/gi
    ),
    staticContent: summarizeStaticContent(html, context)
  };
}

function classifyDownloadRisk({ url, contentType, contentDisposition, htmlSignals }) {
  const reasons = [];
  const lowerType = String(contentType || "").toLowerCase();
  const lowerDisposition = String(contentDisposition || "").toLowerCase();
  const pathname = (() => {
    try { return new URL(url).pathname.toLowerCase(); } catch { return ""; }
  })();

  if (/\battachment\b/.test(lowerDisposition)) reasons.push("Máy chủ trả về Content-Disposition: attachment.");
  if (DOWNLOAD_MIME_MARKERS.some(marker => lowerType.includes(marker))) reasons.push(`Kiểu nội dung có thể là tệp tải xuống: ${contentType}.`);
  if (DOWNLOAD_EXTENSIONS.some(extension => pathname.endsWith(extension))) reasons.push("Đường dẫn kết thúc bằng phần mở rộng tệp có rủi ro.");
  if (htmlSignals?.downloadAttributeCount > 0) reasons.push(`HTML có ${htmlSignals.downloadAttributeCount} phần tử gắn thuộc tính download.`);
  if (htmlSignals?.riskyDownloadLinkCount > 0) reasons.push(`HTML có ${htmlSignals.riskyDownloadLinkCount} liên kết tới loại tệp cần thận trọng.`);
  if (htmlSignals?.autoNavigationSignalCount > 0) reasons.push("HTML có tín hiệu chuyển trang hoặc kích hoạt phần tử bằng mã lệnh.");

  const directDownload = reasons.some(reason =>
    reason.includes("Content-Disposition") || reason.includes("Kiểu nội dung") || reason.includes("phần mở rộng")
  );
  return {
    level: directDownload ? "HIGH" : reasons.length ? "NOTICE" : "NONE",
    label: directDownload
      ? "Có dấu hiệu tải tệp trực tiếp"
      : reasons.length
        ? "Có chỉ báo tải/chuyển trang cần xem xét"
        : "Chưa thấy dấu hiệu tải tự động trong phần đã kiểm tra",
    reasons
  };
}

function buildPreflightVerdict(risk, network) {
  const ranks = { SAFE: 0, SUSPICIOUS: 1, MEDIUM: 2, HIGH: 3 };
  const labels = {
    SAFE: "Chưa thấy bằng chứng rủi ro rõ ràng",
    SUSPICIOUS: "Có tín hiệu cần kiểm tra thêm",
    MEDIUM: "Cần xác minh kỹ trước khi mở",
    HIGH: "Rủi ro cao — không nên mở trực tiếp"
  };
  let level = ranks[risk?.level] === undefined ? "SAFE" : risk.level;
  let score = Math.max(0, Math.min(100, Number(risk?.score) || 0));
  let confidenceScore = Math.max(0, Math.min(100, Number(risk?.confidenceScore) || 0));
  const reasons = [];

  if (network?.downloadRisk?.level === "HIGH") {
    level = "HIGH";
    score = Math.max(score, 75);
    confidenceScore = Math.max(confidenceScore, 82);
    reasons.push("Phản hồi có dấu hiệu tải tệp trực tiếp hoặc loại tệp cần cô lập.");
  } else if (network?.downloadRisk?.level === "NOTICE" && ranks[level] < ranks.SUSPICIOUS) {
    level = "SUSPICIOUS";
    score = Math.max(score, 20);
    confidenceScore = Math.max(confidenceScore, 55);
    reasons.push("HTML có chỉ báo tải tệp hoặc tự điều hướng cần kiểm tra thêm.");
  }

  const staticContent = network?.htmlSignals?.staticContent;
  if (staticContent?.level === "HIGH") {
    level = "HIGH";
    score = Math.max(score, 78, Number(staticContent.score) || 0);
    confidenceScore = Math.max(confidenceScore, 78);
    reasons.push(...(staticContent.reasons || []));
  } else if (staticContent?.level === "WARNING" && ranks[level] < ranks.MEDIUM) {
    level = "MEDIUM";
    score = Math.max(score, 45, Number(staticContent.score) || 0);
    confidenceScore = Math.max(confidenceScore, 65);
    reasons.push(...(staticContent.reasons || []));
  }

  if (network?.probeSkipped) {
    if (ranks[level] < ranks.SUSPICIOUS) {
      level = "SUSPICIOUS";
      score = Math.max(score, 24);
      confidenceScore = Math.max(confidenceScore, 70);
    }
    reasons.unshift("Không kết nối tới link vì URL có thể chứa token dùng một lần hoặc gây tác động phía máy chủ.");
  } else if (network?.redirectAnomaly) {
    if (ranks[level] < ranks.SUSPICIOUS) level = "SUSPICIOUS";
    score = Math.max(score, network.redirectAnomaly.type === "LOOP" ? 28 : 24);
    confidenceScore = Math.max(confidenceScore, 60);
    reasons.push(
      network.redirectAnomaly.type === "LOOP"
        ? "Máy chủ tạo vòng lặp chuyển hướng; không thể xác minh trang đích thực tế."
        : `Chuỗi chuyển hướng vượt giới hạn ${MAX_REDIRECTS} lần; không thể xác minh trang đích thực tế.`
    );
  } else if (network?.reachable === true && network?.ok === false) {
    if (ranks[level] < ranks.SUSPICIOUS) {
      level = "SUSPICIOUS";
      score = Math.max(score, 15);
      confidenceScore = Math.max(confidenceScore, 30);
    }
    reasons.push(`Máy chủ trả HTTP ${network.status || "không thành công"}; Link Lab chưa xác minh được nội dung thực tế.`);
  } else if (network?.reachable === false && ranks[level] < ranks.SUSPICIOUS) {
    level = "SUSPICIOUS";
    score = Math.max(score, 15);
    confidenceScore = Math.max(confidenceScore, 25);
    reasons.push("Không xác minh được phản hồi mạng; không nên suy diễn URL là an toàn.");
  }

  return {
    level,
    score,
    confidenceScore,
    label: labels[level],
    reasons,
    phishingLevel: risk?.level || "SAFE",
    phishingScore: Number(risk?.score) || 0
  };
}

async function readLimitedText(response, maxBytes = MAX_RESPONSE_BYTES) {
  if (!response.body?.getReader) return { text: "", bytesInspected: 0, truncated: false };
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let text = "";
  let bytesInspected = 0;
  let truncated = false;

  try {
    while (bytesInspected < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = maxBytes - bytesInspected;
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      bytesInspected += chunk.byteLength;
      text += decoder.decode(chunk, { stream: true });
      if (value.byteLength > remaining || bytesInspected >= maxBytes) {
        truncated = true;
        break;
      }
    }
    text += decoder.decode();
  } finally {
    if (truncated) await reader.cancel().catch(() => {});
  }

  return { text, bytesInspected, truncated };
}

function safeProbeError(error) {
  if (error?.name === "AbortError") return "Hết thời gian chờ khi kết nối.";
  if (error instanceof TypeError) return "Không thể kết nối hoặc máy chủ từ chối yêu cầu kiểm tra.";
  return String(error?.message || "Không thể kiểm tra phản hồi mạng.").slice(0, 180);
}

async function probeUrlNetwork(rawUrl, fetchImpl = fetch) {
  const redirects = [];
  let current = normalizeLinkLabUrl(rawUrl);
  const visitedUrls = new Set([current.href]);
  let redirectAnomaly = null;
  const initialSensitiveAction = classifySensitiveActionUrl(current.href);
  if (initialSensitiveAction.sensitive) {
    return createSkippedProbeResult(current, initialSensitiveAction);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);

  try {
    for (let index = 0; index <= MAX_REDIRECTS; index += 1) {
      const response = await fetchImpl(current.href, {
        method: "GET",
        headers: {
          Accept: "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.2",
          Range: `bytes=0-${MAX_RESPONSE_BYTES - 1}`
        },
        redirect: "manual",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        signal: controller.signal
      });

      const status = Number(response.status) || 0;
      const contentType = response.headers.get("content-type") || "";
      const contentDisposition = response.headers.get("content-disposition") || "";
      const contentLength = Number(response.headers.get("content-length")) || null;
      const location = response.headers.get("location");
      const isRedirect = REDIRECT_STATUSES.has(status);

      redirects.push({
        url: current.href,
        displayUrl: redactUrl(current.href),
        status,
        location: location ? redactUrl(new URL(location, current).href) : null
      });

      if (isRedirect) {
        await response.body?.cancel().catch(() => {});
        if (!location) throw new Error("Máy chủ chuyển hướng nhưng không cung cấp địa chỉ đích.");
        if (index >= MAX_REDIRECTS) {
          redirectAnomaly = { type: "LIMIT", atUrl: current.href, hop: countRedirectResponses(redirects) };
          throw new Error(`Vượt quá giới hạn ${MAX_REDIRECTS} lần chuyển hướng.`);
        }
        const nextUrl = normalizeLinkLabUrl(location, current);
        if (visitedUrls.has(nextUrl.href)) {
          redirectAnomaly = { type: "LOOP", atUrl: nextUrl.href, hop: countRedirectResponses(redirects) };
          throw new Error("Phát hiện vòng lặp chuyển hướng.");
        }
        const sensitiveAction = classifySensitiveActionUrl(nextUrl.href);
        if (sensitiveAction.sensitive) {
          return createSkippedProbeResult(nextUrl, sensitiveAction, redirects);
        }
        visitedUrls.add(nextUrl.href);
        current = nextUrl;
        continue;
      }

      const textLike = !contentType || /(?:text\/|html|xml|json|javascript)/i.test(contentType);
      const body = textLike
        ? await readLimitedText(response)
        : { text: "", bytesInspected: 0, truncated: false };
      if (!textLike) await response.body?.cancel().catch(() => {});
      const htmlSignals = summarizeHtml(body.text, { url: current.href });
      const downloadRisk = classifyDownloadRisk({
        url: current.href,
        contentType,
        contentDisposition,
        htmlSignals
      });

      return {
        reachable: true,
        finalUrl: current.href,
        displayFinalUrl: redactUrl(current.href),
        status,
        ok: response.ok,
        contentType: contentType || "Không khai báo",
        contentLength,
        contentDisposition: contentDisposition || null,
        redirects,
        redirectCount: countRedirectResponses(redirects),
        redirectAnomaly: null,
        bytesInspected: body.bytesInspected,
        truncated: body.truncated,
        htmlSignals,
        downloadRisk,
        error: null
      };
    }
  } catch (error) {
    return {
      reachable: false,
      finalUrl: current.href,
      displayFinalUrl: redactUrl(current.href),
      status: null,
      ok: false,
      contentType: "Không xác định",
      contentLength: null,
      contentDisposition: null,
      redirects,
      redirectCount: countRedirectResponses(redirects),
      redirectAnomaly,
      bytesInspected: 0,
      truncated: false,
      htmlSignals: summarizeHtml(""),
      downloadRisk: {
        level: "UNKNOWN",
        label: "Chưa xác định được nguy cơ tải tệp",
        reasons: []
      },
      error: safeProbeError(error)
    };
  } finally {
    clearTimeout(timer);
  }
}

export {
  MAX_REDIRECTS,
  MAX_RESPONSE_BYTES,
  PROBE_TIMEOUT_MS,
  buildPreflightVerdict,
  classifySensitiveActionUrl,
  classifyDownloadRisk,
  isBlockedLiteralHost,
  normalizeLinkLabUrl,
  probeUrlNetwork,
  redactUrl,
  summarizeHtml
};
