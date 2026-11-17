(() => {
  const UI_HOST_ID = "dns-phishing-guard-host";
  const RISKY_EXTENSIONS = [
    ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".lnk", ".iso", ".apk", ".jar"
  ];

  const STRICT_CONTENT_CATEGORY_IDS = new Set([
    "SEXUAL_SERVICES", "ADULT", "GAMBLING", "MALWARE", "IDENTITY_ABUSE",
    "PERSONAL_DATA", "SCAM_COMMERCE", "GAME_COMMERCE"
  ]);

  const PAGE_SIGNAL_FILTER = globalThis.DPGPageSignalFilter || Object.freeze({
    findLikelyAdRegions: () => [],
    filterElementsOutsideAdRegions: elements => Array.from(elements || []),
    collectTextOutsideAdRegions: (body, _regions, maxLength = 120000) => ({
      text: String(body?.innerText || "").slice(0, maxLength),
      excludedRegionCount: 0,
      excludedTextLength: 0
    })
  });

  const PAYMENT_SIGNALS = globalThis.DPGPaymentSignals || Object.freeze({
    detectPaymentIntegration: () => ({
      detected: false,
      confidence: "NONE",
      score: 0,
      providers: [],
      context: {},
      disclaimer: "Chưa quét được tín hiệu tích hợp thanh toán."
    })
  });

  const BRAND_RULE_SERVICE = globalThis.DPGBrandRules || Object.freeze({
    getBrandRuleData: () => ({ officialClaimTerms: [], rules: [] }),
    loadBrandRuleData: async () => ({ officialClaimTerms: [], rules: [] }),
    analyzeBrandPresentation: () => ({ officialClaim: false, officialClaimHits: [], matches: [] }),
    deriveCommerceBrandSignals: () => ({
      commerceBrandMismatch: false,
      commerceBrandName: null,
      commerceBrandMentionContext: null,
      officialClaim: false,
      officialClaimHitCount: 0,
      officialClaimMismatch: false,
      officialClaimBrandName: null,
      gameCommerceBrandMismatch: false,
      gameCommerceOfficialBrand: false,
      gameCommerceOfficialClaimMismatch: false,
      gameCommerceBrandName: null,
      gameCommerceBrandMentionContext: null
    })
  });

  let brandRuleData = BRAND_RULE_SERVICE.getBrandRuleData();
  const brandRulesReady = BRAND_RULE_SERVICE.loadBrandRuleData()
    .then(data => {
      brandRuleData = data;
      return data;
    })
    .catch(error => {
      console.warn("Không tải được brand-rules.json; lớp phát hiện giả mạo thương hiệu tạm thời không khả dụng.", error);
      return brandRuleData;
    });

  const URGENCY_KEYWORDS = [
    "xác minh ngay", "tài khoản sẽ bị khóa", "tài khoản bị khóa",
    "cập nhật ngay", "hành động khẩn cấp", "nhập mã otp",
    "verify now", "account suspended", "urgent action required",
    "confirm your password", "your account will be locked"
  ];

  const CONTENT_KEYWORDS = {
    gamblingCore: [
      "casino", "sportsbook", "betting", "bookmaker", "live casino",
      "ca cuoc", "dat cuoc", "nha cai", "tai xiu", "xoc dia",
      "ban ca", "da ga", "no hu", "lo de", "keo bong", "jackpot",
      "roulette", "blackjack", "slot game", "poker online"
    ],
    gamblingActions: [
      "cuoc ngay", "choi ngay", "dang ky ngay", "join now", "bet now",
      "nhan thuong", "bonus dang ky", "khuyen mai nap", "mo tai khoan"
    ],
    gamblingPayments: [
      "nap tien", "rut tien", "deposit", "withdraw", "hoan tra",
      "hoan cuoc", "ty le cuoc", "odds", "cashback"
    ],
    adult: [
      "noi dung 18+", "adult video", "porn", "xxx", "sex video",
      "phim sex", "khieu dam", "hentai", "nude", "onlyfans leak"
    ],
    sexualServiceDirect: [
      "gai goi", "call girl", "escort service", "adult escort",
      "dich vu tinh duc", "phuc vu tinh duc", "ban dam", "mai dam",
      "di khach", "hang di khach", "massage kich duc", "sex service",
      "gai bao", "gai dich vu", "booking gai"
    ],
    sexualServiceContext: [
      "tim ban tinh", "hen ho 18+", "tinh mot dem", "qua dem",
      "sugar baby", "sugar daddy", "tim ban gai", "tim nguoi yeu",
      "ket ban nguoi lon", "rau xanh", "mbbg", "may bay ba gia",
      "em hang", "gai xinh", "hot girl", "ban tinh", "hen gap rieng"
    ],
    sexualServiceTransaction: [
      "booking", "dat lich", "theo gio", "bang gia", "gia phong",
      "phuc vu tan noi", "di tour", "tiep khach", "call ngay",
      "lien he zalo", "lien he telegram", "nhan khach", "bo may",
      "phi dich vu", "gia dich vu"
    ],
    personalDataSale: [
      "mua ban du lieu", "ban data khach hang", "data khach hang",
      "danh sach so dien thoai", "database khach hang", "cccd full",
      "thong tin ca nhan gia re", "mua data", "ban data"
    ],
    identityAbuse: [
      "mua tai khoan ngan hang", "ban tai khoan ngan hang", "thue tai khoan ngan hang",
      "tai khoan rac", "sim rac", "thue otp", "mua otp", "ban otp",
      "cccd gia", "cmnd gia", "ho chieu gia", "clone tai khoan",
      "mua nick ngan hang", "cho thue tai khoan"
    ],
    malware: [
      "software crack", "phan mem crack", "keygen", "activator", "hack tool",
      "cheat game", "apk mod", "rat tool", "remote access trojan",
      "bypass antivirus", "stealer", "credential stealer"
    ],
    deepfake: [
      "deepfake service", "tao deepfake", "lam deepfake", "face swap service",
      "gia giong", "nhai giong ai", "ghep mat", "voice clone service",
      "fake video service"
    ],
    financialScheme: [
      "cam ket loi nhuan", "loi nhuan chac chan", "lai suat theo ngay",
      "hoa hong tuyen duoi", "kinh doanh da cap", "dau tu uy thac",
      "san tien ao", "san tai san so", "nhan doi tai khoan",
      "loi nhuan khong rui ro"
    ],
    prepaidValue: [
      "the cao", "ma the", "so seri", "serial the", "ma pin", "pin the",
      "gift card", "voucher code", "redeem code", "prepaid card", "card pin",
      "ma nap", "ma so nap tien"
    ],
    gameTopup: [
      "nap game", "nap robux", "robux", "nap kim cuong", "kim cuong",
      "top up game", "game currency", "id game", "tai khoan game",
      "nap quan huy", "nap vcoin", "nap uc"
    ],
    unofficialCommerce: [
      "nap lau", "hang lau", "nap chui", "nap ngoai kenh", "khong block acc",
      "khong khoa acc", "gia re bat thuong", "cam ket 100%", "bao hanh tai khoan"
    ],
    promoClaim: [
      "x2 lan nap", "nhan doi", "gap doi", "bonus 100%", "cam ket 100%",
      "nhan ngay sau 10 giay", "gia re nhat", "uy tin nhat"
    ],
    commerceAction: [
      "nap ngay", "nap the", "mua ngay", "thanh toan", "top up", "redeem",
      "doi robux", "rut tien", "deposit", "withdraw"
    ],
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
    privacyPolicy: [
      "privacy policy", "chinh sach quyen rieng tu", "chinh sach bao mat",
      "bao ve du lieu ca nhan", "data protection"
    ],
    identityDocument: [
      "cccd", "cmnd", "can cuoc", "id card", "national id",
      "passport", "ho chieu", "giay to tuy than"
    ],
    financialField: [
      "so the", "card number", "credit card", "debit card", "cvv", "cvc",
      "so tai khoan", "bank account", "iban", "routing number"
    ],
    otpField: ["otp", "one time password", "ma xac thuc", "ma bao mat"],
    sensitiveField: [
      "email", "phone", "so dien thoai", "dia chi", "address", "ngay sinh",
      "date of birth", "cccd", "cmnd", "can cuoc", "passport", "ho chieu",
      "card number", "so the", "so tai khoan", "bank account", "otp",
      "the cao", "ma the", "so seri", "serial the", "ma pin", "gift card",
      "voucher code", "redeem code", "ma nap", "id game", "tai khoan game"
    ]
  };


  let scanTimer = null;
  let lastSignalSignature = "";
  let lastUrl = location.href;
  let currentResult = null;
  let securityLock = null;
  let nonBlockingUiCleanup = null;
  let idleScanHandle = null;

  const LOCKED_BACKGROUND_EVENTS = ["keydown", "beforeinput", "input", "submit"];

  function normalizeDomain(hostname) {
    return String(hostname || "").toLowerCase().replace(/^www\./, "");
  }

  function sameOrSubdomain(domain, expected) {
    return domain === expected || domain.endsWith(`.${expected}`);
  }

  function safeUrl(value) {
    try {
      return new URL(value, location.href);
    } catch {
      return null;
    }
  }

  function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = String(value ?? "");
    return div.innerHTML;
  }

  function foldText(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/đ/g, "d");
  }

  function uniqueKeywordHits(text, keywords) {
    return [...new Set(keywords.filter(keyword => text.includes(keyword)))];
  }

  function queryLimited(selector, limit = 600) {
    const nodes = document.querySelectorAll(selector);
    return Array.from(nodes).slice(0, limit);
  }

  function inputDescriptor(input) {
    const label = input.labels?.[0]?.innerText || input.closest("label")?.innerText || "";
    const nearby = input.parentElement?.innerText?.slice(0, 300) || "";
    return foldText([
      input.type, input.name, input.id, input.placeholder,
      input.autocomplete, input.getAttribute("aria-label"), label, nearby
    ].filter(Boolean).join(" "));
  }

  function getProminentIdentityText(adRegions = []) {
    const values = [document.title];
    const identityElements = PAGE_SIGNAL_FILTER.filterElementsOutsideAdRegions(queryLimited(
      'meta[name="description"],meta[property="og:title"],meta[property="og:site_name"],h1,h2,h3,[role="heading"],img[alt],input[type="image"][alt]',
      640
    ), adRegions).slice(0, 320);
    for (const element of identityElements) {
      values.push(
        element.getAttribute?.("content") || element.getAttribute?.("alt") ||
        element.innerText || element.textContent || ""
      );
    }
    return foldText(values.join(" ").slice(0, 30000));
  }

  function isFederatedLoginControl(rule, adRegions = []) {
    const authWords = [
      "login with", "sign in with", "continue with", "authenticate with",
      "dang nhap bang", "dang nhap voi", "tiep tuc voi", "microsoft email"
    ];
    const foldedTerms = rule.terms.map(foldText);
    const controls = PAGE_SIGNAL_FILTER.filterElementsOutsideAdRegions(queryLimited(
      'a[href],button,input[type="submit"],input[type="button"],[role="button"],form[action]',
      1400
    ), adRegions).slice(0, 700);

    return [...controls].some(element => {
      const text = foldText([
        element.innerText, element.textContent, element.value,
        element.getAttribute?.("aria-label"), element.getAttribute?.("title")
      ].filter(Boolean).join(" "));
      const mentionsBrand = foldedTerms.some(term => text.includes(term));
      if (!mentionsBrand) return false;

      const target = safeUrl(element.getAttribute?.("href") || element.getAttribute?.("action") || "");
      const targetsOfficialProvider = Boolean(target && rule.domains.some(domain => sameOrSubdomain(normalizeDomain(target.hostname), domain)));
      const looksLikeProviderButton = authWords.some(word => text.includes(word));
      return targetsOfficialProvider || looksLikeProviderButton;
    });
  }


  function collectPageSignals() {
    const scanStartedAt = performance.now();
    const currentOrigin = location.origin;
    const currentDomain = normalizeDomain(location.hostname);
    const adRegions = PAGE_SIGNAL_FILTER.findLikelyAdRegions(document.body, currentOrigin);
    const paymentIntegration = PAYMENT_SIGNALS.detectPaymentIntegration(document.body, {
      currentOrigin,
      adRegions
    });
    const contentQueryLimited = (selector, limit = 600) =>
      PAGE_SIGNAL_FILTER.filterElementsOutsideAdRegions(
        queryLimited(selector, Math.min(2400, Math.max(limit, limit * 2))),
        adRegions
      ).slice(0, limit);
    const passwordInputs = queryLimited('input[type="password"]', 120);
    const allInputs = contentQueryLimited("input, textarea, select", 500);

    const externalPasswordForms = passwordInputs.filter(input => {
      const form = input.closest("form");
      if (!form) return false;
      const action = safeUrl(form.getAttribute("action") || location.href);
      return Boolean(action && action.origin !== currentOrigin);
    });

    const externalIframes = queryLimited("iframe[src]", 240).filter(frame => {
      const src = safeUrl(frame.getAttribute("src"));
      return Boolean(src && src.origin !== currentOrigin);
    });

    const externalScripts = queryLimited("script[src]", 900).filter(script => {
      const src = safeUrl(script.getAttribute("src"));
      return Boolean(src && src.origin !== currentOrigin);
    });

    const riskyDownloadLinks = queryLimited("a[href]", 1800).filter(link => {
      const href = safeUrl(link.getAttribute("href"));
      if (!href) return false;
      const pathname = href.pathname.toLowerCase();
      return RISKY_EXTENSIONS.some(extension => pathname.endsWith(extension));
    });

    const titleText = document.title.toLowerCase();
    const descriptionText = [...document.querySelectorAll('meta[name="description"],meta[property="og:description"]')]
      .map(item => item.getAttribute("content") || "")
      .join(" ");
    const filteredBody = PAGE_SIGNAL_FILTER.collectTextOutsideAdRegions(document.body, adRegions, 120000);
    const bodyText = filteredBody.text.toLowerCase();
    const combinedText = `${titleText}\n${descriptionText}\n${bodyText}`;
    const foldedText = foldText(combinedText);
    const foldedTitle = foldText(`${titleText} ${descriptionText}`);
    const hasUrgencyText = URGENCY_KEYWORDS.some(keyword => combinedText.includes(keyword));
    const descriptors = allInputs.map(inputDescriptor);
    const prepaidCodeInputCount = descriptors.filter(descriptor =>
      CONTENT_KEYWORDS.prepaidValue.some(keyword => descriptor.includes(keyword))
    ).length;
    const gameAccountInputCount = descriptors.filter(descriptor =>
      [
        "id game", "idgame", "game id", "gameid", "tai khoan game", "username game",
        "ten nhan vat", "player id", "playerid", "game uid", "gameuid"
      ]
        .some(keyword => descriptor.includes(keyword))
    ).length;
    const commerceControls = contentQueryLimited(
      'button,input[type="submit"],input[type="button"],a[href],[role="button"]',
      900
    ).filter(element => {
      const text = foldText([
        element.innerText, element.textContent, element.value,
        element.getAttribute?.("aria-label"), element.getAttribute?.("title")
      ].filter(Boolean).join(" "));
      return CONTENT_KEYWORDS.commerceAction.some(keyword => text.includes(keyword));
    });
    const gameMarketplaceHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.gameMarketplace);
    const gameTransactionHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.gameTransaction);
    const gameCommerceControls = contentQueryLimited(
      'button,input[type="submit"],input[type="button"],a[href],[role="button"]',
      900
    ).filter(element => {
      const text = foldText([
        element.innerText, element.textContent, element.value,
        element.getAttribute?.("aria-label"), element.getAttribute?.("title")
      ].filter(Boolean).join(" "));
      return CONTENT_KEYWORDS.gameCommerceAction.some(keyword => text.includes(keyword));
    });
    const gameContactElements = contentQueryLimited('a[href],button,[role="button"]', 1400).filter(element => {
      const href = foldText(element.getAttribute?.("href") || "");
      const text = foldText(element.innerText || element.getAttribute?.("aria-label") || "");
      return href.includes("zalo.me") || href.includes("t.me/") || href.includes("telegram") ||
        href.includes("discord.gg") || href.includes("discord.com/invite") || href.includes("wa.me") ||
        href.includes("facebook.com") || href.includes("m.me/") ||
        ["zalo", "telegram", "discord", "messenger", "facebook admin"]
          .some(keyword => text.includes(keyword));
    });

    const prominentIdentityText = getProminentIdentityText(adRegions);
    const brandPresentation = BRAND_RULE_SERVICE.analyzeBrandPresentation({
      data: brandRuleData,
      currentDomain,
      text: foldedText,
      prominentText: prominentIdentityText
    });

    let brandMismatch = false;
    let brandName = null;
    let brandMentionContext = null;
    if (passwordInputs.length > 0) {
      for (const match of brandPresentation.matches) {
        const rule = match.rule;
        const federatedLoginControl = isFederatedLoginControl(rule, adRegions);

        // "Login with Google/Microsoft" on an organization's own portal is a
        // normal federated-login option, not evidence that the page impersonates
        // Google/Microsoft. A mismatch now requires prominent brand identity (title,
        // heading, logo alt text) or repeated non-trivial branding.
        if (!match.matchesBrandDomain && !federatedLoginControl) {
          brandMismatch = true;
          brandName = rule.name;
          brandMentionContext = match.mentionsProminently ? "prominent-identity" : "repeated-branding";
          break;
        }
      }
    }

    const hasSensitiveCommerceAction = prepaidCodeInputCount > 0 || gameAccountInputCount > 0 || commerceControls.length > 0;
    const hasSensitiveTransactionInput = prepaidCodeInputCount > 0 || gameAccountInputCount > 0;
    const hasGameTopupContext = CONTENT_KEYWORDS.gameTopup.some(keyword => foldedText.includes(keyword));
    const hasGameCommerceContext = (
      gameMarketplaceHits.length >= 2 &&
      (gameTransactionHits.length > 0 || gameCommerceControls.length > 0)
    ) || (hasGameTopupContext && hasSensitiveCommerceAction);
    const commerceBrandSignals = BRAND_RULE_SERVICE.deriveCommerceBrandSignals(brandPresentation, {
      hasSensitiveCommerceAction,
      hasSensitiveTransactionInput,
      hasGameCommerceContext
    });
    const {
      commerceBrandMismatch,
      commerceBrandName,
      commerceBrandMentionContext,
      officialClaim,
      officialClaimHitCount,
      officialClaimMismatch,
      officialClaimBrandName,
      gameCommerceBrandMismatch,
      gameCommerceOfficialBrand,
      gameCommerceOfficialClaimMismatch,
      gameCommerceBrandName,
      gameCommerceBrandMentionContext
    } = commerceBrandSignals;

    const gamblingCoreHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.gamblingCore);
    const gamblingActionHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.gamblingActions);
    const gamblingPaymentHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.gamblingPayments);
    const adultHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.adult);
    const sexualDirectHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.sexualServiceDirect);
    const sexualContextHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.sexualServiceContext);
    const sexualTransactionHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.sexualServiceTransaction);
    const personalDataSaleHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.personalDataSale);
    const identityAbuseHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.identityAbuse);
    const malwareHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.malware);
    const deepfakeHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.deepfake);
    const financialSchemeHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.financialScheme);
    const prepaidValueHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.prepaidValue);
    const gameTopupHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.gameTopup);
    const unofficialCommerceHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.unofficialCommerce);
    const promoClaimHits = uniqueKeywordHits(foldedText, CONTENT_KEYWORDS.promoClaim);

    const contactElements = contentQueryLimited('a[href], button, [role="button"]', 1400).filter(element => {
      const href = foldText(element.getAttribute?.("href") || "");
      const text = foldText(element.innerText || element.getAttribute?.("aria-label") || "");
      return href.startsWith("tel:") || href.includes("zalo.me") || href.includes("t.me/") ||
        href.includes("telegram") || href.includes("wa.me") ||
        ["zalo", "telegram", "goi ngay", "call now", "lien he", "booking", "dat lich"]
          .some(keyword => text.includes(keyword));
    });

    const profileCandidates = contentQueryLimited('article, [class*="profile"], [class*="member"], [class*="girl"], [class*="card"], [class*="item"]', 600)
      .filter(element => {
        const text = foldText((element.innerText || "").trim());
        const hasImage = Boolean(element.querySelector?.("img, video"));
        return hasImage && text.length >= 2 && text.length <= 240;
      });

    const sexualServiceTitleHit = CONTENT_KEYWORDS.sexualServiceDirect.some(keyword => foldedTitle.includes(keyword)) ||
      CONTENT_KEYWORDS.sexualServiceContext.some(keyword => foldedTitle.includes(keyword));

    const hasPrivacyPolicyLink = contentQueryLimited("a[href]", 1800).some(link => {
      const text = foldText(`${link.innerText || ""} ${link.getAttribute("href") || ""}`);
      return CONTENT_KEYWORDS.privacyPolicy.some(keyword => text.includes(keyword));
    });

    const identityDocumentRequestCount = allInputs.filter(input => {
      const descriptor = inputDescriptor(input);
      return CONTENT_KEYWORDS.identityDocument.some(keyword => descriptor.includes(keyword));
    }).length;

    const financialInputCount = descriptors.filter(descriptor =>
      CONTENT_KEYWORDS.financialField.some(keyword => descriptor.includes(keyword))
    ).length;
    const otpInputCount = descriptors.filter(descriptor =>
      CONTENT_KEYWORDS.otpField.some(keyword => descriptor.includes(keyword))
    ).length;
    const sensitiveInputCount = descriptors.filter(descriptor =>
      CONTENT_KEYWORDS.sensitiveField.some(keyword => descriptor.includes(keyword))
    ).length;

    return {
      passwordInputCount: passwordInputs.length,
      externalPasswordFormCount: externalPasswordForms.length,
      externalIframeCount: externalIframes.length,
      externalScriptCount: externalScripts.length,
      riskyDownloadLinkCount: riskyDownloadLinks.length,
      formCount: document.forms.length,
      hasUrgencyText,
      brandMismatch,
      brandName,
      brandMentionContext,
      commerceBrandMismatch,
      commerceBrandName,
      commerceBrandMentionContext,
      officialClaim,
      officialClaimHitCount,
      officialClaimMismatch,
      officialClaimBrandName,
      gameCommerceBrandMismatch,
      gameCommerceOfficialBrand,
      gameCommerceOfficialClaimMismatch,
      gameCommerceBrandName,
      gameCommerceBrandMentionContext,
      brandRulesAvailable: brandRuleData.rules.length > 0,
      brandRuleSnapshotDate: brandRuleData.snapshotDate || null,
      gamblingCoreHitCount: gamblingCoreHits.length,
      gamblingActionHitCount: gamblingActionHits.length,
      gamblingPaymentHitCount: gamblingPaymentHits.length,
      gamblingTitleHit: CONTENT_KEYWORDS.gamblingCore.some(keyword => foldedTitle.includes(keyword)),
      adultContentHitCount: adultHits.length,
      adultTitleHit: CONTENT_KEYWORDS.adult.some(keyword => foldedTitle.includes(keyword)),
      sexualServiceDirectHitCount: sexualDirectHits.length,
      sexualServiceContextHitCount: sexualContextHits.length,
      sexualServiceTransactionHitCount: sexualTransactionHits.length,
      sexualServiceContactCount: Math.min(20, contactElements.length),
      sexualServiceProfileCount: Math.min(30, profileCandidates.length),
      sexualServiceTitleHit,
      personalDataSaleHitCount: personalDataSaleHits.length,
      identityAbuseHitCount: identityAbuseHits.length,
      malwareKeywordHitCount: malwareHits.length,
      deepfakeServiceHitCount: deepfakeHits.length,
      financialSchemeHitCount: financialSchemeHits.length,
      prepaidValueHitCount: prepaidValueHits.length,
      gameTopupHitCount: gameTopupHits.length,
      unofficialCommerceHitCount: unofficialCommerceHits.length,
      promoClaimHitCount: promoClaimHits.length,
      commerceActionCount: Math.min(20, commerceControls.length),
      gameMarketplaceHitCount: gameMarketplaceHits.length,
      gameTransactionHitCount: gameTransactionHits.length,
      gameOffPlatformContactCount: Math.min(20, gameContactElements.length),
      gameCommerceActionCount: Math.min(20, gameCommerceControls.length),
      prepaidCodeInputCount,
      gameAccountInputCount,
      identityDocumentRequestCount,
      financialInputCount,
      otpInputCount,
      sensitiveInputCount,
      hasPrivacyPolicyLink,
      paymentIntegration,
      excludedAdRegionCount: filteredBody.excludedRegionCount,
      excludedAdTextLength: filteredBody.excludedTextLength,
      contentSamples: {
        gambling: [...gamblingCoreHits, ...gamblingActionHits, ...gamblingPaymentHits].slice(0, 8),
        adult: adultHits.slice(0, 8),
        sexualServices: [...sexualDirectHits, ...sexualContextHits, ...sexualTransactionHits].slice(0, 12),
        personalData: personalDataSaleHits.slice(0, 8),
        identityAbuse: identityAbuseHits.slice(0, 8),
        malware: malwareHits.slice(0, 8),
        deepfake: deepfakeHits.slice(0, 8),
        financialScheme: financialSchemeHits.slice(0, 8),
        scamCommerce: [
          ...unofficialCommerceHits,
          ...prepaidValueHits,
          ...gameTopupHits,
          ...promoClaimHits
        ].slice(0, 12),
        gameCommerce: [
          ...gameMarketplaceHits,
          ...gameTransactionHits
        ].slice(0, 12)
      },
      scanDurationMs: Math.round((performance.now() - scanStartedAt) * 10) / 10,
      scannedAt: new Date().toISOString()
    };
  }

  function schedulePageScan(delay = 650) {
    clearTimeout(scanTimer);
    if (idleScanHandle && "cancelIdleCallback" in window) {
      window.cancelIdleCallback(idleScanHandle);
      idleScanHandle = null;
    }

    const runScan = async () => {
      if (document.hidden) {
        schedulePageScan(1800);
        return;
      }
      await brandRulesReady;
      const signals = collectPageSignals();
      const { scannedAt, scanDurationMs, ...signatureSignals } = signals;
      const signature = JSON.stringify(signatureSignals);

      if (signature === lastSignalSignature) return;
      lastSignalSignature = signature;

      try {
        await chrome.runtime.sendMessage({
          type: "PAGE_SIGNALS_UPDATED",
          url: location.href,
          signals
        });
      } catch {
        // Extension may have been reloaded while the page remained open.
      }
    };

    scanTimer = setTimeout(() => {
      if ("requestIdleCallback" in window) {
        idleScanHandle = window.requestIdleCallback(() => {
          idleScanHandle = null;
          runScan();
        }, { timeout: 1200 });
      } else {
        runScan();
      }
    }, delay);
  }

  function releaseSecurityLock() {
    if (!securityLock) return;
    const { body, bodyWasInert, bodyAriaHidden, guardBackgroundEvent, guardBackgroundFocus, shadow, trapTab } = securityLock;
    for (const eventName of LOCKED_BACKGROUND_EVENTS) {
      document.removeEventListener(eventName, guardBackgroundEvent, true);
    }
    document.removeEventListener("focusin", guardBackgroundFocus, true);
    shadow.removeEventListener("keydown", trapTab, true);

    if (body?.isConnected) {
      body.inert = bodyWasInert;
      if (bodyAriaHidden === null) body.removeAttribute("aria-hidden");
      else body.setAttribute("aria-hidden", bodyAriaHidden);
    }
    securityLock = null;
  }

  function activateSecurityLock(shadow, initialFocusId) {
    releaseSecurityLock();
    const host = shadow?.host;
    const body = document.body;
    if (!host || !body) return;

    const focusableSelector = [
      "button:not([disabled])", "input:not([disabled])", "select:not([disabled])",
      "textarea:not([disabled])", "a[href]", "[tabindex]:not([tabindex='-1'])"
    ].join(",");
    const focusInitial = () => {
      const preferred = initialFocusId ? shadow.getElementById(initialFocusId) : null;
      const fallback = [...shadow.querySelectorAll(focusableSelector)]
        .find(element => element.getClientRects().length > 0);
      (preferred || fallback)?.focus({ preventScroll: true });
    };
    const eventIsInsideWarning = event => event.composedPath?.().includes(host);
    const guardBackgroundEvent = event => {
      if (eventIsInsideWarning(event)) return;
      event.preventDefault();
      event.stopImmediatePropagation();
    };
    const guardBackgroundFocus = event => {
      if (eventIsInsideWarning(event)) return;
      event.stopImmediatePropagation();
      queueMicrotask(focusInitial);
    };
    const trapTab = event => {
      if (event.key !== "Tab") return;
      const focusable = [...shadow.querySelectorAll(focusableSelector)]
        .filter(element => element.getClientRects().length > 0);
      if (!focusable.length) {
        event.preventDefault();
        return;
      }
      const active = shadow.activeElement;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (active === first || !focusable.includes(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (active === last || !focusable.includes(active))) {
        event.preventDefault();
        first.focus();
      }
    };

    document.activeElement?.blur?.();
    const bodyWasInert = Boolean(body.inert);
    const bodyAriaHidden = body.getAttribute("aria-hidden");
    document.body.inert = true;
    body.setAttribute("aria-hidden", "true");
    for (const eventName of LOCKED_BACKGROUND_EVENTS) {
      document.addEventListener(eventName, guardBackgroundEvent, true);
    }
    document.addEventListener("focusin", guardBackgroundFocus, true);
    shadow.addEventListener("keydown", trapTab, true);
    securityLock = {
      body,
      bodyWasInert,
      bodyAriaHidden,
      guardBackgroundEvent,
      guardBackgroundFocus,
      shadow,
      trapTab
    };
    queueMicrotask(focusInitial);
  }

  function removeSecurityUI() {
    nonBlockingUiCleanup?.();
    nonBlockingUiCleanup = null;
    releaseSecurityLock();
    document.getElementById(UI_HOST_ID)?.remove();
    window.speechSynthesis?.cancel?.();
  }

  function createHost() {
    removeSecurityUI();
    const host = document.createElement("div");
    host.id = UI_HOST_ID;
    host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;";
    const shadow = host.attachShadow({ mode: "closed" });
    document.documentElement.appendChild(host);
    return shadow;
  }

  function installNonBlockingPanelBehavior(shadow) {
    nonBlockingUiCleanup?.();
    nonBlockingUiCleanup = null;
    const host = shadow?.host;
    const bar = shadow?.querySelector?.(".bar");
    const panel = shadow?.querySelector?.(".panel");
    if (!host || !bar || !panel || securityLock) return;

    let collapsed = false;
    const setCollapsed = value => {
      collapsed = Boolean(value);
      panel.hidden = collapsed;
      bar.classList.toggle("collapsed", collapsed);
      bar.setAttribute("aria-expanded", String(!collapsed));
      bar.title = collapsed ? "Mở lại bảng cảnh báo" : "Thu gọn bảng cảnh báo";
    };
    const eventIsInsideExtension = event => event.composedPath?.().includes(host);
    const collapseFromPageEvent = event => {
      if (!eventIsInsideExtension(event)) setCollapsed(true);
    };
    const collapseForPageSelection = () => {
      const selection = document.getSelection?.();
      if (!selection || selection.isCollapsed) return;
      if (selection.anchorNode?.getRootNode?.() === shadow) return;
      setCollapsed(true);
    };
    const togglePanel = event => {
      event?.preventDefault?.();
      setCollapsed(!collapsed);
    };
    const onBarKeydown = event => {
      if (event.key === "Enter" || event.key === " ") togglePanel(event);
    };

    bar.setAttribute("role", "button");
    bar.setAttribute("tabindex", "0");
    bar.addEventListener("click", togglePanel);
    bar.addEventListener("keydown", onBarKeydown);
    document.addEventListener("pointerdown", collapseFromPageEvent, true);
    document.addEventListener("contextmenu", collapseFromPageEvent, true);
    document.addEventListener("selectionchange", collapseForPageSelection, true);

    nonBlockingUiCleanup = () => {
      bar.removeEventListener("click", togglePanel);
      bar.removeEventListener("keydown", onBarKeydown);
      document.removeEventListener("pointerdown", collapseFromPageEvent, true);
      document.removeEventListener("contextmenu", collapseFromPageEvent, true);
      document.removeEventListener("selectionchange", collapseForPageSelection, true);
    };
  }

  function goBackToSafety() {
    if (history.length > 1) {
      history.back();
    } else {
      location.replace("about:blank");
    }
  }

  function speakVietnamese(text) {
    try {
      window.speechSynthesis.cancel();
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.lang = "vi-VN";
      utterance.rate = 0.88;
      utterance.pitch = 1.04;
      window.speechSynthesis.speak(utterance);
    } catch {
      // Speech synthesis is optional and may be unavailable.
    }
  }

  function getRiskTheme(level) {
    if (level === "HIGH") {
      return { label: "NGUY HIỂM", icon: "🛑", color: "#D92D20", foreground: "#FFFFFF" };
    }
    if (level === "MEDIUM") {
      return { label: "CẢNH BÁO", icon: "⚠️", color: "#F7C948", foreground: "#17202A" };
    }
    if (level === "SUSPICIOUS") {
      return { label: "CẦN KIỂM TRA", icon: "🔎", color: "#F59E0B", foreground: "#17202A" };
    }
    return { label: "KHÔNG PHÁT HIỆN PHISHING", icon: "✅", color: "#20A464", foreground: "#FFFFFF" };
  }

  function hasIncompleteSafeEvidence(result) {
    if (result?.evidenceAssessment?.riskState) {
      return result.evidenceAssessment.riskState === "UNDETERMINED" ||
        result.evidenceAssessment.safeDisplayState === "CAUTION";
    }
    if (result?.risk?.level !== "SAFE") return false;
    const identityCode = result.risk.identityStatus?.code || "UNVERIFIED";
    const recognizedContext = [
      "KNOWN_DOMAIN", "OFFICIAL_SUFFIX", "ESTABLISHED_DOMAIN", "MODERATELY_ESTABLISHED", "USER_TRUSTED",
      "LOCAL_DEVELOPMENT", "PRIVATE_NETWORK"
    ].includes(identityCode);
    const evidenceScore = Number(result.risk.confidenceScore) || 0;
    return result.contentSafety?.available !== true || !recognizedContext || evidenceScore < 45;
  }

  function hasContentSafetyWarning(result) {
    return Boolean(
      result.contentSafety?.detected &&
      result.settings?.showContentSafetyWarnings !== false
    );
  }

  function shouldSuppressSearchEngineUi(result) {
    return Boolean(
      result.isSearchEngineHome &&
      result.risk?.level === "SAFE" &&
      result.settings?.showSearchEnginePageUi !== true &&
      !hasContentSafetyWarning(result)
    );
  }

  function shouldShowSafeStatusBar(result) {
    return Boolean(
      result.settings?.showSafeBanner ||
      (result.isSearchEngineHome && result.settings?.showSearchEnginePageUi)
    );
  }

  function getContentTheme(level, categories = []) {
    const gameCommerceOnly = categories.length > 0 && categories.every(item => item?.id === "GAME_COMMERCE");
    if (gameCommerceOnly) return { label: "GIAO DỊCH GAME CẦN XÁC MINH", icon: "🎮", color: "#F59E0B", foreground: "#17202A" };
    if (level === "HIGH") return { label: "RỦI RO NỘI DUNG CAO", icon: "🛡️", color: "#7C3AED", foreground: "#FFFFFF" };
    if (level === "WARNING") return { label: "CẢNH BÁO NỘI DUNG", icon: "⚑", color: "#A855F7", foreground: "#FFFFFF" };
    return { label: "NỘI DUNG CẦN LƯU Ý", icon: "⚑", color: "#F97316", foreground: "#FFFFFF" };
  }

  function contentCategoryItems(contentSafety) {
    return (contentSafety?.categories || []).slice(0, 6)
      .map(item => `<li><b>${escapeHtml(item.icon || "⚑")} ${escapeHtml(item.label)}</b> — ${escapeHtml(item.score)}/100</li>`)
      .join("");
  }

  function reasonItems(reasons) {
    if (!reasons?.length) return "<li>Không phát hiện dấu hiệu rủi ro rõ ràng.</li>";
    return reasons.slice(0, 8).map(item => `<li>${escapeHtml(item)}</li>`).join("");
  }

  function recommendationItems(recommendations) {
    return (recommendations || []).slice(0, 5)
      .map(item => `<li>${escapeHtml(item)}</li>`)
      .join("");
  }

  function childReasons(result) {
    const items = [];
    const page = result.pageSignals || {};

    if (result.listStatus?.blacklisted) items.push("Trang này đã từng được báo là trang xấu.");
    if (result.homoglyphInfo?.hasHomoglyph || result.homoglyphInfo?.isPunycode || result.typoMatch) {
      items.push("Tên trang nhìn giống một trang nổi tiếng nhưng có chữ khác lạ.");
    }
    if (result.ageInfo && result.ageInfo.ageDays < 30) items.push("Trang này mới được tạo gần đây.");
    if (page.externalPasswordFormCount > 0) items.push("Trang đang hỏi mật khẩu và có thể gửi thông tin sang nơi khác.");
    else if (page.passwordInputCount > 0) items.push("Trang đang yêu cầu nhập mật khẩu.");
    if (page.brandMismatch) items.push(`Trang nói là ${page.brandName || "một thương hiệu nổi tiếng"} nhưng địa chỉ không khớp.`);
    if (page.riskyDownloadLinkCount > 0) items.push("Trang có nút tải tệp có thể làm hại máy tính.");
    if (page.hasUrgencyText) items.push("Trang đang thúc giục con làm ngay, nên cần cẩn thận.");
    if (result.redirectInfo?.crossDomainCount > 0 && !result.redirectInfo?.isFederatedAuthFlow) items.push("Trang đã tự chuyển con sang một địa chỉ khác.");
    if (result.redirectInfo?.httpsDowngrade) items.push("Trang đã chuyển từ kết nối an toàn sang kết nối kém an toàn hơn.");
    const categories = result.contentSafety?.categories || [];
    if (categories.some(item => item.id === "GAMBLING")) items.push("Trang có dấu hiệu cờ bạc hoặc cá cược dùng tiền.");
    if (categories.some(item => item.id === "ADULT")) items.push("Trang có nội dung không phù hợp với trẻ em.");
    if (categories.some(item => item.id === "SEXUAL_SERVICES")) items.push("Trang có dấu hiệu môi giới hoặc đặt lịch dịch vụ nhạy cảm dành cho người lớn.");
    if (categories.some(item => item.id === "PERSONAL_DATA" || item.id === "IDENTITY_ABUSE")) items.push("Trang có thể đang hỏi hoặc trao đổi giấy tờ và thông tin riêng tư.");
    if (categories.some(item => item.id === "SCAM_COMMERCE")) items.push("Trang có dấu hiệu yêu cầu mã thẻ, voucher hoặc giao dịch ngoài kênh chính thức.");
    if (categories.some(item => item.id === "GAME_COMMERCE")) items.push("Trang có ngữ cảnh mua bán tài khoản/dịch vụ game qua kênh bên thứ ba; hãy xác minh chủ thể và thanh toán.");
    if (categories.some(item => item.id === "MALWARE")) items.push("Trang quảng bá tệp hoặc công cụ có thể làm hại máy tính.");
    if (categories.some(item => item.id === "DEEPFAKE")) items.push("Trang có nội dung tạo hình, tiếng nói hoặc video giả bằng AI.");
    if (!items.length) items.push("Trang có vài dấu hiệu lạ mà con không cần tự kiểm tra.");

    return [...new Set(items)].slice(0, 4);
  }

  function childSpeechText(result) {
    if (result.contentSafety?.detected && ["HIGH", "WARNING"].includes(result.contentSafety.level)) {
      const hasSexualServices = (result.contentSafety?.categories || []).some(item => item.id === "SEXUAL_SERVICES");
      return hasSexualServices
        ? "Dừng lại. Trang này có dịch vụ nhạy cảm chỉ dành cho người lớn. Con đừng liên hệ, gửi ảnh, chia sẻ vị trí hoặc chuyển tiền. Hãy quay lại và gọi người lớn."
        : "Khoan đã. Trang này có nội dung cần người lớn kiểm tra. Con đừng nạp tiền, gửi giấy tờ, tải tệp hoặc tiếp tục một mình.";
    }
    if (result.risk.level === "HIGH") {
      return "Dừng lại. Trang này có thể không an toàn. Con đừng nhập mật khẩu, mã O T P, số điện thoại và đừng tải tệp. Hãy quay lại và gọi người lớn.";
    }
    if (result.risk.level === "MEDIUM" || result.risk.level === "SUSPICIOUS") {
      return "Khoan đã. Trang này có vài dấu hiệu cần kiểm tra. Con đừng nhập mật khẩu hoặc thông tin của gia đình. Hãy quay lại hoặc gọi người lớn kiểm tra.";
    }
    return "Trang này có vẻ ổn. Nhưng con vẫn không nên đưa mật khẩu hoặc thông tin của gia đình cho người lạ.";
  }

  function openParentPinDialog(shadow, result, onUnlocked) {
    shadow.getElementById("dpg-parent-dialog")?.remove();

    const wrapper = document.createElement("div");
    wrapper.id = "dpg-parent-dialog";
    wrapper.className = "pin-overlay";
    wrapper.innerHTML = `
      <div class="pin-card" role="dialog" aria-modal="true" aria-label="Nhập mã PIN của người lớn">
        <div class="pin-icon">🔒</div>
        <h2>Dành cho người lớn</h2>
        <p>Nhập mã PIN để xem chi tiết kỹ thuật hoặc cho phép tiếp tục.</p>
        <input id="dpg-parent-pin" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="8" autocomplete="off" placeholder="PIN 4–8 số" aria-label="Mã PIN">
        <p class="pin-error" id="dpg-pin-error" aria-live="polite"></p>
        <div class="pin-actions">
          <button id="dpg-pin-cancel">Hủy</button>
          <button class="primary" id="dpg-pin-submit">Mở khóa</button>
        </div>
      </div>
    `;
    shadow.appendChild(wrapper);

    const input = shadow.getElementById("dpg-parent-pin");
    const error = shadow.getElementById("dpg-pin-error");
    input?.focus();

    shadow.getElementById("dpg-pin-cancel")?.addEventListener("click", () => {
      wrapper.remove();
      (shadow.getElementById("dpg-back") || shadow.getElementById("dpg-child-back") || shadow.getElementById("dpg-ignore"))?.focus();
    });
    const submit = async () => {
      const pin = input?.value || "";
      error.textContent = "Đang kiểm tra…";
      const response = await chrome.runtime.sendMessage({
        type: "VERIFY_PARENT_PIN",
        pin,
        minutes: 10
      }).catch(() => null);

      if (!response?.done) {
        error.textContent = response?.error || "PIN không đúng.";
        if (input) {
          input.value = "";
          input.focus();
        }
        return;
      }

      wrapper.remove();
      onUnlocked?.(result);
    };

    shadow.getElementById("dpg-pin-submit")?.addEventListener("click", submit);
    input?.addEventListener("keydown", event => {
      if (event.key === "Enter") submit();
    });
  }

  async function openAdultDetails(shadow, result) {
    const state = await chrome.runtime.sendMessage({ type: "GET_PARENT_STATE" }).catch(() => null);
    if (state?.unlocked) {
      showAdvancedSecurityUI(result, true);
      return;
    }
    openParentPinDialog(shadow, result, () => showAdvancedSecurityUI(result, true));
  }

  function showChildSafeBanner(result) {
    const shadow = createHost();
    const style = document.createElement("style");
    style.textContent = `
      .child-safe{pointer-events:auto;position:fixed;right:14px;bottom:14px;display:flex;width:min(620px,calc(100vw - 28px));align-items:center;justify-content:center;gap:12px;padding:12px 18px;border-radius:16px;background:#EAFBF2;color:#11663C;border:2px solid #20A464;box-shadow:0 7px 24px rgba(0,0,0,.22);font:800 16px/1.35 Arial,sans-serif;text-align:center}
      .child-safe .shield{font-size:28px}.child-safe small{display:block;font-size:12px;font-weight:600;color:#315A47;margin-top:2px}
    `;
    shadow.appendChild(style);
    const banner = document.createElement("div");
    banner.className = "child-safe";
    banner.setAttribute("role", "status");
    banner.innerHTML = `
      <span class="shield">🛡️</span>
      <span>Đã kiểm tra — chưa thấy cảnh báo rõ ràng<small>Đừng đưa mật khẩu, ảnh riêng tư hoặc thông tin gia đình cho người lạ nhé.</small></span>
    `;
    shadow.appendChild(banner);
  }

  function showChildScanningBanner() {
    const shadow = createHost();
    const style = document.createElement("style");
    style.textContent = `.scan{pointer-events:auto;position:fixed;right:14px;bottom:14px;display:flex;width:min(620px,calc(100vw - 28px));align-items:center;justify-content:center;gap:12px;padding:12px 18px;border-radius:16px;background:#EEF5FF;color:#174A7E;border:2px solid #3B82F6;box-shadow:0 7px 24px rgba(0,0,0,.22);font:800 15px/1.35 Arial,sans-serif;text-align:center}.spin{font-size:25px;animation:r 1.1s linear infinite}@keyframes r{to{transform:rotate(360deg)}}small{display:block;font-size:12px;font-weight:600;margin-top:2px}`;
    shadow.appendChild(style);
    const banner = document.createElement("div");
    banner.className = "scan";
    banner.innerHTML = `<span class="spin">🛡️</span><span>Khiên Nhỏ đang kiểm tra nội dung trang<small>Con hãy chờ trước khi nhập thông tin hoặc bấm tải tệp.</small></span>`;
    shadow.appendChild(banner);
  }

  function showChildUnverifiedBanner() {
    const shadow = createHost();
    const style = document.createElement("style");
    style.textContent = `.check{pointer-events:auto;position:fixed;right:14px;bottom:14px;display:flex;width:min(620px,calc(100vw - 28px));align-items:center;justify-content:center;gap:12px;padding:12px 18px;border-radius:16px;background:#FFF7D6;color:#6A5000;border:2px solid #F59E0B;box-shadow:0 7px 24px rgba(0,0,0,.22);font:800 15px/1.35 Arial,sans-serif;text-align:center}.icon{font-size:26px}small{display:block;font-size:12px;font-weight:650;margin-top:2px}`;
    shadow.appendChild(style);
    const banner = document.createElement("div");
    banner.className = "check";
    banner.setAttribute("role", "status");
    banner.innerHTML = `<span class="icon">🔎</span><span>Chưa đủ dữ liệu để nói trang này an toàn<small>Con đừng nhập thông tin hoặc thanh toán; hãy nhờ người lớn kiểm tra domain.</small></span>`;
    shadow.appendChild(banner);
  }

  function showChildWarningUI(result) {
    if (result.ignoredUntil && result.ignoredUntil > Date.now()) return;

    if (result.settings?.childRequireContentScan !== false && result.contentSafety?.available === false) {
      showChildScanningBanner();
      return;
    }

    const categories = result.contentSafety?.categories || [];
    const hasAlwaysBlockedCategory = categories.some(item => STRICT_CONTENT_CATEGORY_IDS.has(item.id));
    const protectionLevel = result.settings?.childProtectionLevel || "strict";
    const minimumContentLevel = protectionLevel === "strict" ? "NOTICE" : "WARNING";
    const contentRanks = { NONE: 0, NOTICE: 1, WARNING: 2, HIGH: 3 };
    const contentWarning = Boolean(
      result.contentSafety?.detected &&
      (hasAlwaysBlockedCategory || contentRanks[result.contentSafety.level] >= contentRanks[minimumContentLevel])
    );
    const phishingWarning = result.risk.level !== "SAFE" && result.risk.presentation?.shouldWarnOnPage !== false;
    if (!phishingWarning && !contentWarning) {
      if (result.settings?.childSafeBanner && result.contentSafety?.available) {
        if (hasIncompleteSafeEvidence(result)) showChildUnverifiedBanner();
        else showChildSafeBanner(result);
      }
      return;
    }

    const shadow = createHost();
    const contentOnly = !phishingWarning && contentWarning;
    const theme = contentOnly ? getContentTheme(result.contentSafety.level, result.contentSafety.categories || []) : getRiskTheme(result.risk.level);
    const isHigh = (phishingWarning && result.risk.level === "HIGH") || result.contentSafety?.level === "HIGH";
    const simpleReasons = childReasons(result);

    const style = document.createElement("style");
    style.textContent = `
      *{box-sizing:border-box} .screen{pointer-events:auto;position:fixed;inset:0;background:${isHigh ? "rgba(73,10,10,.91)" : "rgba(40,33,5,.76)"};display:flex;align-items:center;justify-content:center;padding:18px;font-family:Arial,sans-serif}.card{width:min(610px,96vw);max-height:94vh;overflow:auto;background:#fff;color:#17202a;border-radius:26px;border:8px solid ${theme.color};box-shadow:0 24px 90px rgba(0,0,0,.55);padding:24px;text-align:center}.mascot{font-size:64px;line-height:1}.eyebrow{font-size:17px;font-weight:900;color:${isHigh ? "#B42318" : "#7A5C00"};letter-spacing:.8px;margin-top:6px}.title{font-size:${isHigh ? "38px" : "34px"};line-height:1.1;margin:5px 0 10px;color:${isHigh ? "#B42318" : "#6A5000"}}.message{font-size:20px;line-height:1.45;font-weight:800;margin:0 auto 14px;max-width:500px}.rule{height:1px;background:#e5e7eb;margin:16px 0}.dont{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;text-align:left;margin:14px 0}.dont div{background:${isHigh ? "#FFF0EF" : "#FFF9D8"};border-radius:13px;padding:12px;font-size:15px;font-weight:800}.why{text-align:left;background:#F6F8FA;border-radius:14px;padding:14px 16px;margin-top:14px}.why h3{margin:0 0 7px;font-size:15px}.why ul{margin:0;padding-left:20px}.why li{margin:6px 0;font-size:14px}.actions{display:grid;gap:10px;margin-top:18px}.big{border:0;border-radius:15px;padding:15px 18px;font-size:18px;font-weight:900;cursor:pointer}.back{background:${theme.color};color:${theme.foreground}}.secondary{background:#17202A;color:#fff}.light{background:#fff;border:2px solid #CBD5E1;color:#17202A}.adult{font-size:14px;padding:11px}.helper{display:none;margin-top:12px;padding:12px;border-radius:12px;background:#EAF3FF;color:#174A7E;font-size:16px;font-weight:800}.pin-overlay{pointer-events:auto;position:fixed;inset:0;background:rgba(8,14,22,.84);display:flex;align-items:center;justify-content:center;padding:18px}.pin-card{width:min(390px,94vw);background:#fff;color:#17202a;border-radius:18px;padding:22px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}.pin-icon{font-size:42px}.pin-card h2{margin:5px 0}.pin-card p{line-height:1.45}.pin-card input{width:100%;padding:13px;border:2px solid #CBD5E1;border-radius:11px;font-size:20px;text-align:center;letter-spacing:6px}.pin-error{min-height:20px;color:#B42318;font-weight:700}.pin-actions{display:flex;gap:9px}.pin-actions button{flex:1;border-radius:10px;padding:11px;border:1px solid #CBD5E1;background:#fff;font-weight:800;cursor:pointer}.pin-actions .primary{background:#2563EB;color:#fff;border-color:#2563EB}@media(max-width:520px){.dont{grid-template-columns:1fr}.card{padding:18px}.title{font-size:31px}.message{font-size:18px}.actions{position:sticky;bottom:-18px;z-index:3;padding:12px 0 3px;background:linear-gradient(transparent,#fff 22%)}}
    `;
    shadow.appendChild(style);

    const screen = document.createElement("div");
    screen.className = "screen";
    screen.setAttribute("role", "alertdialog");
    screen.setAttribute("aria-modal", "true");
    screen.setAttribute("aria-label", isHigh ? "Cảnh báo nguy hiểm" : "Cảnh báo website đáng ngờ");
    screen.innerHTML = `
      <div class="card">
        <div class="mascot">🛡️</div>
        <div class="eyebrow">KHIÊN NHỎ NÓI</div>
        <h1 class="title">${isHigh ? "🛑 DỪNG LẠI!" : "⚠️ KHOAN ĐÃ!"}</h1>
        <p class="message">${contentOnly
          ? ((result.contentSafety?.categories || []).some(item => item.id === "SEXUAL_SERVICES")
            ? "Trang này có dịch vụ nhạy cảm chỉ dành cho người lớn. Con không được liên hệ hoặc tiếp tục một mình."
            : "Trang này có nội dung hoặc yêu cầu thông tin cần người lớn kiểm tra.")
          : isHigh
            ? "Trang này có thể đang cố lấy thông tin hoặc làm hại máy tính."
            : "Trang này hơi lạ. Con không cần tự quyết định một mình."}</p>
        <div class="dont">
          <div>🔑 Đừng nhập mật khẩu hoặc mã OTP</div>
          <div>📥 Đừng tải hay mở tệp lạ</div>
          <div>📞 Đừng đưa số điện thoại của gia đình</div>
          <div>📷 Đừng gửi ảnh riêng tư hoặc vị trí</div>
          <div>💳 Đừng chuyển tiền hoặc đặt lịch</div>
          <div>👨‍👩‍👧 Hãy gọi bố mẹ hoặc thầy cô</div>
        </div>
        <div class="why">
          <h3>Vì sao Khiên Nhỏ thấy trang này lạ?</h3>
          <ul>${simpleReasons.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        </div>
        <div class="actions">
          <button class="big back" id="dpg-child-back">← QUAY LẠI NƠI AN TOÀN</button>
          <button class="big secondary" id="dpg-child-speak">🔊 Nghe Khiên Nhỏ hướng dẫn</button>
          <button class="big light" id="dpg-child-adult">👨‍👩‍👧 Gọi người lớn</button>
          <button class="big light adult" id="dpg-child-unlock">Dành cho người lớn 🔒</button>
        </div>
        <div class="helper" id="dpg-child-helper">Hãy đưa máy tính cho bố mẹ, người chăm sóc hoặc thầy cô. Con không cần bấm tiếp.</div>
      </div>
    `;
    shadow.appendChild(screen);
    activateSecurityLock(shadow, "dpg-child-back");

    shadow.getElementById("dpg-child-back")?.addEventListener("click", goBackToSafety);
    shadow.getElementById("dpg-child-speak")?.addEventListener("click", () => speakVietnamese(childSpeechText(result)));
    shadow.getElementById("dpg-child-adult")?.addEventListener("click", () => {
      const helper = shadow.getElementById("dpg-child-helper");
      if (helper) helper.style.display = "block";
      speakVietnamese("Hãy đưa máy tính cho bố mẹ, người chăm sóc hoặc thầy cô để kiểm tra trang này.");
    });
    shadow.getElementById("dpg-child-unlock")?.addEventListener("click", () => openAdultDetails(shadow, result));

    if (result.settings?.childAutoSpeak && !sessionStorage.getItem("dpg-child-spoken")) {
      sessionStorage.setItem("dpg-child-spoken", "1");
      setTimeout(() => speakVietnamese(childSpeechText(result)), 250);
    }
  }

  function bypassNeedsTypedDomain(result) {
    return Boolean(
      result.risk?.level === "HIGH" ||
      result.listStatus?.blacklisted ||
      result.threatInfo?.isUnsafe ||
      result.contentSafety?.level === "HIGH"
    );
  }

  function shouldShowPageWarning(result) {
    if (!result || result.risk?.level === "SAFE") return false;
    if (result.risk?.presentation?.shouldWarnOnPage === false) return false;
    if (
      result.settings?.simpleWarningsOnly &&
      result.settings?.uiProfile === "simple" &&
      result.risk?.level === "SUSPICIOUS" &&
      !result.listStatus?.blacklisted &&
      !result.threatInfo?.isUnsafe
    ) return false;
    return true;
  }

  async function submitTemporaryIgnore(shadow, result, confirmationDomain = "") {
    const response = await chrome.runtime.sendMessage({
      type: "IGNORE_DOMAIN_TEMP",
      domain: result.domain,
      confirmationDomain
    }).catch(() => null);
    if (response?.requiresParent) {
      openParentPinDialog(shadow, result, () => submitTemporaryIgnore(shadow, result, confirmationDomain));
      return false;
    }
    if (response?.done) {
      removeSecurityUI();
      return true;
    }
    return response;
  }

  function openBypassConfirmation(shadow, result) {
    shadow.getElementById("dpg-bypass-confirm")?.remove();
    if (!shadow.getElementById("dpg-bypass-style")) {
      const style = document.createElement("style");
      style.id = "dpg-bypass-style";
      style.textContent = `
        .bypass-overlay{pointer-events:auto;position:fixed;z-index:20;inset:0;display:grid;place-items:center;padding:18px;background:rgba(3,9,13,.91);backdrop-filter:blur(11px)}
        .bypass-card{width:min(450px,94vw);border:1px solid rgba(255,90,95,.5);border-radius:18px;padding:20px;background:linear-gradient(150deg,#251317,#101c23);color:#fff;box-shadow:0 24px 70px rgba(0,0,0,.58);font:13px/1.5 "Aptos","Trebuchet MS",sans-serif}
        .bypass-card .kicker{color:#ff7b80;font-size:9px;font-weight:900;letter-spacing:1.2px}.bypass-card h2{margin:4px 0 8px;font-size:21px}.bypass-card p{margin:0 0 10px;color:#cbb9bc}.bypass-card code{display:block;overflow:hidden;margin:8px 0;border-radius:9px;padding:9px;background:#07141b;color:#fff;text-overflow:ellipsis;white-space:nowrap}
        .bypass-card input{width:100%;border:1px solid rgba(255,123,128,.4);border-radius:10px;padding:11px;background:#07141b;color:#fff;font:750 13px/1.3 "Aptos","Trebuchet MS",sans-serif}.bypass-actions{display:grid;grid-template-columns:.7fr 1.3fr;gap:8px;margin-top:10px}.bypass-actions button{border-radius:10px;padding:11px;border:1px solid rgba(180,203,211,.24);background:#17303c;color:#fff;font-weight:800;cursor:pointer}.bypass-actions .confirm:not(:disabled){border-color:#ff5a5f;background:#bd3038}.bypass-actions button:disabled{cursor:not-allowed;opacity:.42}.bypass-status{min-height:20px;margin:9px 0 0!important;color:#ff9da1!important;font-weight:750}
      `;
      shadow.appendChild(style);
    }

    const hadSecurityLock = Boolean(securityLock);
    const wrapper = document.createElement("div");
    wrapper.id = "dpg-bypass-confirm";
    wrapper.className = "bypass-overlay";
    wrapper.setAttribute("role", "dialog");
    wrapper.setAttribute("aria-modal", "true");
    wrapper.innerHTML = `
      <div class="bypass-card">
        <div class="kicker">XÁC NHẬN VƯỢT CẢNH BÁO</div>
        <h2>Gõ đúng domain để tiếp tục</h2>
        <p>Chỉ cho phép khi bạn đã xác minh địa chỉ bằng nguồn chính thức. Extension sẽ tự thu hồi quyền này sau 10 phút.</p>
        <code>${escapeHtml(result.domain)}</code>
        <input id="dpg-bypass-domain" type="text" inputmode="url" autocomplete="off" spellcheck="false" placeholder="Nhập domain ở trên" aria-label="Nhập lại domain cần cho phép">
        <div class="bypass-actions">
          <button id="dpg-bypass-cancel">Hủy</button>
          <button class="confirm" id="dpg-bypass-submit" disabled>Cho phép 10 phút</button>
        </div>
        <p class="bypass-status" id="dpg-bypass-status" aria-live="polite"></p>
      </div>
    `;
    shadow.appendChild(wrapper);

    const input = shadow.getElementById("dpg-bypass-domain");
    const submit = shadow.getElementById("dpg-bypass-submit");
    const status = shadow.getElementById("dpg-bypass-status");
    const matches = () => String(input?.value || "").trim().toLowerCase().replace(/^www\./, "") === result.domain;
    input?.addEventListener("input", () => { submit.disabled = !matches(); });
    input?.addEventListener("keydown", event => {
      if (event.key === "Enter" && !submit.disabled) submit.click();
    });
    shadow.getElementById("dpg-bypass-cancel")?.addEventListener("click", () => {
      wrapper.remove();
      if (!hadSecurityLock) releaseSecurityLock();
      shadow.getElementById("dpg-ignore")?.focus();
    });
    submit?.addEventListener("click", async () => {
      if (!matches()) return;
      submit.disabled = true;
      status.textContent = "Đang xác nhận…";
      const response = await submitTemporaryIgnore(shadow, result, input.value);
      if (response && response !== true) {
        status.textContent = response.error || "Không thể cho phép tạm thời.";
        submit.disabled = false;
      }
    });

    if (!hadSecurityLock) activateSecurityLock(shadow, "dpg-bypass-domain");
    else queueMicrotask(() => input?.focus({ preventScroll: true }));
  }

  function wireAdvancedActions(shadow, result) {
    shadow.getElementById("dpg-close")?.addEventListener("click", removeSecurityUI);
    shadow.getElementById("dpg-back")?.addEventListener("click", goBackToSafety);
    shadow.getElementById("dpg-speak")?.addEventListener("click", () => {
      const contentText = result.contentSafety?.detected
        ? `${result.contentSafety.reasons.join(". ")}. ${result.contentSafety.recommendations.join(". ")}`
        : "";
      const text = `${result.risk.level === "HIGH" ? "Nguy hiểm" : "Cảnh báo"}. ${result.risk.reasons.join(". ")}. ${result.risk.recommendations.join(". ")}. ${contentText}`;
      speakVietnamese(text);
    });

    shadow.getElementById("dpg-ignore")?.addEventListener("click", async () => {
      if (bypassNeedsTypedDomain(result)) {
        openBypassConfirmation(shadow, result);
        return;
      }
      const response = await submitTemporaryIgnore(shadow, result);
      if (response?.requiresConfirmation) openBypassConfirmation(shadow, result);
    });

    shadow.getElementById("dpg-trust")?.addEventListener("click", async () => {
      const response = await chrome.runtime.sendMessage({
        type: "ADD_WHITELIST",
        domain: result.domain
      }).catch(() => null);
      if (response?.done) removeSecurityUI();
    });

    shadow.getElementById("dpg-strict")?.addEventListener("click", async () => {
      const response = await chrome.runtime.sendMessage({
        type: "ENABLE_STRICT_MODE"
      }).catch(() => null);
      if (response?.requiresParent) {
        openParentPinDialog(shadow, result, async () => {
          await chrome.runtime.sendMessage({ type: "ENABLE_STRICT_MODE" }).catch(() => null);
        });
      }
    });

    shadow.getElementById("dpg-normal")?.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "DISABLE_STRICT_MODE" }).catch(() => null);
    });
  }

  function showAdvancedSecurityUI(result, parentView = false) {
    currentResult = result;
    removeSecurityUI();

    if (result.ignoredUntil && result.ignoredUntil > Date.now()) return;
    if (!parentView && shouldSuppressSearchEngineUi(result)) return;
    if (result.risk.level === "SAFE" && !shouldShowSafeStatusBar(result)) return;
    if (result.risk.level !== "SAFE" && !parentView && !shouldShowPageWarning(result)) return;

    const shadow = createHost();
    const incompleteSafeEvidence = hasIncompleteSafeEvidence(result);
    const theme = incompleteSafeEvidence
      ? { label: "CHƯA ĐỦ DỮ LIỆU", icon: "?", color: "#F59E0B", foreground: "#17202A" }
      : getRiskTheme(result.risk.level);
    const isHigh = result.risk.level === "HIGH" || result.contentSafety?.level === "HIGH";
    const isMedium = result.risk.level === "MEDIUM";
    const isSuspicious = result.risk.level === "SUSPICIOUS";
    const canTrust = isMedium || isSuspicious;
    const riskUndetermined = hasIncompleteSafeEvidence(result);
    const score = riskUndetermined ? null : Math.max(0, Math.min(100, Number(result.risk.score) || 0));
    const confidence = Math.max(0, Math.min(100, Number(result.risk.confidenceScore) || 0));
    const redirects = result.redirectInfo;
    const redirectCount = redirects?.hopCount > 1 ? redirects.hopCount - 1 : 0;
    const ageDays = Number(result.ageInfo?.ageDays);
    const ageLabel = Number.isFinite(ageDays)
      ? ageDays < 60
        ? `${Math.round(ageDays)} ngày`
        : ageDays < 730
          ? `${Math.round(ageDays / 30)} tháng`
          : `${(ageDays / 365.25).toFixed(1)} năm`
      : "Không xác định";
    const ml = result.mlInfo || result.risk.model?.urlModel;
    const mlProbability = Number(ml?.probability);
    const mlRawLabel = ml?.skipped
      ? "Không áp dụng"
      : Number.isFinite(mlProbability)
      ? `${Math.round(mlProbability * 1000) / 10}%`
      : "—";
    const mlAnomalyBand = ml?.skipped
      ? "Mạng cục bộ / riêng"
      : !Number.isFinite(mlProbability)
        ? "Chưa có dữ liệu"
        : mlProbability >= 0.90
          ? "Rất cao"
          : mlProbability >= 0.75
            ? "Cao"
            : mlProbability >= 0.55
              ? "Cần theo dõi"
              : "Thấp";
    const mlApplied = Number(result.risk?.breakdown?.ml || 0);
    const mlReduction = Number(result.risk?.breakdown?.mlReduction || 0);
    const modelVersion = ml?.modelVersion || ml?.version || result.risk.model?.version || "Mặc định";
    const hybridLabel = result.risk.binaryPrediction === "PHISHING"
      ? "Có bằng chứng nguy hiểm"
      : "Chưa đủ bằng chứng kết luận phishing";
    const identityLabel = result.risk.identityStatus?.label || "Chưa xác minh";

    const style = document.createElement("style");
    style.textContent = `
      *{box-sizing:border-box}
      .bar{--tone:${theme.color};pointer-events:auto;position:fixed;right:14px;bottom:14px;display:flex;width:min(560px,calc(100vw - 28px));min-height:48px;gap:12px;align-items:center;border:1px solid color-mix(in srgb,var(--tone) 44%,#263d48);border-radius:15px;padding:8px 12px 8px 30px;background:linear-gradient(135deg,rgba(5,18,26,.97),rgba(10,31,41,.97));color:#eff8fa;box-shadow:0 12px 38px rgba(0,0,0,.4),0 0 22px color-mix(in srgb,var(--tone) 12%,transparent);font:600 12px/1.35 "Aptos","Trebuchet MS",sans-serif;backdrop-filter:blur(16px);animation:bar-in .42s cubic-bezier(.2,.78,.2,1) both}
      .bar::before{position:absolute;top:50%;left:12px;width:8px;height:8px;transform:translateY(-50%);border-radius:50%;background:var(--tone);box-shadow:0 0 10px var(--tone);content:"";animation:pulse 2s ease-in-out infinite}.bar strong{min-width:0;flex:1 1 auto;overflow:hidden;font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif;font-size:13px;letter-spacing:.25px;text-overflow:ellipsis;white-space:nowrap}.bar-domain{min-width:0;flex:1 1 130px;overflow:hidden;color:#9db4bd;text-overflow:ellipsis;white-space:nowrap}.bar-metric{flex:0 0 auto;padding-left:12px;border-left:1px solid rgba(137,177,192,.18);color:#8fa8b2;font-size:10px;white-space:nowrap}.bar-metric b{display:block;color:#f4fafb;font-size:12px}.bar.collapsed{cursor:pointer}
      .panel{pointer-events:auto;position:fixed;right:14px;bottom:76px;width:min(490px,calc(100vw - 28px));max-height:calc(100vh - 104px);overflow:auto;border-radius:22px;scrollbar-color:color-mix(in srgb,${theme.color} 55%,#607783) transparent;scrollbar-width:thin;animation:panel-in .46s cubic-bezier(.2,.8,.2,1) both}
      .overlay{pointer-events:auto;position:fixed;inset:0;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 20%,color-mix(in srgb,${theme.color} 13%,transparent),transparent 37%),rgba(2,9,14,.9);backdrop-filter:blur(10px)}
      .surface{--tone:${theme.color};position:relative;width:100%;max-height:100%;overflow:auto;border:1px solid color-mix(in srgb,var(--tone) 38%,#27404c);border-radius:22px;padding:18px;background:radial-gradient(circle at 100% 0%,color-mix(in srgb,var(--tone) 13%,transparent),transparent 30%),linear-gradient(150deg,#0d2530,#071720 72%);color:#eff7f9;box-shadow:0 26px 80px rgba(0,0,0,.56),inset 0 1px 0 rgba(255,255,255,.035);font:13px/1.48 "Aptos","Trebuchet MS",sans-serif}
      .overlay .surface{width:min(680px,96vw);max-height:92vh;padding:22px}.surface::before{position:absolute;top:0;right:0;left:0;height:2px;background:linear-gradient(90deg,transparent,var(--tone),transparent);box-shadow:0 0 18px var(--tone);content:""}.parent-note{margin-bottom:12px;border:1px solid rgba(79,216,255,.23);border-radius:11px;padding:8px 10px;background:rgba(79,216,255,.07);color:#a8e9fa;font-weight:750}
      .alert-head{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;align-items:start}.icon-orbit{position:relative;display:grid;width:54px;height:54px;place-items:center;border:1px solid color-mix(in srgb,var(--tone) 45%,transparent);border-radius:17px;background:color-mix(in srgb,var(--tone) 10%,transparent);font-size:25px}.icon-orbit::after{position:absolute;inset:6px;border:1px dashed color-mix(in srgb,var(--tone) 30%,transparent);border-radius:12px;content:"";animation:orbit 12s linear infinite}.eyebrow{color:var(--tone);font-size:9px;font-weight:900;letter-spacing:1.45px}.title{margin:2px 0 3px;font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif;font-size:26px;line-height:1.05}.subtitle{margin:0;color:#a9bdc5;font-size:12px;font-weight:600;line-height:1.42}.close{display:grid;width:33px;height:33px;min-width:0;place-items:center;border:1px solid rgba(142,176,188,.22);border-radius:10px;padding:0;background:rgba(6,18,25,.5);color:#a4bac3;font-size:18px;cursor:pointer}.close:hover{border-color:var(--tone);color:#fff}
      .metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-top:15px}.metric{min-width:0;border:1px solid rgba(130,173,188,.15);border-radius:13px;padding:10px;background:rgba(3,15,22,.38)}.metric span{display:block;color:#78939e;font-size:8.5px;font-weight:800;letter-spacing:.6px;text-transform:uppercase}.metric b{display:block;min-height:1.2em;margin-top:4px;color:#f4fafb;font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif;font-size:15px;line-height:1.2;overflow-wrap:anywhere}.metric.risk b{color:var(--tone);font-size:20px;white-space:nowrap}.meter{height:3px;margin-top:7px;overflow:hidden;border-radius:999px;background:rgba(124,160,174,.14)}.meter i{display:block;height:100%;border-radius:inherit;background:var(--tone)}
      .domain-strip{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,.85fr);gap:7px;margin-top:8px}.domain-cell{min-width:0;border:1px solid rgba(129,171,186,.13);border-radius:12px;padding:9px 10px;background:rgba(4,16,23,.3)}.domain-cell span{display:block;color:#78939e;font-size:8.5px;text-transform:uppercase;letter-spacing:.65px}.domain-cell b{display:block;margin-top:3px;overflow:hidden;font-size:11px;text-overflow:ellipsis;word-break:break-word}
      .model-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin-top:8px;padding:9px;border:1px solid rgba(79,216,255,.14);border-radius:13px;background:linear-gradient(90deg,rgba(79,216,255,.055),rgba(55,223,141,.025))}.model-strip div{min-width:0;padding-left:8px;border-left:2px solid rgba(79,216,255,.25)}.model-strip span{display:block;color:#7995a0;font-size:8px;font-weight:800;letter-spacing:.55px;text-transform:uppercase}.model-strip b{display:block;margin-top:3px;overflow:hidden;color:#dcecef;font-size:10px;text-overflow:ellipsis;white-space:nowrap}.model-strip small{display:block;margin-top:2px;color:#6f8993;font-size:8px}
      .section-label{display:flex;align-items:center;gap:7px;margin:15px 0 7px;color:#8ea7b0;font-size:9px;font-weight:900;letter-spacing:1.15px;text-transform:uppercase}.section-label::before{width:16px;height:1px;background:var(--tone);box-shadow:0 0 8px var(--tone);content:""}.insights{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.insight{border:1px solid rgba(130,171,186,.13);border-radius:13px;padding:10px;background:rgba(4,17,24,.34)}.insight h3{margin:0 0 7px;font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif;font-size:13px}.insight ul,.content-panel ul{margin:0;padding-left:17px}.insight li,.content-panel li{margin:5px 0;color:#c4d4da;font-size:10.5px;line-height:1.45}.insight li::marker,.content-panel li::marker{color:var(--tone)}.content-panel{margin-top:9px;border:1px solid rgba(255,139,77,.2);border-radius:13px;padding:10px;background:rgba(255,139,77,.055)}.content-panel h3{margin:0 0 7px;color:#ffb48b;font-size:12px}
      .actions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin-top:14px}button{min-width:0;border:1px solid rgba(137,175,188,.26);border-radius:11px;padding:10px 8px;background:linear-gradient(180deg,rgba(29,59,72,.92),rgba(17,39,50,.92));color:#eff7f9;font:800 10.5px/1.3 "Aptos","Trebuchet MS",sans-serif;cursor:pointer;transition:transform .18s ease,border-color .18s ease}button:hover{transform:translateY(-1px);border-color:var(--tone)}.primary{border-color:var(--tone);background:var(--tone);color:${theme.foreground}}.dark{border-color:#152d39;background:#07141c;color:#fff}.muted{margin:10px 0 0;color:#718b96;font-size:9.5px;line-height:1.45}
      @keyframes panel-in{from{transform:translateX(18px);opacity:0}}@keyframes bar-in{from{transform:translateY(12px);opacity:0}}@keyframes orbit{to{transform:rotate(360deg)}}@keyframes pulse{50%{opacity:.5;box-shadow:0 0 18px var(--tone)}}
      @media(max-width:700px){.bar-metric:last-child{display:none}.overlay{padding:12px}.overlay .surface{padding:18px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.insights{grid-template-columns:1fr}}
      @media(max-width:620px){.bar{width:min(500px,calc(100vw - 20px))}.panel{max-height:calc(100vh - 98px)}}
      @media(max-width:520px){.bar{right:7px;bottom:7px;width:calc(100vw - 14px);gap:8px}.bar-domain{display:none}.bar-metric{margin-left:auto;padding-left:8px}.panel{right:7px;bottom:66px;width:calc(100vw - 14px);max-height:calc(100vh - 76px);border-radius:20px}.surface{padding:15px}.alert-head{grid-template-columns:auto minmax(0,1fr) auto}.icon-orbit{width:46px;height:46px}.title{font-size:22px}.domain-strip,.model-strip{grid-template-columns:1fr}.model-strip div{padding:5px 0 5px 8px}.actions{position:sticky;bottom:-15px;z-index:4;grid-template-columns:repeat(2,minmax(0,1fr));padding:9px 0 3px;background:linear-gradient(transparent,#071720 24%)}}
      @media(max-width:468px){.bar-metric:last-child{display:none}.panel{max-height:calc(100vh - 72px)}}
      @media(max-width:420px){.bar{min-height:44px;padding:7px 9px 7px 27px}.bar strong{font-size:12px}.bar-metric{font-size:9px}.panel{bottom:60px}.metrics{gap:6px}.metric{padding:8px}.title{font-size:20px}}
      @media(max-width:320px){.bar{right:4px;bottom:4px;width:calc(100vw - 8px)}.panel{right:4px;bottom:56px;width:calc(100vw - 8px);max-height:calc(100vh - 62px)}.bar-metric{display:none}.actions{grid-template-columns:1fr}}
      @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
    `;
    shadow.appendChild(style);

    const bar = document.createElement("div");
    bar.className = "bar";
    bar.innerHTML = `
      <strong>${theme.icon} ${theme.label}</strong>
      <span class="bar-domain">${escapeHtml(result.domain)}</span>
      <span class="bar-metric">RỦI RO <b>${score === null ? "—" : `${score}/100`}</b></span>
      <span class="bar-metric">BẰNG CHỨNG <b>${confidence}/100</b></span>
    `;
    shadow.appendChild(bar);

    if (result.risk.level === "SAFE") return;

    const container = document.createElement("div");
    container.className = isHigh ? "overlay" : "panel";
    container.setAttribute("role", "alertdialog");
    container.setAttribute("aria-label", `${theme.label} trên ${result.domain}`);
    if (isHigh) container.setAttribute("aria-modal", "true");
    container.innerHTML = `
      <div class="surface">
        ${parentView ? '<div class="parent-note">🔓 Đang xem chế độ dành cho người lớn trong 10 phút.</div>' : ""}
        <div class="alert-head">
          <div class="icon-orbit">${theme.icon}</div>
          <div>
            <div class="eyebrow">DNS PHISHING GUARD · LIVE ALERT</div>
            <h1 class="title">${theme.label}</h1>
            <p class="subtitle">${isHigh
              ? "Nhiều lớp phân tích cùng ghi nhận dấu hiệu nguy hiểm."
              : isSuspicious
                ? "Có tín hiệu cần kiểm tra thêm; chưa đủ bằng chứng để kết luận phishing."
                : "Hãy xác minh địa chỉ và nội dung trước khi tiếp tục."}</p>
          </div>
          ${isHigh ? "" : '<button class="close" id="dpg-close" aria-label="Đóng cảnh báo">×</button>'}
        </div>

        <div class="metrics">
          <div class="metric risk"><span>Risk score</span><b>${score === null ? "CHƯA XÁC ĐỊNH" : `${score}/100`}</b><div class="meter"><i style="width:${score ?? 0}%"></i></div></div>
          <div class="metric"><span>Chất lượng bằng chứng</span><b>${confidence}/100</b><div class="meter"><i style="width:${confidence}%"></i></div></div>
          <div class="metric"><span>Tuổi domain</span><b>${ageLabel}</b></div>
          <div class="metric"><span>Redirect</span><b>${redirects?.isFederatedAuthFlow ? "OAuth/SSO" : `${redirectCount} lần`}</b></div>
        </div>

        <div class="domain-strip">
          <div class="domain-cell"><span>Hostname</span><b>${escapeHtml(result.domain)}</b></div>
          <div class="domain-cell"><span>Domain đăng ký</span><b>${escapeHtml(result.registrableDomain || result.domain)}</b></div>
          <div class="domain-cell"><span>Chuyển hướng</span><b>${redirects?.isFederatedAuthFlow ? `OAuth/SSO ${escapeHtml(redirects.providerName || "chính thức")}${redirects.relyingPartyDomain ? ` → ${escapeHtml(redirects.relyingPartyDomain)}` : ""}` : (redirectCount > 0 ? `${redirectCount} lần / ${redirects.uniqueDomainCount || 1} domain` : "Không đáng kể")}</b></div>
          <div class="domain-cell"><span>Nhận diện domain</span><b>${escapeHtml(identityLabel)}</b></div>
          <div class="domain-cell"><span>Chế độ hạn chế</span><b>${result.strictMode ? "Đang bật" : "Đang tắt"}</b></div>
        </div>

        <div class="model-strip">
          <div><span>Độ bất thường URL</span><b>${mlRawLabel} · ${escapeHtml(mlAnomalyBand)}</b><small>Chỉ báo cấu trúc, không phải phán quyết</small></div>
          <div><span>ML áp dụng</span><b>${mlApplied}/100${mlReduction > 0 ? ` · giảm ${mlReduction}` : ""}</b><small>Sau hiệu chỉnh hybrid</small></div>
          <div><span>Risk engine</span><b>${escapeHtml(modelVersion)}</b><small>${escapeHtml(hybridLabel)}</small></div>
        </div>

        <div class="section-label">Phân tích &amp; hướng xử lý</div>
        <div class="insights">
          <section class="insight"><h3>Vì sao bị cảnh báo?</h3><ul>${reasonItems(result.risk.reasons)}</ul></section>
          <section class="insight"><h3>Nên làm gì?</h3><ul>${recommendationItems(result.risk.recommendations)}</ul></section>
        </div>
        ${result.contentSafety?.detected ? `
          <section class="content-panel">
            <h3>⚑ An toàn nội dung · ${result.contentSafety.score || 0}/100</h3>
            <ul>${contentCategoryItems(result.contentSafety)}</ul>
            <ul>${reasonItems(result.contentSafety.reasons)}</ul>
            <p class="muted">${escapeHtml(result.contentSafety.disclaimer || "Chỉ báo kỹ thuật, không phải kết luận pháp lý.")}</p>
          </section>
        ` : ""}
        <div class="actions">
          ${isHigh ? '<button class="primary" id="dpg-back">← Quay lại</button>' : ""}
          <button id="dpg-speak">🔊 Đọc hướng dẫn</button>
          <button class="bypass-action" id="dpg-ignore" style="opacity:.68;font-size:9.5px">Tôi hiểu rủi ro · cho phép 10 phút</button>
          ${result.strictMode ? '<button id="dpg-normal">Tắt chế độ hạn chế</button>' : '<button id="dpg-strict">Mở chế độ hạn chế</button>'}
          ${canTrust ? '<button id="dpg-trust">Thêm vào whitelist</button>' : ""}
        </div>
        <p class="muted">Whitelist chỉ giảm điểm uy tín domain; hành vi nguy hiểm trên trang vẫn tiếp tục được kiểm tra.</p>
      </div>
    `;
    shadow.appendChild(container);
    if (isHigh) activateSecurityLock(shadow, "dpg-back");
    wireAdvancedActions(shadow, result);
    if (!isHigh) installNonBlockingPanelBehavior(shadow);
  }

  function showContentSafetyUI(result) {
    currentResult = result;
    removeSecurityUI();
    if (result.ignoredUntil && result.ignoredUntil > Date.now()) return;
    if (!result.contentSafety?.detected || result.settings?.showContentSafetyWarnings === false) return;

    const shadow = createHost();
    const content = result.contentSafety;
    const theme = getContentTheme(content.level, content.categories || []);
    const contentCategories = content.categories || [];
    const gameCommerceOnly = contentCategories.length > 0 && contentCategories.every(item => item?.id === "GAME_COMMERCE");
    const isBlockingContent = content.level === "HIGH" &&
      contentCategories.some(item => STRICT_CONTENT_CATEGORY_IDS.has(item?.id));
    const riskUndetermined = hasIncompleteSafeEvidence(result);
    const style = document.createElement("style");
    style.textContent = `
      *{box-sizing:border-box}
      .bar{--tone:${theme.color};pointer-events:auto;position:fixed;right:14px;bottom:14px;display:flex;width:min(560px,calc(100vw - 28px));min-height:48px;gap:12px;align-items:center;border:1px solid color-mix(in srgb,var(--tone) 42%,#33434c);border-radius:15px;padding:8px 12px 8px 30px;background:linear-gradient(135deg,rgba(5,18,26,.97),rgba(27,24,24,.97));color:#fff6f1;box-shadow:0 12px 38px rgba(0,0,0,.4),0 0 22px color-mix(in srgb,var(--tone) 12%,transparent);font:600 12px/1.35 "Aptos","Trebuchet MS",sans-serif;backdrop-filter:blur(16px);animation:bar-in .42s cubic-bezier(.2,.78,.2,1) both}.bar::before{position:absolute;top:50%;left:12px;width:8px;height:8px;transform:translateY(-50%);border-radius:50%;background:var(--tone);box-shadow:0 0 10px var(--tone);content:"";animation:pulse 2s ease-in-out infinite}.bar strong{min-width:0;flex:1 1 auto;overflow:hidden;font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif;font-size:13px;text-overflow:ellipsis;white-space:nowrap}.bar-domain{min-width:0;flex:1 1 130px;overflow:hidden;color:#b8a69f;text-overflow:ellipsis;white-space:nowrap}.bar-score{flex:0 0 auto;padding-left:12px;border-left:1px solid rgba(190,163,151,.2);color:#ad958b;font-size:9px;text-transform:uppercase;white-space:nowrap}.bar-score b{display:block;color:#fff4ee;font-size:12px;white-space:nowrap}.bar.collapsed{cursor:pointer}
      .panel{--tone:${theme.color};pointer-events:auto;position:fixed;right:14px;bottom:76px;width:min(490px,calc(100vw - 28px));max-height:calc(100vh - 104px);overflow:auto;border:1px solid color-mix(in srgb,var(--tone) 38%,#3c4245);border-radius:22px;padding:18px;background:radial-gradient(circle at 100% 0%,color-mix(in srgb,var(--tone) 14%,transparent),transparent 31%),linear-gradient(150deg,#221d1d,#0b181f 73%);color:#fff5ef;box-shadow:0 26px 80px rgba(0,0,0,.56),inset 0 1px 0 rgba(255,255,255,.035);font:13px/1.48 "Aptos","Trebuchet MS",sans-serif;scrollbar-color:color-mix(in srgb,var(--tone) 55%,#786b66) transparent;scrollbar-width:thin;animation:panel-in .46s cubic-bezier(.2,.8,.2,1) both}.panel::before{position:absolute;top:0;right:0;left:0;height:2px;background:linear-gradient(90deg,transparent,var(--tone),transparent);box-shadow:0 0 18px var(--tone);content:""}
      .content-overlay{pointer-events:auto;position:fixed;inset:0;display:grid;place-items:center;padding:18px;background:rgba(24,5,18,.91);backdrop-filter:blur(13px)}.content-overlay .panel{position:relative;top:auto;right:auto;bottom:auto;width:min(680px,96vw);max-height:94vh;border-color:color-mix(in srgb,var(--tone) 68%,#ff7278);box-shadow:0 30px 100px rgba(0,0,0,.7),0 0 36px color-mix(in srgb,var(--tone) 22%,transparent)}
      .head{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;align-items:start}.icon{position:relative;display:grid;width:54px;height:54px;place-items:center;border:1px solid color-mix(in srgb,var(--tone) 45%,transparent);border-radius:17px;background:color-mix(in srgb,var(--tone) 10%,transparent);font-size:24px}.icon::after{position:absolute;inset:6px;border:1px dashed color-mix(in srgb,var(--tone) 30%,transparent);border-radius:12px;content:"";animation:orbit 12s linear infinite}.eyebrow{color:var(--tone);font-size:9px;font-weight:900;letter-spacing:1.45px}.title{margin:2px 0 3px;font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif;font-size:25px;line-height:1.05}.subtitle{margin:0;color:#c0aaa0;font-size:12px;line-height:1.42}.close{display:grid;width:33px;height:33px;min-width:0;place-items:center;border:1px solid rgba(189,162,150,.22);border-radius:10px;padding:0;background:rgba(15,12,13,.45);color:#c2aba1;font-size:18px;cursor:pointer}
      .phishing-safe{margin-top:13px;border:1px solid rgba(55,223,141,.22);border-radius:11px;padding:9px 10px;background:rgba(55,223,141,.065);color:#a9e9c7;font-size:10.5px;font-weight:700}.phishing-safe.caution{border-color:rgba(245,158,11,.28);background:rgba(245,158,11,.075);color:#ffd398}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-top:8px}.metric{min-width:0;border:1px solid rgba(191,163,151,.14);border-radius:12px;padding:9px;background:rgba(10,13,17,.32)}.metric span{display:block;color:#a28d84;font-size:8px;font-weight:800;letter-spacing:.55px;text-transform:uppercase}.metric b{display:block;min-height:1.2em;margin-top:4px;color:#fff5ef;font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif;font-size:14px;overflow-wrap:anywhere}.metric.primary b{color:var(--tone);font-size:19px;white-space:nowrap}.meter{height:3px;margin-top:7px;overflow:hidden;border-radius:999px;background:rgba(190,160,147,.13)}.meter i{display:block;height:100%;border-radius:inherit;background:var(--tone)}
      .section-label{display:flex;align-items:center;gap:7px;margin:14px 0 7px;color:#ae978d;font-size:9px;font-weight:900;letter-spacing:1.1px;text-transform:uppercase}.section-label::before{width:16px;height:1px;background:var(--tone);box-shadow:0 0 8px var(--tone);content:""}.category-grid{display:flex;flex-wrap:wrap;gap:6px}.category-grid li{list-style:none;margin:0;border:1px solid color-mix(in srgb,var(--tone) 30%,transparent);border-radius:999px;padding:5px 8px;background:color-mix(in srgb,var(--tone) 7%,transparent);color:#ffd7c3;font-size:9.5px}.insights{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.insight{border:1px solid rgba(190,162,150,.13);border-radius:13px;padding:10px;background:rgba(8,13,17,.28)}.insight h3{margin:0 0 7px;font-family:"Bahnschrift SemiCondensed","Aptos Display",sans-serif;font-size:13px}.insight ul{margin:0;padding-left:17px}.insight li{margin:5px 0;color:#dbcac2;font-size:10.5px;line-height:1.45}.insight li::marker{color:var(--tone)}
      .actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:14px}button{min-width:0;border:1px solid rgba(190,162,150,.26);border-radius:11px;padding:10px 8px;background:linear-gradient(180deg,rgba(62,48,43,.92),rgba(37,30,30,.92));color:#fff5ef;font:800 10.5px/1.3 "Aptos","Trebuchet MS",sans-serif;cursor:pointer;transition:transform .18s ease,border-color .18s ease}button:hover{transform:translateY(-1px);border-color:var(--tone)}.primary{border-color:var(--tone);background:var(--tone);color:#fff}.muted{margin:10px 0 0;color:#9f8980;font-size:9.5px;line-height:1.45}
      @keyframes panel-in{from{transform:translateX(18px);opacity:0}}@keyframes bar-in{from{transform:translateY(12px);opacity:0}}@keyframes orbit{to{transform:rotate(360deg)}}@keyframes pulse{50%{opacity:.5;box-shadow:0 0 18px var(--tone)}}
      @media(max-width:700px){.bar{width:min(540px,calc(100vw - 20px))}}
      @media(max-width:620px){.bar{right:7px;bottom:7px;width:calc(100vw - 14px)}.panel{right:7px;bottom:66px;width:calc(100vw - 14px);max-height:calc(100vh - 76px);padding:15px}.bar-domain{display:none}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.insights{grid-template-columns:1fr}.actions{position:sticky;bottom:-15px;z-index:4;padding:9px 0 3px;background:linear-gradient(transparent,#0b181f 24%)}}
      @media(max-width:520px){.bar{gap:8px}.bar strong{font-size:12px}.panel{border-radius:20px}.title{font-size:22px}}
      @media(max-width:468px){.bar-score{padding-left:8px}.panel{max-height:calc(100vh - 72px)}}
      @media(max-width:420px){.bar{min-height:44px;padding:7px 9px 7px 27px}.bar-score{font-size:8px}.panel{bottom:60px}.metrics{gap:6px}.metric{padding:8px}.title{font-size:20px}}
      @media(max-width:320px){.bar{right:4px;bottom:4px;width:calc(100vw - 8px)}.panel{right:4px;bottom:56px;width:calc(100vw - 8px);max-height:calc(100vh - 62px)}.bar strong{max-width:135px}.actions{grid-template-columns:1fr}}
      @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
    `;
    shadow.appendChild(style);

    const bar = document.createElement("div");
    bar.className = "bar";
    bar.innerHTML = `
      <strong>${theme.icon} ${theme.label}</strong>
      <span class="bar-domain">${escapeHtml(result.domain)}</span>
      <span class="bar-score">CONTENT SCORE <b>${content.score}/100</b></span>
    `;
    if (!isBlockingContent) shadow.appendChild(bar);

    const panel = document.createElement("div");
    panel.className = "panel";
    panel.setAttribute("role", "alertdialog");
    panel.setAttribute("aria-label", `${theme.label} trên ${result.domain}`);
    if (isBlockingContent) panel.setAttribute("aria-modal", "true");
    panel.innerHTML = `
      <div class="head">
        <div class="icon">${theme.icon}</div>
        <div><div class="eyebrow">DNS PHISHING GUARD · CONTENT LAYER</div><h1 class="title">${theme.label}</h1><p class="subtitle">Trang có tín hiệu thuộc danh mục nội dung hoặc hành vi cần lưu ý.</p></div>
        ${isBlockingContent ? "" : '<button class="close" id="dpg-close" aria-label="Đóng cảnh báo">×</button>'}
      </div>
      <div class="phishing-safe${riskUndetermined ? " caution" : ""}">${riskUndetermined
        ? "Lớp phishing chưa có đủ bằng chứng để xác nhận an toàn. Hãy kiểm tra đúng domain trước khi đăng nhập, thanh toán hoặc tải tệp."
        : gameCommerceOnly
        ? "Đây là chỉ báo ngữ cảnh giao dịch bên thứ ba, không phải kết luận website lừa đảo. Hãy xác minh chủ thể, domain chính thức và kênh thanh toán trước khi giao dịch."
        : "Lớp phishing riêng chưa phát hiện bằng chứng rõ ràng. Điều này không xác nhận website uy tín, an toàn hoặc hợp pháp."}</div>
      <div class="metrics">
        <div class="metric primary"><span>Content score</span><b>${content.score}/100</b><div class="meter"><i style="width:${content.score}%"></i></div></div>
        <div class="metric"><span>Phishing risk</span><b>${riskUndetermined ? "CHƯA XÁC ĐỊNH" : `${result.risk.score}/100`}</b></div>
        <div class="metric"><span>Danh mục</span><b>${content.categories.length}</b></div>
        <div class="metric"><span>Trạng thái</span><b>Đã quét</b></div>
      </div>
      <div class="section-label">Danh mục phát hiện</div>
      <ul class="category-grid">${contentCategoryItems(content)}</ul>
      <div class="section-label">Phân tích &amp; hướng xử lý</div>
      <div class="insights">
        <section class="insight"><h3>Tín hiệu quan sát</h3><ul>${reasonItems(content.reasons)}</ul></section>
        <section class="insight"><h3>Nên làm gì?</h3><ul>${recommendationItems(content.recommendations)}</ul></section>
      </div>
      <div class="actions">
        ${isBlockingContent ? '<button class="primary" id="dpg-back">← Quay lại</button>' : ""}
        <button id="dpg-speak">🔊 Đọc hướng dẫn</button>
        <button class="bypass-action" id="dpg-ignore" style="opacity:.68;font-size:9.5px">Tôi hiểu rủi ro · cho phép 10 phút</button>
        ${result.strictMode ? '<button id="dpg-normal">Tắt chế độ hạn chế</button>' : '<button id="dpg-strict">Mở chế độ hạn chế</button>'}
      </div>
      <p class="muted">${escapeHtml(content.disclaimer)}</p>
    `;
    if (isBlockingContent) {
      const overlay = document.createElement("div");
      overlay.className = "content-overlay";
      overlay.appendChild(panel);
      shadow.appendChild(overlay);
      activateSecurityLock(shadow, "dpg-back");
    } else {
      shadow.appendChild(panel);
    }
    wireAdvancedActions(shadow, result);
    if (!isBlockingContent) installNonBlockingPanelBehavior(shadow);
  }

  function showSecurityUI(result) {
    currentResult = result;
    const phishingPageWarning = shouldShowPageWarning(result);
    if (shouldSuppressSearchEngineUi(result)) {
      removeSecurityUI();
      return;
    }
    if (result.settings?.childMode) {
      showChildWarningUI(result);
    } else if (
      !phishingPageWarning &&
      result.contentSafety?.detected &&
      result.settings?.showContentSafetyWarnings !== false
    ) {
      showContentSafetyUI(result);
    } else {
      showAdvancedSecurityUI(result, false);
    }
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "REQUEST_PAGE_SIGNALS") {
      brandRulesReady.then(() => {
        const signals = collectPageSignals();
        sendResponse({ ok: true, url: location.href, signals });
      });
      return true;
    }
    if (message.type === "PHISHING_RESULT") {
      showSecurityUI(message.result);
    } else if (message.type === "PHISHING_DISABLED" || message.type === "PHISHING_IGNORED") {
      removeSecurityUI();
    }
  });

  const observer = new MutationObserver(mutations => {
    const relevant = mutations.some(mutation =>
      mutation.type === "childList" || mutation.type === "attributes" || mutation.type === "characterData"
    );
    if (relevant) schedulePageScan();
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    characterData: true,
    attributeFilter: ["action", "src", "href", "type", "name", "placeholder", "autocomplete", "aria-label"]
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) schedulePageScan(120);
  });

  setInterval(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      lastSignalSignature = "";
      chrome.runtime.sendMessage({ type: "PAGE_URL_CHANGED", url: location.href }).catch(() => {});
      schedulePageScan(800);
    }
  }, 1000);

  schedulePageScan(900);
})();
