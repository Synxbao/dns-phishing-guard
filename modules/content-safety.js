// Content-safety classifier. This layer is separate from phishing scoring.
// It surfaces observable indicators and never makes a legal determination.

const CATEGORY_META = {
  GAMBLING: {
    label: "Cờ bạc / cá cược",
    icon: "🎰",
    legalContext: "Nội dung hạn chế và rủi ro tài chính; tính hợp pháp phụ thuộc giấy phép và quy định áp dụng."
  },
  ADULT: {
    label: "Nội dung người lớn",
    icon: "🔞",
    legalContext: "Nội dung có thể không phù hợp với trẻ em hoặc môi trường công cộng."
  },
  SEXUAL_SERVICES: {
    label: "Dịch vụ tình dục / môi giới nhạy cảm",
    icon: "🚫",
    legalContext: "Có dấu hiệu quảng bá, môi giới hoặc giao dịch dịch vụ tình dục; đây chỉ là chỉ báo kỹ thuật, không phải kết luận pháp lý."
  },
  PERSONAL_DATA: {
    label: "Thu thập / mua bán dữ liệu cá nhân",
    icon: "🪪",
    legalContext: "Có thể liên quan Luật An ninh mạng 116/2025/QH15 và Luật Bảo vệ dữ liệu cá nhân 2025."
  },
  IDENTITY_ABUSE: {
    label: "Danh tính giả / tài khoản rác",
    icon: "🎭",
    legalContext: "Có thể liên quan quy định về danh tính giả, giấy tờ giả và tài khoản phục vụ hành vi trái pháp luật."
  },
  MALWARE: {
    label: "Phần mềm độc hại / công cụ bẻ khóa",
    icon: "🦠",
    legalContext: "Có thể liên quan hành vi phát tán phần mềm độc hại hoặc xâm phạm an ninh thông tin."
  },
  DEEPFAKE: {
    label: "Dịch vụ giả mạo bằng AI / deepfake",
    icon: "🧠",
    legalContext: "Có thể liên quan quy định về sử dụng AI để giả mạo hình ảnh, video hoặc giọng nói trái pháp luật."
  },
  FINANCIAL_SCHEME: {
    label: "Quảng bá tài chính rủi ro",
    icon: "📈",
    legalContext: "Có thể liên quan quảng bá tài chính, tài sản số hoặc đa cấp có dấu hiệu cần xác minh."
  },
  SCAM_COMMERCE: {
    label: "Giao dịch hoặc mã trả trước cần xác minh",
    icon: "🎫",
    legalContext: "Có dấu hiệu thu mã thẻ, voucher hoặc giá trị trả trước trong giao dịch ngoài kênh chính thức; cần xác minh độc lập trước khi thanh toán."
  },
  GAME_COMMERCE: {
    label: "Giao dịch game bên thứ ba cần xác minh",
    icon: "🎮",
    legalContext: "Có ngữ cảnh mua bán tài khoản hoặc dịch vụ game qua domain/kênh liên hệ bên thứ ba; đây là cảnh báo xác minh, không phải kết luận lừa đảo hay vi phạm."
  }
};

function clamp(value, min = 0, max = 100) {
  return Math.min(max, Math.max(min, Number(value) || 0));
}

function pushCategory(categories, id, score, reasons, evidence = []) {
  const normalized = clamp(score);
  if (normalized < 25) return;

  let level = "NOTICE";
  if (normalized >= 75) level = "HIGH";
  else if (normalized >= 45) level = "WARNING";

  categories.push({
    id,
    ...CATEGORY_META[id],
    score: normalized,
    level,
    reasons: [...new Set(reasons)].slice(0, 6),
    evidence: [...new Set(evidence)].slice(0, 12)
  });
}

function analyzeContentSafety(pageSignals, options = {}) {
  if (options.enabled === false) {
    return {
      available: false,
      disabled: true,
      detected: false,
      score: 0,
      level: "NONE",
      categories: [],
      reasons: [],
      recommendations: [],
      legalIndicators: [],
      disclaimer: "Tính năng phân tích nội dung đang tắt."
    };
  }

  if (!pageSignals) {
    return {
      available: false,
      disabled: false,
      detected: false,
      score: 0,
      level: "NONE",
      categories: [],
      reasons: [],
      recommendations: [],
      legalIndicators: [],
      disclaimer: "Chưa thu thập được tín hiệu nội dung trang."
    };
  }

  const categories = [];
  const samples = pageSignals.contentSamples || {};

  const gamblingCore = Number(pageSignals.gamblingCoreHitCount) || 0;
  const gamblingActions = Number(pageSignals.gamblingActionHitCount) || 0;
  const gamblingPayments = Number(pageSignals.gamblingPaymentHitCount) || 0;
  const gamblingTitle = Boolean(pageSignals.gamblingTitleHit);
  let gamblingScore = Math.min(42, gamblingCore * 9) +
    Math.min(30, gamblingActions * 12) +
    Math.min(20, gamblingPayments * 10) +
    (gamblingTitle ? 18 : 0);
  if (gamblingCore < 2 && !gamblingTitle) gamblingScore = Math.min(gamblingScore, 20);
  pushCategory(
    categories,
    "GAMBLING",
    gamblingScore,
    [
      gamblingCore >= 2 ? `Trang có ${gamblingCore} nhóm từ khóa cờ bạc/cá cược` : "",
      gamblingActions > 0 ? "Có lời kêu gọi đăng ký, chơi hoặc đặt cược" : "",
      gamblingPayments > 0 ? "Có nội dung nạp tiền, rút tiền, thưởng hoặc khuyến mãi" : "",
      gamblingTitle ? "Tiêu đề hoặc mô tả trang thể hiện nội dung cá cược" : ""
    ].filter(Boolean),
    samples.gambling || []
  );

  const adultHits = Number(pageSignals.adultContentHitCount) || 0;
  const adultTitle = Boolean(pageSignals.adultTitleHit);
  let adultScore = Math.min(75, adultHits * 18) + (adultTitle ? 25 : 0);
  if (adultHits < 2 && !adultTitle) adultScore = Math.min(adultScore, 20);
  pushCategory(
    categories,
    "ADULT",
    adultScore,
    [
      adultHits >= 2 ? `Trang có ${adultHits} nhóm từ khóa nội dung người lớn` : "",
      adultTitle ? "Tiêu đề hoặc mô tả trang có dấu hiệu nội dung 18+" : ""
    ].filter(Boolean),
    samples.adult || []
  );

  const sexualDirect = Number(pageSignals.sexualServiceDirectHitCount) || 0;
  const sexualContext = Number(pageSignals.sexualServiceContextHitCount) || 0;
  const sexualTransactions = Number(pageSignals.sexualServiceTransactionHitCount) || 0;
  const sexualContacts = Number(pageSignals.sexualServiceContactCount) || 0;
  const sexualProfiles = Number(pageSignals.sexualServiceProfileCount) || 0;
  const sexualTitle = Boolean(pageSignals.sexualServiceTitleHit);
  let sexualScore = Math.min(70, sexualDirect * 34) +
    Math.min(30, sexualContext * 9) +
    Math.min(30, sexualTransactions * 12) +
    Math.min(20, sexualContacts * 5) +
    Math.min(18, sexualProfiles >= 4 ? 18 : sexualProfiles * 3) +
    (sexualTitle ? 20 : 0);
  const hasSexualCombination = sexualDirect > 0 ||
    (sexualContext >= 2 && sexualTransactions > 0) ||
    (sexualContext >= 2 && sexualContacts >= 2 && sexualProfiles >= 4) ||
    (sexualTitle && sexualContext >= 1 && (sexualContacts > 0 || sexualProfiles >= 3));
  if (!hasSexualCombination) sexualScore = Math.min(sexualScore, 20);
  pushCategory(
    categories,
    "SEXUAL_SERVICES",
    sexualScore,
    [
      sexualDirect > 0 ? `Có ${sexualDirect} cụm từ trực tiếp liên quan dịch vụ tình dục` : "",
      sexualContext >= 2 ? `Có ${sexualContext} nhóm từ khóa hẹn hò/người lớn mang tính gợi ý` : "",
      sexualTransactions > 0 ? "Có lời mời đặt lịch, trả phí, theo giờ hoặc phục vụ tận nơi" : "",
      sexualContacts > 0 ? `Có ${sexualContacts} liên kết hoặc nút liên hệ trực tiếp` : "",
      sexualProfiles >= 4 ? `Trang hiển thị nhiều hồ sơ/cá nhân để lựa chọn (${sexualProfiles})` : "",
      sexualTitle ? "Tiêu đề hoặc mô tả trang có dấu hiệu dịch vụ nhạy cảm" : ""
    ].filter(Boolean),
    samples.sexualServices || []
  );

  const dataSaleHits = Number(pageSignals.personalDataSaleHitCount) || 0;
  const identityRequests = Number(pageSignals.identityDocumentRequestCount) || 0;
  const sensitiveInputs = Number(pageSignals.sensitiveInputCount) || 0;
  const financialInputs = Number(pageSignals.financialInputCount) || 0;
  const otpInputs = Number(pageSignals.otpInputCount) || 0;
  const hasPrivacyPolicy = Boolean(pageSignals.hasPrivacyPolicyLink);
  let personalDataScore = Math.min(75, dataSaleHits * 32) +
    Math.min(35, identityRequests * 18) +
    Math.min(20, financialInputs * 5) +
    Math.min(15, otpInputs * 8);
  if (!hasPrivacyPolicy && identityRequests > 0) personalDataScore += 20;
  if (!hasPrivacyPolicy && sensitiveInputs >= 4) personalDataScore += 15;
  pushCategory(
    categories,
    "PERSONAL_DATA",
    personalDataScore,
    [
      dataSaleHits > 0 ? "Có nội dung chào mua, bán hoặc trao đổi dữ liệu cá nhân" : "",
      identityRequests > 0 ? `Trang yêu cầu tải lên hoặc cung cấp giấy tờ định danh (${identityRequests} trường)` : "",
      financialInputs > 0 ? `Trang có ${financialInputs} trường thu thập thông tin tài chính` : "",
      otpInputs > 0 ? "Trang yêu cầu OTP hoặc mã xác thực" : "",
      !hasPrivacyPolicy && sensitiveInputs >= 4 ? "Thu thập nhiều dữ liệu nhạy cảm nhưng chưa thấy liên kết chính sách quyền riêng tư" : ""
    ].filter(Boolean),
    samples.personalData || []
  );

  const identityAbuseHits = Number(pageSignals.identityAbuseHitCount) || 0;
  const identityAbuseScore = Math.min(100, identityAbuseHits * 38);
  pushCategory(
    categories,
    "IDENTITY_ABUSE",
    identityAbuseScore,
    [identityAbuseHits > 0 ? "Có nội dung liên quan mua bán/cho thuê tài khoản, SIM, OTP hoặc giấy tờ giả" : ""].filter(Boolean),
    samples.identityAbuse || []
  );

  const malwareHits = Number(pageSignals.malwareKeywordHitCount) || 0;
  const riskyDownloads = Number(pageSignals.riskyDownloadLinkCount) || 0;
  let malwareScore = Math.min(60, malwareHits * 18) + Math.min(40, riskyDownloads * 12);
  if (malwareHits === 0 || riskyDownloads === 0) malwareScore = Math.min(malwareScore, 40);
  pushCategory(
    categories,
    "MALWARE",
    malwareScore,
    [
      malwareHits > 0 ? "Có nội dung quảng bá crack, keygen, cheat, hack tool hoặc phần mềm can thiệp" : "",
      riskyDownloads > 0 ? `Có ${riskyDownloads} liên kết tải loại tệp có khả năng thực thi` : ""
    ].filter(Boolean),
    samples.malware || []
  );

  const deepfakeHits = Number(pageSignals.deepfakeServiceHitCount) || 0;
  const deepfakeScore = Math.min(100, deepfakeHits * 34);
  pushCategory(
    categories,
    "DEEPFAKE",
    deepfakeScore,
    [deepfakeHits > 0 ? "Có nội dung quảng bá tạo hoặc cung cấp dịch vụ giả mặt, giả giọng hay deepfake" : ""].filter(Boolean),
    samples.deepfake || []
  );

  const financialSchemeHits = Number(pageSignals.financialSchemeHitCount) || 0;
  const financialScore = Math.min(100, financialSchemeHits * 22);
  pushCategory(
    categories,
    "FINANCIAL_SCHEME",
    financialScore,
    [financialSchemeHits > 0 ? "Có nội dung cam kết lợi nhuận, đa cấp, tài sản số hoặc đầu tư rủi ro cần xác minh" : ""].filter(Boolean),
    samples.financialScheme || []
  );

  const prepaidHits = Number(pageSignals.prepaidValueHitCount) || 0;
  const gameTopupHits = Number(pageSignals.gameTopupHitCount) || 0;
  const unofficialHits = Number(pageSignals.unofficialCommerceHitCount) || 0;
  const promoHits = Number(pageSignals.promoClaimHitCount) || 0;
  const commerceActions = Number(pageSignals.commerceActionCount) || 0;
  const prepaidInputs = Number(pageSignals.prepaidCodeInputCount) || 0;
  const gameAccountInputs = Number(pageSignals.gameAccountInputCount) || 0;
  const commerceBrandMismatch = Boolean(pageSignals.commerceBrandMismatch);
  const officialClaimMismatch = Boolean(pageSignals.officialClaimMismatch);
  const hasSensitiveTransactionInput = prepaidInputs > 0 || gameAccountInputs > 0;
  const hasStrongOfficialClaimMismatch = officialClaimMismatch && hasSensitiveTransactionInput;
  const hasStrongCommerceCombination = (
    unofficialHits > 0 &&
    (prepaidHits > 0 || gameTopupHits > 0) &&
    (hasSensitiveTransactionInput || (commerceActions >= 2 && promoHits > 0))
  ) || (
    commerceBrandMismatch &&
    hasSensitiveTransactionInput &&
    (prepaidInputs > 0 || prepaidHits >= 2 || gameTopupHits >= 2)
  ) || (
    prepaidInputs >= 2 && promoHits > 0
  ) || hasStrongOfficialClaimMismatch;
  let scamCommerceScore = Math.min(30, unofficialHits * 18) +
    Math.min(24, prepaidHits * 8) +
    Math.min(18, gameTopupHits * 6) +
    Math.min(16, promoHits * 5) +
    Math.min(24, prepaidInputs * 14) +
    Math.min(10, gameAccountInputs * 6) +
    Math.min(12, commerceActions * 4) +
    (commerceBrandMismatch ? 24 : 0) +
    (officialClaimMismatch ? 40 : 0);
  if (hasStrongOfficialClaimMismatch) scamCommerceScore = Math.max(78, scamCommerceScore);
  else if (!hasStrongCommerceCombination) scamCommerceScore = Math.min(scamCommerceScore, 20);
  pushCategory(
    categories,
    "SCAM_COMMERCE",
    scamCommerceScore,
    [
      unofficialHits > 0 ? "Trang tự mô tả giao dịch ngoài kênh chính thức hoặc dùng cam kết khó kiểm chứng" : "",
      prepaidHits > 0 ? `Có ${prepaidHits} nhóm từ khóa liên quan mã thẻ, voucher hoặc giá trị trả trước` : "",
      prepaidInputs > 0 ? `Trang có ${prepaidInputs} trường yêu cầu mã thẻ, số seri, PIN hoặc voucher` : "",
      gameTopupHits > 0 ? "Có nội dung nạp tiền/vật phẩm hoặc tiền tệ trong game" : "",
      gameAccountInputs > 0 ? "Trang yêu cầu ID hoặc tài khoản game để thực hiện giao dịch" : "",
      promoHits > 0 ? "Có khuyến mãi, nhân đôi hoặc cam kết kết quả cần xác minh" : "",
      commerceBrandMismatch ? `Trang dùng thương hiệu ${pageSignals.commerceBrandName || "nổi tiếng"} cho giao dịch trên domain không chính thức` : "",
      officialClaimMismatch ? `Trang tự nhận chính thức/đối tác của ${pageSignals.officialClaimBrandName || "thương hiệu game"} nhưng domain không thuộc hệ thống đã xác minh` : ""
    ].filter(Boolean),
    samples.scamCommerce || []
  );

  const gameMarketplaceHits = Number(pageSignals.gameMarketplaceHitCount) || 0;
  const gameTransactionHits = Number(pageSignals.gameTransactionHitCount) || 0;
  const offPlatformContacts = Number(pageSignals.gameOffPlatformContactCount) || 0;
  const gameCommerceActions = Number(pageSignals.gameCommerceActionCount) || 0;
  const gameCommerceBrandMismatch = Boolean(pageSignals.gameCommerceBrandMismatch);
  const gameCommerceOfficialBrand = Boolean(pageSignals.gameCommerceOfficialBrand);
  const gameCommerceOfficialClaimMismatch = Boolean(pageSignals.gameCommerceOfficialClaimMismatch);
  const hasStrongGameCommerceCombination = (
    gameCommerceOfficialClaimMismatch && hasSensitiveTransactionInput
  ) || (
    !gameCommerceOfficialBrand &&
    gameMarketplaceHits >= 2 &&
    gameTransactionHits >= 1 &&
    gameCommerceActions >= 1 &&
    (offPlatformContacts >= 1 || gameCommerceBrandMismatch) &&
    (gameCommerceBrandMismatch || offPlatformContacts >= 2 || gameMarketplaceHits >= 4)
  );
  let gameCommerceScore = Math.min(30, gameMarketplaceHits * 5) +
    Math.min(18, gameTransactionHits * 6) +
    Math.min(12, offPlatformContacts * 4) +
    Math.min(10, gameCommerceActions * 4) +
    (gameCommerceBrandMismatch ? 12 : 0) +
    (gameCommerceOfficialClaimMismatch ? 36 : 0);
  gameCommerceScore = gameCommerceOfficialClaimMismatch && hasSensitiveTransactionInput
    ? Math.min(78, Math.max(65, gameCommerceScore))
    : hasStrongGameCommerceCombination
      ? Math.min(70, Math.max(45, gameCommerceScore))
      : Math.min(20, gameCommerceScore);
  pushCategory(
    categories,
    "GAME_COMMERCE",
    gameCommerceScore,
    [
      gameMarketplaceHits > 0 ? `Có ${gameMarketplaceHits} nhóm từ khóa mua bán tài khoản hoặc dịch vụ game` : "",
      gameTransactionHits > 0 ? "Có ngữ cảnh nạp tiền, thanh toán, bảo hành hoặc giao dịch" : "",
      gameCommerceActions > 0 ? `Có ${gameCommerceActions} hành động giao dịch/dịch vụ game trên trang` : "",
      offPlatformContacts > 0 ? `Có ${offPlatformContacts} kênh liên hệ bên ngoài như Zalo, Telegram, Discord hoặc mạng xã hội` : "",
      gameCommerceBrandMismatch ? `Trang dùng thương hiệu ${pageSignals.gameCommerceBrandName || "game"} trên domain không thuộc nhà phát hành` : "",
      gameCommerceOfficialClaimMismatch ? "Trang tự nhận là kênh chính thức/đối tác chính thức trong khi domain không khớp nguồn nhà phát hành" : ""
    ].filter(Boolean),
    samples.gameCommerce || []
  );

  categories.sort((a, b) => b.score - a.score);
  const highest = categories[0]?.score || 0;
  const second = categories[1]?.score || 0;
  const score = clamp(Math.round(highest + Math.min(20, second * 0.2)));

  let level = "NONE";
  if (score >= 75) level = "HIGH";
  else if (score >= 45) level = "WARNING";
  else if (score >= 25) level = "NOTICE";

  const reasons = categories.flatMap(category =>
    category.reasons.map(reason => `${category.icon} ${category.label}: ${reason}`)
  ).slice(0, 10);

  const recommendations = [];
  if (categories.some(item => item.id === "GAMBLING")) {
    recommendations.push("Không nạp tiền, vay tiền hoặc cung cấp thông tin ngân hàng cho trang cá cược chưa được xác minh.");
  }
  if (categories.some(item => item.id === "ADULT")) {
    recommendations.push("Không tiếp tục trong Chế độ trẻ em hoặc trên thiết bị dùng chung.");
  }
  if (categories.some(item => item.id === "SEXUAL_SERVICES")) {
    recommendations.push("Không đặt lịch, chuyển tiền, gửi ảnh riêng tư hoặc chia sẻ vị trí cho dịch vụ nhạy cảm chưa được xác minh.");
  }
  if (categories.some(item => item.id === "PERSONAL_DATA" || item.id === "IDENTITY_ABUSE")) {
    recommendations.push("Không gửi CCCD/hộ chiếu, OTP, ảnh khuôn mặt hoặc dữ liệu tài chính khi chưa xác minh đơn vị thu thập và mục đích sử dụng.");
  }
  if (categories.some(item => item.id === "MALWARE")) {
    recommendations.push("Không tải crack, keygen, cheat, APK lạ hoặc tệp thực thi từ trang này.");
  }
  if (categories.some(item => item.id === "DEEPFAKE")) {
    recommendations.push("Không tải ảnh, video hoặc giọng nói của người khác để tạo nội dung giả mạo khi chưa có sự đồng ý hợp pháp.");
  }
  if (categories.some(item => item.id === "FINANCIAL_SCHEME")) {
    recommendations.push("Không chuyển tiền chỉ dựa trên cam kết lợi nhuận; hãy kiểm tra tư cách pháp lý và cảnh báo từ cơ quan có thẩm quyền.");
  }
  if (categories.some(item => item.id === "SCAM_COMMERCE")) {
    recommendations.push("Không gửi mã thẻ, số seri, PIN, voucher hoặc thanh toán cho tới khi xác minh domain và kênh bán chính thức.");
  }
  if (categories.some(item => item.id === "GAME_COMMERCE")) {
    recommendations.push("Kiểm tra domain chính thức của nhà phát hành, danh tính đơn vị vận hành, chính sách hoàn tiền/bảo hành và kênh thanh toán trước khi mua tài khoản hoặc dịch vụ game.");
    recommendations.push("Không gửi OTP, mã thẻ hoặc chuyển tiền qua tài khoản cá nhân chỉ dựa trên Zalo, Telegram, Discord hay tin nhắn mạng xã hội.");
  }
  if (categories.length) {
    recommendations.push("Các tín hiệu chỉ hỗ trợ sàng lọc; hãy kiểm tra nguồn chính thức trước khi kết luận hoặc báo cáo website.");
  }

  const legalIndicators = [];
  if (categories.some(item => item.id === "SEXUAL_SERVICES")) {
    legalIndicators.push("Dấu hiệu quảng bá hoặc môi giới dịch vụ tình dục cần được người dùng trưởng thành và cơ quan có thẩm quyền xác minh");
  }
  if (categories.some(item => item.id === "PERSONAL_DATA")) {
    legalIndicators.push("Bảo vệ dữ liệu cá nhân và minh bạch khi thu thập dữ liệu");
  }
  if (categories.some(item => item.id === "IDENTITY_ABUSE")) {
    legalIndicators.push("Danh tính giả, giấy tờ giả hoặc tài khoản rác");
  }
  if (categories.some(item => item.id === "MALWARE")) {
    legalIndicators.push("Phát tán phần mềm độc hại hoặc công cụ xâm nhập");
  }
  if (categories.some(item => item.id === "DEEPFAKE")) {
    legalIndicators.push("Giả mạo hình ảnh, video hoặc giọng nói bằng AI");
  }
  if (categories.some(item => item.id === "FINANCIAL_SCHEME")) {
    legalIndicators.push("Quảng bá tài chính, tài sản số hoặc đa cấp có dấu hiệu cần xác minh");
  }
  if (categories.some(item => item.id === "SCAM_COMMERCE")) {
    legalIndicators.push("Giao dịch thu mã hoặc giá trị trả trước ngoài kênh chính thức cần được xác minh độc lập");
  }
  if (categories.some(item => item.id === "GAME_COMMERCE")) {
    legalIndicators.push("Giao dịch tài khoản hoặc dịch vụ game bên thứ ba cần xác minh chủ thể, điều khoản và kênh thanh toán");
  }

  return {
    available: true,
    disabled: false,
    detected: categories.length > 0,
    score,
    level,
    categories,
    reasons,
    recommendations: [...new Set(recommendations)].slice(0, 6),
    legalIndicators,
    scannedAt: pageSignals.scannedAt || new Date().toISOString(),
    disclaimer: "Đây là chỉ báo kỹ thuật về nội dung và hành vi quan sát được, không phải kết luận website vi phạm pháp luật."
  };
}

export { analyzeContentSafety, CATEGORY_META };
