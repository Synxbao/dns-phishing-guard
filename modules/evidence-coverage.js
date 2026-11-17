const RECOGNIZED_IDENTITY_CODES = new Set([
  "KNOWN_DOMAIN",
  "OFFICIAL_SUFFIX",
  "ESTABLISHED_DOMAIN",
  "MODERATELY_ESTABLISHED",
  "USER_TRUSTED",
  "LOCAL_DEVELOPMENT",
  "PRIVATE_NETWORK"
]);

const COVERAGE_LABELS = {
  COMPLETE: "ĐỦ PHẠM VI CỐT LÕI",
  PARTIAL: "DỮ LIỆU MỘT PHẦN",
  INSUFFICIENT: "CHƯA ĐỦ DỮ LIỆU"
};

const SAFE_PRESENTATION_EVIDENCE_THRESHOLD = 45;
const PAYMENT_EVIDENCE_MAX_BOOST = 20;
const VERIFIED_BRAND_EVIDENCE_MAX_BOOST = 10;
const POSITIVE_EVIDENCE_COMBINED_MAX_BOOST = 20;

function clamp(value) {
  return Math.max(0, Math.min(100, Number(value) || 0));
}

function addLayer(target, id, label, detail, options = {}) {
  if (target.some(item => item.id === id)) return;
  target.push({
    id,
    label,
    detail,
    required: options.required !== false
  });
}

function categoryLabels(contentSafety) {
  return (contentSafety?.categories || [])
    .map(item => item?.label)
    .filter(Boolean)
    .slice(0, 3);
}

function strongPaymentIntegration(pageSignals) {
  const payment = pageSignals?.paymentIntegration;
  const context = payment?.context || {};
  return Boolean(
    payment?.detected === true &&
    payment?.confidence === "STRONG" &&
    Number(payment?.score) >= 70 &&
    Array.isArray(payment?.providers) && payment.providers.length > 0 &&
    context.paymentContext === true &&
    Number(context.interactiveControlCount) > 0 &&
    context.hasPaymentAction === true &&
    context.hasAmountOrCurrency === true
  );
}

function strongVerifiedGameBrandAlignment(pageSignals) {
  return Boolean(
    pageSignals?.gameCommerceOfficialBrand === true &&
    String(pageSignals?.gameCommerceBrandName || "").trim() &&
    (Number(pageSignals?.gameAccountInputCount || 0) > 0 || Number(pageSignals?.prepaidCodeInputCount || 0) > 0) &&
    (Number(pageSignals?.gameCommerceActionCount || 0) > 0 || Number(pageSignals?.commerceActionCount || 0) > 0)
  );
}

function paymentEvidenceBlockers(input, riskLevel) {
  const pageSignals = input.pageSignals || {};
  const redirectInfo = input.redirectInfo || {};
  const blockers = [];
  if (riskLevel !== "SAFE") blockers.push("risk-not-safe");
  if (input.listStatus?.blacklisted || input.risk?.identityStatus?.code === "BLACKLISTED") blockers.push("blacklist");
  if (input.threatInfo?.isUnsafe) blockers.push("threat-intel");
  if (
    pageSignals.brandMismatch ||
    pageSignals.commerceBrandMismatch ||
    pageSignals.gameCommerceBrandMismatch ||
    pageSignals.officialClaimMismatch ||
    pageSignals.gameCommerceOfficialClaimMismatch
  ) {
    blockers.push("brand-mismatch");
  }
  if (Number(pageSignals.externalPasswordFormCount || 0) > 0) blockers.push("external-password-form");
  if (Number(pageSignals.riskyDownloadLinkCount || 0) > 0) blockers.push("risky-download");
  if (redirectInfo.httpsDowngrade) blockers.push("https-downgrade");
  if (!redirectInfo.isFederatedAuthFlow && Number(redirectInfo.crossDomainCount || 0) >= 2) {
    blockers.push("redirect-anomaly");
  }
  return [...new Set(blockers)];
}

function verifiedBrandEvidenceBlockers(input, riskLevel, identityRecognized) {
  const blockers = paymentEvidenceBlockers(input, riskLevel);
  if (!identityRecognized) blockers.push("identity-unrecognized");
  return [...new Set(blockers)];
}

function buildEvidenceAssessment(input = {}) {
  const risk = input.risk || {};
  const contentSafety = input.contentSafety || null;
  const settings = input.settings || {};
  const mode = input.mode === "preflight" ? "preflight" : "live";
  const checkedLayers = [];
  const missingLayers = [];
  const verifiedFacts = [];
  const identityCode = risk.identityStatus?.code || "UNVERIFIED";
  const identityRecognized = RECOGNIZED_IDENTITY_CODES.has(identityCode);
  const contentAvailable = contentSafety?.available === true;
  const contentDetected = Boolean(contentSafety?.detected);
  const contentLabels = categoryLabels(contentSafety);
  const riskLevel = risk.level || "SAFE";
  const rawEvidenceScore = clamp(risk.confidenceScore);
  const paymentIntegration = input.pageSignals?.paymentIntegration || null;
  const paymentEvidenceObserved = strongPaymentIntegration(input.pageSignals);
  const paymentBlockers = paymentEvidenceBlockers(input, riskLevel);
  const paymentEvidenceEligible = paymentEvidenceObserved && paymentBlockers.length === 0;
  const verifiedBrandEvidenceObserved = strongVerifiedGameBrandAlignment(input.pageSignals);
  const verifiedBrandBlockers = verifiedBrandEvidenceBlockers(input, riskLevel, identityRecognized);
  const verifiedBrandEvidenceEligible = verifiedBrandEvidenceObserved && verifiedBrandBlockers.length === 0;

  addLayer(
    checkedLayers,
    "DOMAIN_LISTS",
    "Tên miền & danh sách cục bộ",
    "Đã phân tích host, public suffix, blacklist, whitelist và domain phổ biến."
  );
  verifiedFacts.push(`Đã phân tích domain ${input.domain || input.registrableDomain || "hiện tại"}.`);

  if (identityRecognized) {
    addLayer(
      checkedLayers,
      "IDENTITY",
      "Ngữ cảnh danh tính",
      risk.identityStatus?.detail || "Domain có ngữ cảnh nhận diện đủ mạnh."
    );
    verifiedFacts.push(`Ngữ cảnh domain: ${risk.identityStatus?.label || identityCode}.`);
  } else {
    addLayer(
      missingLayers,
      "IDENTITY",
      "Danh tính/chủ thể website",
      "Chưa nhận diện được domain chính thức, domain phổ biến, domain đã hoạt động đủ lâu hoặc domain do người dùng tin cậy."
    );
  }

  if (input.rdapMeta?.skipped) {
    addLayer(checkedLayers, "RDAP", "Dữ liệu đăng ký domain", "Không áp dụng cho localhost hoặc mạng riêng.", { required: false });
  } else if (input.rdapMeta?.available) {
    addLayer(checkedLayers, "RDAP", "Dữ liệu đăng ký domain", "Đã nhận được dữ liệu RDAP về tuổi và trạng thái domain.", { required: false });
    if (Number.isFinite(Number(input.ageInfo?.ageDays))) {
      verifiedFacts.push(`Tuổi domain quan sát được: ${Number(input.ageInfo.ageDays)} ngày.`);
    }
  } else {
    addLayer(missingLayers, "RDAP", "Dữ liệu đăng ký domain", "RDAP không trả dữ liệu trong lần quét này.", { required: false });
  }

  if (input.mlInfo?.available) {
    addLayer(checkedLayers, "URL_ML", "Cấu trúc địa chỉ website", "Đã kiểm tra đặc trưng URL; kết quả ML chỉ là tín hiệu tham khảo.");
  } else if (input.mlInfo?.skipped) {
    addLayer(checkedLayers, "URL_ML", "Cấu trúc địa chỉ website", "Không áp dụng cho ngữ cảnh mạng cục bộ.", { required: false });
  } else {
    addLayer(
      missingLayers,
      "URL_ML",
      "Cấu trúc địa chỉ website",
      input.mlInfo?.disabled || settings.urlModelEnabled === false ? "URL ML đang tắt." : "URL ML chưa trả kết quả.",
      { required: false }
    );
  }

  if (contentAvailable) {
    addLayer(
      checkedLayers,
      mode === "preflight" ? "STATIC_CONTENT" : "PAGE_CONTENT",
      mode === "preflight" ? "Nội dung xem trước giới hạn" : "Nội dung trang",
      mode === "preflight"
        ? "Đã đọc phần HTML giới hạn mà không chạy JavaScript, form hoặc download."
        : "Đã thu thập tín hiệu nội dung và hành vi DOM trên trang."
    );
    verifiedFacts.push(contentDetected
      ? `Phát hiện ngữ cảnh cần lưu ý: ${contentLabels.join(", ") || "nội dung nhạy cảm"}.`
      : "Lớp nội dung chưa phát hiện danh mục cảnh báo theo các luật hiện có.");
  } else {
    addLayer(
      missingLayers,
      mode === "preflight" ? "STATIC_CONTENT" : "PAGE_CONTENT",
      mode === "preflight" ? "Nội dung thực tế của trang" : "Nội dung trang",
      mode === "preflight"
        ? "Link Lab chưa đọc được phản hồi HTML thành công."
        : settings.analyzePage === false || contentSafety?.disabled
          ? "Phân tích nội dung đang tắt."
          : "Content script chưa trả đủ tín hiệu trang."
    );
  }

  if (input.redirectInfo) {
    addLayer(checkedLayers, "REDIRECTS", "Chuỗi chuyển hướng", "Đã theo dõi chuyển hướng trong phạm vi trình duyệt hoặc Link Lab.", { required: false });
  } else if (settings.redirectAnalysis === false) {
    addLayer(missingLayers, "REDIRECTS", "Chuỗi chuyển hướng", "Phân tích chuyển hướng đang tắt.", { required: false });
  }

  if (input.threatInfo?.checked) {
    addLayer(checkedLayers, "THREAT_INTEL", "Nguồn uy tín bên ngoài", "Đã đối chiếu nguồn Threat Intelligence được cấu hình.", { required: false });
    verifiedFacts.push(input.threatInfo.isUnsafe
      ? "Threat Intelligence có kết quả khớp nguy hiểm."
      : "Threat Intelligence được cấu hình không trả kết quả khớp trong lần quét này.");
  } else if (!input.threatInfo?.skipped) {
    addLayer(
      missingLayers,
      "THREAT_INTEL",
      "Nguồn uy tín bên ngoài",
      "Chưa cấu hình hoặc chưa kiểm tra nguồn uy tín bên ngoài.",
      { required: false }
    );
  }

  if (paymentEvidenceObserved) {
    const providerLabels = paymentIntegration.providers
      .map(item => item?.label)
      .filter(Boolean)
      .slice(0, 4);
    addLayer(
      checkedLayers,
      "PAYMENT_INTEGRATION",
      "Tích hợp thanh toán được quan sát",
      paymentEvidenceEligible
        ? `Phát hiện luồng thanh toán có tương tác với ${providerLabels.join(", ") || "cổng phổ biến"}; đây không phải xác thực đơn vị bán hàng hoặc giao dịch thật.`
        : "Có logo/cấu trúc cổng thanh toán nhưng không dùng làm bằng chứng tích cực vì trang vẫn có tín hiệu rủi ro độc lập.",
      { required: false }
    );
    verifiedFacts.push(
      `Quan sát tích hợp ${providerLabels.join(", ") || "cổng thanh toán phổ biến"}; tín hiệu này không chứng minh website hay giao dịch là chính hãng.`
    );
  }

  if (verifiedBrandEvidenceObserved) {
    const brandName = String(input.pageSignals?.gameCommerceBrandName || "thương hiệu game").trim();
    addLayer(
      checkedLayers,
      "VERIFIED_BRAND_ALIGNMENT",
      "Khớp thương hiệu và địa chỉ chính thức",
      verifiedBrandEvidenceEligible
        ? `Trang hiển thị ${brandName} trên địa chỉ đã được xác minh trong bộ quy tắc và có luồng nạp game tương tác; đây là bằng chứng hỗ trợ, không bảo đảm giao dịch.`
        : `Đã thấy thương hiệu ${brandName}, nhưng không dùng làm bằng chứng tích cực vì còn tín hiệu rủi ro độc lập hoặc danh tính domain chưa đủ mạnh.`,
      { required: false }
    );
    verifiedFacts.push(
      `Địa chỉ hiện tại khớp hệ thống domain đã xác minh của ${brandName}; tín hiệu này không thay thế kiểm tra giao dịch, tài khoản nhận tiền hoặc hỗ trợ chính thức.`
    );
  }

  const requiredMissing = missingLayers.filter(item => item.required);
  const hasObservedConcern = riskLevel !== "SAFE" || contentDetected;
  const checkedLayerIds = new Set(checkedLayers.map(item => item.id));
  const contentLayerId = mode === "preflight" ? "STATIC_CONTENT" : "PAGE_CONTENT";
  const coreTechnicalLayersComplete = checkedLayerIds.has("DOMAIN_LISTS") &&
    checkedLayerIds.has("URL_ML") && checkedLayerIds.has(contentLayerId);
  const coverageExecutionFloor = coreTechnicalLayersComplete ? 25 : 0;
  const baseEvidenceScore = Math.max(rawEvidenceScore, coverageExecutionFloor);
  const identityOnlyRequiredMissing = requiredMissing.length === 1 && requiredMissing[0].id === "IDENTITY";
  const paymentSupportedIdentityGap = paymentEvidenceEligible && identityOnlyRequiredMissing;
  const paymentEvidenceBoost = paymentEvidenceEligible
    ? Math.min(
        PAYMENT_EVIDENCE_MAX_BOOST,
        POSITIVE_EVIDENCE_COMBINED_MAX_BOOST,
        Math.max(0, 100 - baseEvidenceScore)
      )
    : 0;
  const remainingPositiveEvidenceCapacity = Math.max(
    0,
    POSITIVE_EVIDENCE_COMBINED_MAX_BOOST - paymentEvidenceBoost
  );
  const verifiedBrandEvidenceBoost = verifiedBrandEvidenceEligible
    ? Math.min(
        VERIFIED_BRAND_EVIDENCE_MAX_BOOST,
        remainingPositiveEvidenceCapacity,
        Math.max(0, 100 - baseEvidenceScore - paymentEvidenceBoost)
      )
    : 0;
  const positiveEvidenceBoost = paymentEvidenceBoost + verifiedBrandEvidenceBoost;
  const evidenceScore = clamp(baseEvidenceScore + positiveEvidenceBoost);
  let status = "COMPLETE";
  if (requiredMissing.length > 0) status = hasObservedConcern ? "PARTIAL" : "INSUFFICIENT";
  if (paymentSupportedIdentityGap) status = "PARTIAL";

  const riskState = riskLevel === "SAFE" && requiredMissing.length > 0
    ? paymentSupportedIdentityGap ? "PROVISIONAL" : "UNDETERMINED"
    : status === "COMPLETE"
      ? "DETERMINED"
      : "PROVISIONAL";
  const safeDisplayState = riskLevel !== "SAFE"
    ? "NOT_APPLICABLE"
    : riskState === "UNDETERMINED" || evidenceScore < SAFE_PRESENTATION_EVIDENCE_THRESHOLD
      ? "CAUTION"
      : "CONFIDENT";

  const gameCommerceCategory = (contentSafety?.categories || []).find(item => item?.id === "GAME_COMMERCE");
  let summary;
  let recommendedAction;
  if (gameCommerceCategory) {
    summary = riskState === "UNDETERMINED"
      ? "Đã thấy giao dịch game bên thứ ba, nhưng uy tín và danh tính website chưa được xác minh đầy đủ."
      : "Đã thấy ngữ cảnh giao dịch game bên thứ ba cần kiểm tra độc lập.";
    recommendedAction = "Kiểm tra domain chính thức của nhà phát hành, danh tính đơn vị vận hành, chính sách hoàn tiền/bảo hành và kênh thanh toán. Không gửi OTP, mã thẻ hoặc chuyển tiền qua tài khoản cá nhân trước khi xác minh.";
  } else if (riskLevel === "HIGH") {
    summary = "Có bằng chứng rủi ro cao dù một số lớp dữ liệu có thể còn thiếu.";
    recommendedAction = "Rời khỏi trang, không nhập dữ liệu, không thanh toán và không tải tệp.";
  } else if (paymentSupportedIdentityGap) {
    summary = "Chưa xác minh được chủ thể website qua tuổi/domain chính thức, nhưng đã quan sát một luồng thanh toán có cấu trúc với cổng phổ biến và không thấy tín hiệu rủi ro độc lập.";
    recommendedAction = "Có thể tiếp tục thận trọng, nhưng vẫn đối chiếu domain với kênh chính thức và không xem logo/cổng thanh toán là bảo đảm giao dịch thật.";
  } else if (verifiedBrandEvidenceEligible) {
    summary = `Địa chỉ hiện tại khớp hệ thống domain đã xác minh của ${input.pageSignals?.gameCommerceBrandName || "thương hiệu game"} và không có tín hiệu rủi ro độc lập trong lần quét này.`;
    recommendedAction = "Có thể tiếp tục thận trọng; vẫn kiểm tra đúng tài khoản nhận tiền, nội dung giao dịch và kênh hỗ trợ trước khi gửi mã thẻ hoặc thanh toán.";
  } else if (requiredMissing.some(item => item.id === "PAGE_CONTENT" || item.id === "STATIC_CONTENT")) {
    summary = "Chưa đọc đủ nội dung thực tế nên chưa thể xác nhận mức rủi ro đầy đủ.";
    recommendedAction = mode === "preflight"
      ? "Không mở trực tiếp nếu link yêu cầu đăng nhập hoặc thanh toán; thử lại Link Lab sau hoặc xác minh domain qua kênh chính thức."
      : "Tải lại rồi quét lại trang; nếu vẫn thiếu dữ liệu, dùng Link Lab và xác minh domain qua nguồn chính thức.";
  } else if (!identityRecognized) {
    summary = "Các lớp kỹ thuật đã chạy một phần nhưng chưa xác minh được chủ thể đứng sau website.";
    recommendedAction = "Kiểm tra tên pháp nhân, thông tin liên hệ, domain chính thức và chính sách giao dịch trước khi nhập dữ liệu hoặc thanh toán.";
  } else if (safeDisplayState === "CAUTION") {
    summary = "Chưa thấy phishing rõ ràng, nhưng chất lượng bằng chứng còn thấp nên không nên hiển thị như một xác nhận an toàn.";
    recommendedAction = "Tiếp tục thận trọng, kiểm tra đúng domain chính thức và quét lại trước khi đăng nhập hoặc thanh toán.";
  } else if (riskLevel !== "SAFE") {
    summary = "Có tín hiệu rủi ro cần xác minh trước khi tiếp tục.";
    recommendedAction = "Không nhập dữ liệu nhạy cảm cho tới khi kiểm tra được domain và lý do cảnh báo.";
  } else {
    summary = "Đã hoàn tất các lớp bằng chứng cốt lõi; chưa thấy bằng chứng phishing rõ ràng trong lần quét này.";
    recommendedAction = "Có thể tiếp tục thận trọng và luôn kiểm tra domain trước khi đăng nhập hoặc thanh toán.";
  }

  return {
    status,
    label: paymentSupportedIdentityGap && safeDisplayState === "CONFIDENT"
      ? "BẰNG CHỨNG HỖ TRỢ TỐT"
      : COVERAGE_LABELS[status],
    riskState,
    safeDisplayState,
    evidenceScore,
    rawEvidenceScore,
    baseEvidenceScore,
    coverageExecutionFloor,
    paymentEvidenceBoost,
    paymentEvidenceEligible,
    paymentEvidenceBlockers: paymentBlockers,
    verifiedBrandEvidenceObserved,
    verifiedBrandEvidenceBoost,
    verifiedBrandEvidenceEligible,
    verifiedBrandEvidenceBlockers: verifiedBrandBlockers,
    positiveEvidenceBoost,
    checkedLayers,
    missingLayers,
    verifiedFacts: [...new Set(verifiedFacts)].slice(0, 6),
    summary,
    recommendedAction,
    contextAdvisory: gameCommerceCategory
      ? {
          id: "GAME_COMMERCE",
          label: gameCommerceCategory.label,
          level: gameCommerceCategory.level,
          score: gameCommerceCategory.score
        }
      : null
  };
}

function getEvidenceAssessment(result) {
  if (result?.evidenceAssessment) return result.evidenceAssessment;
  return buildEvidenceAssessment(result || {});
}

function isRiskUndetermined(result) {
  return getEvidenceAssessment(result).riskState === "UNDETERMINED";
}

export {
  COVERAGE_LABELS,
  RECOGNIZED_IDENTITY_CODES,
  SAFE_PRESENTATION_EVIDENCE_THRESHOLD,
  PAYMENT_EVIDENCE_MAX_BOOST,
  VERIFIED_BRAND_EVIDENCE_MAX_BOOST,
  POSITIVE_EVIDENCE_COMBINED_MAX_BOOST,
  buildEvidenceAssessment,
  getEvidenceAssessment,
  isRiskUndetermined
};
